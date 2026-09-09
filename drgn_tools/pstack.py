# Copyright (c) 2025, 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Tools for creating stack traces of userspace tasks, from the kernel

This script contains tools that enable creating stack traces for userspace
tasks, when debugging a kernel program. This requires having access to the
userspace pages, which is not common for core dumps, however they are normally
available for /proc/kcore and /proc/vmcore. If you would like to use this script
with a core dump file, you must either ensure that makedumpfile's dump-level
does not exclude userspace pages, or you could make use of the in-development
"userstack" makedumpfile extensions.

It works by creating a second drgn Program to represent a userspace process,
with a memory reader that just uses the underlying kernel Program to read memory
from the process address space in the vmcore. It assumes that the root
filesystem in which it is running is the same one as the vmcore, and so it
consults the binaries on the filesystem for unwind info.

This script is tested on x86_64 and aarch64, and it's especially suited for
Fedora and its derivatives, due to their inclusion of ".eh_frame" on runtime
binaries, as well as ".gnu_debugdata" sections for address to symbol resolution.
"""
import argparse
import ctypes.util
import fnmatch
import logging
import os
import struct
import sys
import warnings
from functools import lru_cache
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from drgn import Architecture
from drgn import Object
from drgn import Program
from drgn import ProgramFlags
from drgn import sizeof
from drgn import StackTrace
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux import access_remote_vm
from drgn.helpers.linux import cpu_curr
from drgn.helpers.linux import d_path
from drgn.helpers.linux import find_task
from drgn.helpers.linux import for_each_online_cpu
from drgn.helpers.linux import for_each_task
from drgn.helpers.linux import for_each_vma
from drgn.helpers.linux import task_state_to_char

from drgn_tools.corelens import CorelensModule
from drgn_tools.task import for_each_task_in_group
from drgn_tools.task import task_cpu
from drgn_tools.util import align
from drgn_tools.util import CommaList


log = logging.getLogger("drgn.pstack")


def build_id_from_first_bytes(data: bytes) -> Optional[bytes]:
    """
    Return the build ID from the first bytes of an ELF file.

    HACK: we only support x86_64 and aarch64, so we're only implementing support
    for ELF64 little-endian.
    """

    # Basic sanity check: enough data for ELF header and have a header.
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None

    # Rather than encode the whole struct, let's just get the fields we care
    # about.
    e_phoff = struct.unpack_from("=Q", data, 32)[0]
    e_phentsize = struct.unpack_from("=H", data, 54)[0]
    e_phnum = struct.unpack_from("=H", data, 56)[0]

    if e_phentsize != 56:
        return None

    PT_NOTE = 0x4
    for phoff in range(e_phoff, e_phoff + e_phentsize * e_phnum, e_phentsize):
        # Hit the end of the data, we couldn't find it.
        if phoff + e_phentsize > len(data):
            break

        # Only process PT_NOTE
        p_type = struct.unpack_from("=I", data, phoff)[0]
        if p_type != PT_NOTE:
            continue

        # Process all notes contained within data
        p_offset = struct.unpack_from("=Q", data, phoff + 8)[0]
        p_filesz = struct.unpack_from("=Q", data, phoff + 32)[0]
        noff = p_offset
        nend = min(len(data), p_offset + p_filesz)
        while noff + 16 < nend:
            namesz, descsz, tp = struct.unpack_from("=3I", data, noff)
            if (
                namesz == 4
                and tp == 3
                and noff + 16 + descsz <= nend
                and data[noff + 12 : noff + 16] == b"GNU\0"
            ):
                # A GNU_BUILD_ID with its full desc present! Return it.
                return data[noff + 16 : noff + 16 + descsz]

            noff += 12 + align(namesz, 4) + align(descsz, 4)
    return None


def task_saved_pt_regs(task: Object) -> Object:
    """
    Return the userspace registers for the given task struct

    This returns the registers which were saved on entry to the kernel. For
    vmcores generated via kexec and /proc/vmcore, all userspace tasks will have
    registers stored on the stack, because every CPU should be interrupted and
    halted. However, for vmcores which were created by a hypervisor, or for
    live systems, userspace tasks may be directly executing, and any data stored
    on the kernel stack is stale. Drgn does not provide an easy API to get this
    info, but you can tell based on whether the stack pointer is a user or
    kernel address.

    :param task: the ``struct task_struct *`` of this task
    :returns: a ``struct pt_regs`` value object
    """
    prog = task.prog_
    # The pt_regs is dumped at the top of the stack. The stack size may vary,
    # but it gets a guard page on top, and there's sometimes padding. See
    # TOP_OF_STACK_PADDING in arch/x86/include/asm/thread_info.h -- for x86_64,
    # if FRED is enabled, then there is 16 bytes of padding, otherwise 0.
    # an offset of 16 bytes for 64-bit.
    try:
        prog.symbol("fred_rsp0")
        padding = 16
    except LookupError:
        padding = 0
    regs_addr = (
        task.stack_vm_area.addr.value_()
        + task.stack_vm_area.size.value_()
        - sizeof(prog.type("struct pt_regs"))
        - prog["PAGE_SIZE"]
        - padding
    )
    return Object(prog, "struct pt_regs", address=regs_addr)


def task_running_pt_regs(kstack: StackTrace) -> Object:
    """
    Create a ``struct pt_regs`` object from the top frame of a stack trace

    This returns the registers for a task that is/was actively running. They
    should be stored in the core dump metadata (e.g. PRSTATUS), and we can get
    at them via drgn's stack trace object. Drgn's kernel Program won't be able
    to unwind it anyway.

    :param kstack: The kernel stack trace.
    :returns: A ``struct pt_regs`` value object containing the user-space registers.
    """
    prog = kstack.prog
    pt_regs = {}
    tp = prog.type("struct pt_regs")
    if prog.platform.arch == Architecture.X86_64:
        rename = {
            "rip": "ip",
            "rbp": "bp",
            "rax": "ax",
            "rbx": "bx",
            "rcx": "cx",
            "rdx": "dx",
            "rdi": "di",
            "rsi": "si",
            "rsp": "sp",
            "rflags": "flags",
        }
        for name, value in kstack[0].registers().items():
            if name in rename:
                name = rename[name]
            try:
                tp.member(name)
            except LookupError:
                continue
            pt_regs[name] = value
    elif prog.platform.arch == Architecture.AARCH64:
        pt_regs["regs"] = [0] * 31
        pt_regs["pc"] = kstack[0].pc
        for name, value in kstack[0].registers().items():
            if name[0] == "x":
                pt_regs["regs"][int(name[1:])] = value
            elif name == "lr":  # an alias for x30
                pt_regs["regs"][30] = value
            else:
                try:
                    tp.member(name)
                    pt_regs[name] = value
                except LookupError:
                    pass
    else:
        raise NotImplementedError(
            f"Support for {prog.platform.arch} is not implemented"
        )

    return Object(prog, "struct pt_regs", value=pt_regs)


def make_fake_pt_regs(up: Program, data: bytes) -> Object:
    """
    Create a fake ``struct pt_regs`` to convince drgn to unwind a thread

    Drgn's unwinder will accept any object that looks like a ``struct pt_regs``
    (a correctly-named struct of the correct size) and use it as the initial
    registers for a stack unwind. This function can take the bytes of a real
    pt_regs object, and a Program, and return an object associated with that
    program which drgn will unwind.

    :param up: a user program, like the one returned by ``get_user_prog()``
    :param data: the bytes of a ``struct pt_regs``, like that returned by
      ``get_pt_regs()``
    """
    # Luckily, all drgn cares about for x86_64 pt_regs is that it is a structure
    # with the right size. Rather than creating a matching struct pt_regs
    # definition, we can just create a dummy one of the correct size:
    #     struct pt_regs {};
    # Drgn will happily use that (not questioning why an empty struct has that
    # size), and we can save ourselves the trouble of creating a convincing
    # replica of the real struct.
    fake_pt_regs_type = up.struct_type(
        tag="pt_regs", size=len(data), members=[]
    )
    return Object.from_bytes_(up, fake_pt_regs_type, data)


def get_tasks(prog: Program, args: argparse.Namespace) -> List[Object]:
    """
    Return the list of tasks according to the dump arguments

    Only task group leaders (i.e. task structs associated with "processes") are
    returned, though this does include kthreads. No task will appear twice in
    the list.
    """
    tasks = []
    task_struct_set = set()

    def add(task: Object) -> None:
        leader = task.group_leader
        if leader.value_() not in task_struct_set:
            task_struct_set.add(leader.value_())
            tasks.append(leader)

    # Only iterate over every task on the system if we have to.
    if args.comm or args.state or args.all:
        comms = [c.encode("utf-8") for c in args.comm]
        for task in for_each_task(prog):
            if task.tgid != task.pid:
                continue  # only handle group leaders

            if args.all:
                add(task)
            elif args.state and task_state_to_char(task) in args.state:
                add(task)
            else:
                comm = task.comm.string_()
                if any(fnmatch.fnmatch(comm, c) for c in comms):
                    add(task)
    # For on-CPU processes, we can efficiently look these up by CPU
    if args.online:
        for cpu in for_each_online_cpu(prog):
            add(cpu_curr(prog, cpu))
    # For PIDs, we can efficiently look these up
    for pid in args.pid:
        add(find_task(prog, pid))
    return tasks


def add_task_args(group: argparse.ArgumentParser) -> None:
    group.add_argument(
        "--online",
        "-o",
        action="store_true",
        help="print stacks for all on-cpu tasks (not supported for live kernels)",
    )
    group.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="print stacks for all PIDs (not recommended)",
    )
    group.add_argument(
        "--state",
        "-s",
        action=CommaList,
        default=[],
        help="print stacks for all tasks in given state (ps(1) 1-letter code)",
    )
    group.add_argument(
        "--comm",
        "-c",
        action=CommaList,
        default=[],
        help="print stacks for all tasks whose command matches this pattern (glob)",
    )
    group.add_argument(
        "--pid",
        "-p",
        action=CommaList,
        default=[],
        element_type=int,
        help="print stack for specific PIDs (may be specified multiple times)",
    )


def task_dsos(mm: Object) -> List[Tuple[str, int, int, int]]:
    """
    Return the mapped DSOs for a task's ``mm_struct``. The return value is a
    tuple: (path, start, end, ino)
    """
    # For the first pass, find any mapping which starts at offset 0 within the
    # file, and record the full range of the file (even if it's not actually
    # mapped for its full size). Also, record which file mappings have an
    # executable VMA, since we'll only care about those.
    file_range: Dict[str, Tuple[int, int, int]] = {}
    file_exec = set()
    VM_EXEC = 0x4
    for vma in for_each_vma(mm):
        if not vma.vm_file:
            continue
        path = os.fsdecode(d_path(vma.vm_file.f_path))
        # We choose the *first* mapping with pgoff == 0.
        if vma.vm_pgoff == 0 and path not in file_range:
            file_range[path] = (
                vma.vm_start.value_(),
                (vma.vm_start + vma.vm_file.f_inode.i_size).value_(),
                vma.vm_file.f_inode.i_ino.value_(),
            )
        if vma.vm_flags & VM_EXEC:
            file_exec.add(path)

    # For the second pass, ensure there is no overlap between the ranges we
    # created previously. Since the whole file is not necessarily mapped, we
    # want to avoid creating overlapping ranges that drgn is not expecting (see
    # https://github.com/osandov/drgn/issues/574). Once we've ensured there are
    # no overlaps, and the file had an executable mapping, we can emit it.
    ranges = sorted(file_range.items(), key=lambda t: t[1][0])
    result = []
    for i, (path, (start, end, ino)) in enumerate(ranges):
        if i + 1 < len(ranges):
            end = min(end, ranges[i + 1][1][0])
        if path in file_exec:
            result.append((path, start, end, ino))
    return result


@lru_cache(maxsize=1)
def _load_demangler() -> Callable[[str], str]:
    # The GNU C++ standard library contains a function called __cxa_demangle
    # which we can use to translate C++ function names.
    #
    # https://gcc.gnu.org/onlinedocs/libstdc++/manual/ext_demangling.html
    # https://gcc.gnu.org/onlinedocs/libstdc++/latest-doxygen/a00026.html#aaf2180d3f67420d4e937e85b281b94a0
    #
    # Signature:
    # char * __cxxabiv1::__cxa_demangle ( const char *__mangled_name,
    #                                     char *__output_buffer,
    #                                     size_t *__length,
    #                                     int *__status
    # )
    # The output buffer, when not provided, is allocated and must be freed via
    # free().
    stdcxx_name = ctypes.util.find_library("stdc++")
    stdc_name = ctypes.util.find_library("c")
    if not stdcxx_name or not stdc_name:
        warnings.warn("Cannot import C++ demangling")
        return lambda s: s
    stdcxx = ctypes.CDLL(stdcxx_name)
    stdc = ctypes.CDLL(stdc_name)
    demangle_func_p = stdcxx.__cxa_demangle
    demangle_func_p.restype = ctypes.POINTER(ctypes.c_char)

    # The status variable has the following return codes:
    status_codes = {
        0: "The demangling operation succeeded.",
        -1: "A memory allocation failure occurred.",
        -2: "mangled_name is not a valid name under the C++ ABI mangling rules.",
        -3: "One of the arguments is invalid.",
    }

    def demanglefn(mangled: str) -> str:
        in_buffer = ctypes.c_char_p(mangled.encode("utf-8"))
        status = ctypes.c_int()
        result = demangle_func_p(in_buffer, None, None, ctypes.pointer(status))
        if status.value != 0:
            msg = status_codes.get(status.value, "unknown error")
            warnings.warn(f"Unable to demangle '{mangled}': {msg}")
            return mangled
        strval = ctypes.cast(result, ctypes.c_char_p).value.decode("utf-8")  # type: ignore
        stdc.free(result)
        return strval

    return demanglefn


def demangle(mangled: str) -> str:
    if mangled.startswith("_Z"):
        return _load_demangler()(mangled)
    else:
        return mangled


def print_user_stack_trace(regs: Object) -> None:
    """
    Prints the userspace stack trace for regs, with the module name included
    for each frame. Including the module name is pretty important for userspace.
    """
    prog = regs.prog_
    trace = prog.stack_trace(regs)
    print("    ------ userspace ---------")
    for i, frame in enumerate(trace):
        name = demangle(frame.name)

        offset = ""
        try:
            sym = frame.symbol()
            offset = f"+0x{frame.pc - sym.address:x}/0x{sym.size:x}"
        except LookupError:
            pass

        mod_text = ""
        try:
            mod = prog.module(frame.pc)
            off = frame.pc - mod.address_range[0]
            mod_text = f" (from {mod.name} +0x{off:x})"
        except LookupError:
            pass

        source_text = ""
        try:
            source_info = ":".join(map(str, frame.source()))
            source_text = f" ({source_info})"
        except LookupError:
            pass

        print(f"    #{i:<2d} {name}{offset}{source_text}{mod_text}")


def build_prog_from_mm(mm: Object) -> Program:
    """
    Create a Program representing a userspace task in the kernel Program

    :param mm: the ``struct mm_struct`` for the process
    :returns: a Program which can be debugged like a userspace process
    """
    prog = mm.prog_
    up = Program(prog.platform)

    def read_fn(_, count, offset, __):
        return access_remote_vm(mm, offset, count)

    up.add_memory_segment(0, 0xFFFFFFFFFFFFFFFF, read_fn, False)

    for path, start, end, ino in task_dsos(mm):
        try:
            statbuf = os.stat(path)
            if statbuf.st_ino != ino:
                log.warning(
                    "file %s doesn't match the inode on-disk, it may"
                    " have been updated",
                    path,
                )
        except OSError:
            pass
        mod = up.extra_module(path, create=True)
        mod.address_range = (start, end)
        mod.try_file(path)

    return up


def pstack_print_process(task: Object) -> None:
    comm = escape_ascii_string(task.comm.string_())
    print(f"[PID: {task.pid.value_()} COMM: {comm}]")
    prog = task.prog_
    if not task.mm:
        print("  " + str(prog.stack_trace(task)).replace("\n", "\n  "))
        return

    user_prog = build_prog_from_mm(task.mm)
    for i, thread in enumerate(
        for_each_task_in_group(task, include_self=True)
    ):
        tid = thread.pid.value_()
        tcomm = escape_ascii_string(thread.comm.string_())
        st = task_state_to_char(thread)
        cpu = task_cpu(thread)
        on_cpu = cpu_curr(prog, cpu) == thread
        cpunote = "RUNNING ON " if on_cpu else ""
        print(f"  Thread {i} TID={tid} [{st}] {cpunote}CPU={cpu} ('{tcomm}')")
        try:
            kstack = prog.stack_trace(thread)
        except ValueError as e:
            if "cannot unwind stack of running task" in str(e):
                print(f"    {str(e)}")
                continue
            else:
                raise
        if len(kstack) > 0 and (kstack[0].pc & (1 << 63)):
            # Kernel stack is indeed a kernel stack, print it
            print(
                "    " + str(prog.stack_trace(thread)).replace("\n", "\n    ")
            )
            regs = task_saved_pt_regs(task)
        else:
            # CPU was in user-mode, print that instead:
            print("    <running in user mode>")
            regs = task_running_pt_regs(kstack)
        fake_regs = make_fake_pt_regs(user_prog, regs.to_bytes_())
        print_user_stack_trace(fake_regs)


def pstack(prog: Program) -> None:
    parser = argparse.ArgumentParser(description="print stack traces")
    add_task_args(parser)
    args = parser.parse_args()
    if args.online and prog.flags & ProgramFlags.IS_LIVE:
        sys.exit("error: --online: cannot unwind running tasks on live system")
    errs = 0
    for task in get_tasks(prog, args):
        try:
            pstack_print_process(task)
        except Exception as e:
            errs += 1
            print(f"error: {str(e)}")
        print()
    if errs > 0:
        print(f"NOTE: encountered {errs} error{'s' if errs > 1 else ''}")


class Pstack(CorelensModule):
    """Select and print user + kernel stacks, if data is available"""

    name = "pstack"
    run_when = "never"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        add_task_args(parser)

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if args.online and prog.flags & ProgramFlags.IS_LIVE:
            print(
                "--online: cannot unwind running tasks on live system, skipping"
            )
            return
        errs = 0
        for task in get_tasks(prog, args):
            try:
                pstack_print_process(task)
            except Exception as e:
                errs += 1
                print(f"error: {str(e)}")
            print()
        if errs > 0:
            print(f"NOTE: encountered {errs} error{'s' if errs > 1 else ''}")


if __name__ == "__main__":
    logging.basicConfig()
    prog: Program
    pstack(prog)  # noqa
