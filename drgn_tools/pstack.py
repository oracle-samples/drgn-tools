# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Tools for creating stack traces of userspace tasks, from the kernel

This script contains tools that enable creating stack traces for userspace
tasks, when debugging a kernel program. This requires having access to the
userspace pages, which is not common for core dumps (see makedumpfile's -d
option), however it is available for /proc/kcore and /proc/vmcore. The script
contains two approaches:

1. By directly creating a Program to represent a process, which reads memory via
   the kernel Program. This allows directly printing stack traces. This approach
   works well with /proc/kcore, but in the kexec/kdump environment it may
   require too much memory, as well as access to the full root filesystem.
2. By dumping userspace stack memory and some metadata. Later, a second call can
   read this information and actually create the stack trace. This approach
   works better in a kexec environment, because the root filesystem is not
   required, and userspace debuginfo is not consulted.

This script is tested on x86_64 and aarch64, and it's especially suited for
Fedora and its derivatives, due to their inclusion of ".eh_frame" on runtime
binaries, as well as ".gnu_debugdata" sections for address to symbol resolution.
"""
import argparse
import base64
import fnmatch
import gzip
import json
import logging
import os
import struct
import sys
from bisect import bisect_left
from pathlib import Path
from typing import Any
from typing import BinaryIO
from typing import Dict
from typing import Iterator
from typing import List
from typing import Tuple

import drgn
from drgn import Architecture
from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn import sizeof
from drgn import StackTrace
from drgn.helpers.linux import access_remote_vm
from drgn.helpers.linux import cpu_curr
from drgn.helpers.linux import d_path
from drgn.helpers.linux import find_task
from drgn.helpers.linux import for_each_online_cpu
from drgn.helpers.linux import for_each_task
from drgn.helpers.linux import for_each_vma
from drgn.helpers.linux import task_state_to_char
from drgn.helpers.linux import vma_find

from drgn_tools.corelens import CorelensModule
from drgn_tools.task import for_each_task_in_group


log = logging.getLogger("drgn.pstack")


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


def get_tasks(prog: Program, args: argparse.Namespace) -> Iterator[Object]:
    """Return an iterable of tasks according to the dump arguments"""
    if args.pid:
        for pid in args.pid:
            yield find_task(prog, pid)
    elif args.online:
        for cpu in for_each_online_cpu(prog):
            yield cpu_curr(prog, cpu)
    else:
        if args.comm:
            args.comm = args.comm.encode("utf-8")
        for task in for_each_task(prog):
            if task.tgid != task.pid:
                continue  # only handle group leaders
            if args.state and task_state_to_char(task) != args.state:
                continue
            if args.comm and not fnmatch.fnmatch(
                task.comm.string_(), args.comm
            ):
                continue
            yield task


def add_task_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--online",
        "-o",
        action="store_true",
        help="dump stacks for all on-cpu tasks (not supported for live kernels)",
    )
    group.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="dump stacks for all PIDs (not recommended)",
    )
    group.add_argument(
        "--state",
        "-s",
        help="dump stacks for all tasks in given state (ps(1) 1-letter code)",
    )
    group.add_argument(
        "--comm",
        "-c",
        help="dump stacks for all tasks whose command matches this pattern (glob)",
    )
    group.add_argument(
        "--pid",
        "-p",
        action="append",
        type=int,
        help="dump stack for specific PIDs (may be specified multiple times)",
    )


def write_pages(outfile: BinaryIO, task: Object, start: int, end: int) -> None:
    """Write pages from start to end, skipping ones which are swapped out."""
    prog = task.prog_
    pgsize = prog["PAGE_SIZE"].value_()
    for pgaddr in range(start, end, pgsize):
        try:
            data = access_remote_vm(task.mm, pgaddr, pgsize)
        except FaultError:
            continue
        outfile.write(struct.pack("=Q", pgaddr))
        outfile.write(data)


def task_metadata(prog: Program, task: Object) -> Dict[str, Any]:
    """Return JSON metadata about a task, for later use."""
    VM_EXEC = 0x4
    load_addrs = {}
    file_vm_end: Dict[str, int] = {}
    for vma in for_each_vma(task.mm):
        if not vma.vm_file:
            continue
        path = os.fsdecode(d_path(vma.vm_file.f_path))
        file_vm_end[path] = max(
            vma.vm_end.value_(),
            file_vm_end.get(path, 0),
        )
        if vma.vm_flags & VM_EXEC and vma.vm_file:
            file_start = (
                vma.vm_start - vma.vm_pgoff * task.mm.prog_["PAGE_SIZE"]
            ).value_()
            inode = vma.vm_file.f_inode.i_ino.value_()
            load_addrs[path] = [file_start, vma.vm_end.value_(), inode]

    # use the largest vm_end we find for the end of the address range
    for path in load_addrs:
        load_addrs[path][1] = file_vm_end[path]
    return {
        "pid": task.pid.value_(),
        "page_size": prog["PAGE_SIZE"].value_(),
        "comm": task.comm.string_().decode("utf-8", errors="replace"),
        "mm": load_addrs,
        "threads": [],
    }


def dump(prog: Program) -> None:
    parser = argparse.ArgumentParser(description="dump stacks")
    parser.add_argument(
        "directory",
        help="store stack dumps in the given directory by PID",
    )
    add_task_args(parser)
    args = parser.parse_args(sys.argv[2:])

    dir_ = Path(args.directory)
    dir_.mkdir(exist_ok=True)
    page_mask = ~(prog["PAGE_SIZE"] - 1)
    for task in get_tasks(prog, args):
        # Skip kthreads and zombies without memory
        if not task.mm:
            continue
        metadata = task_metadata(prog, task)
        with gzip.open(dir_ / f"{task.pid.value_()}.gz", "wb") as f:
            for thread in for_each_task_in_group(task, include_self=True):
                tid = thread.pid.value_()
                tcomm = thread.comm.string_().decode("utf-8", errors="replace")
                try:
                    kstack = prog.stack_trace(thread)
                except ValueError:
                    log.warning("skipped running TID %d ('%s')", tid, tcomm)
                    continue
                if len(kstack) > 0 and (kstack[0].pc & (1 << 63)):
                    # CPU was running in kernel mode, get the saved registers
                    regs = task_saved_pt_regs(thread)
                    kstack_str = str(kstack)
                else:
                    # CPU was in user mode. Drgn won't make be able to unwind
                    # it, but we can take the top frame and get the original
                    # registers for unwinding.
                    regs = task_running_pt_regs(kstack)
                    kstack_str = "<running in user mode>"
                metadata["threads"].append(
                    {
                        "tid": tid,
                        "comm": tcomm,
                        "kstack": kstack_str,
                        "regs": base64.b64encode(regs.to_bytes_()).decode(),
                    },
                )
                # Three big assumptions here: (1) the stack grows down, (2)
                # there is no stack switching going on, and (3) the stack is in
                # its own VMA.  These are usually true, but not always.
                vma = vma_find(task.mm, regs.sp)
                if not vma:
                    log.warning(
                        "could not find VMA for SP (%x) in TID %d ('%s')",
                        regs.sp.value_(),
                        tid,
                        tcomm,
                    )
                    continue
                start = (regs.sp & page_mask).value_()
                end = vma.vm_end.value_()
                # mypy false positive:
                # Argument 1 to "write_pages" has incompatible type "GzipFile"; expected "BinaryIO"  [arg-type]
                write_pages(f, thread, start, end)  # type: ignore
        with gzip.open(dir_ / f"{task.pid.value_()}-meta.json.gz", "wb") as f:
            f.write(json.dumps(metadata).encode("utf-8"))


def build_prog_from_dump(
    data: List[Tuple[int, bytes]], metadata: Dict[str, Any]
) -> Program:
    prog = Program(drgn.host_platform)
    page_size = metadata["page_size"]
    data.sort()

    def read_fn(_, count, offset, __):
        # This may be a bit overkill given that the average single-threaded task
        # only has a few stack pages to speak of. But I can't justify using a
        # linear search when binary search will do better.
        page = offset & ~(page_size - 1)
        # bisect_left gained a "key" kwarg, but in Python 3.10, oh well...
        index = bisect_left(data, (page, b""))
        output = bytearray()
        while len(output) < count:
            if index >= len(data) or data[index][0] != page:
                raise FaultError("memory not present", page)
            pgoff = (offset + len(output)) & (page_size - 1)
            pgend = min(page_size, pgoff + count - len(output))
            output += data[index][1][pgoff:pgend]

            # Move to the next page, which is hopefully present if we have more
            # to read.
            page += page_size
            index += 1
        return output

    prog.add_memory_segment(0, 0xFFFFFFFFFFFFFFFF, read_fn, False)

    pid = metadata["pid"]
    for name, (start, end, ino) in metadata["mm"].items():
        path = Path(name)
        inode = None
        try:
            if path.exists():
                inode = path.stat().st_ino
            else:
                log.warning("For PID %d, could not find file %s", pid, name)
                continue
        except OSError as e:
            log.warning(
                "For PID %d, could not access file %s (%r)", pid, name, e
            )
            continue
        if inode is not None and inode != ino:
            log.warning(
                "For PID %d, file %s inode does not match, file may be updated",
                pid,
                name,
            )
        mod = prog.extra_module(name=name, create=True)
        mod.address_range = (start, end)
        mod.try_file(name, force=True)
    return prog


def print_user_stack_trace(regs: Object) -> None:
    """
    Prints the userspace stack trace for regs, with the module name included
    for each frame. Including the module name is pretty important for userspace.
    """
    prog = regs.prog_
    trace = prog.stack_trace(regs)
    print("    ------ userspace ---------")
    for frame, line in zip(trace, str(trace).split("\n")):
        mod_text = ""
        try:
            mod = prog.module(frame.pc)
            off = frame.pc - mod.address_range[0]
            mod_text = f" (in {mod.name} +0x{off:x})"
        except LookupError:
            pass
        print("    " + line.rstrip() + mod_text)


def dump_print_process(f: Path) -> None:
    """Print traces for a dumped process"""
    PAGE_SIZE = 4096
    with gzip.open(f, "rb") as fp:
        meta = json.loads(fp.read().decode("utf-8"))

    pid = meta["pid"]
    data = []
    with gzip.open(f.parent / f"{pid}.gz", "rb") as fp:
        while True:
            header = fp.read(8)
            if not header:
                break
            addr = struct.unpack("=Q", header)[0]
            data.append((addr, fp.read(PAGE_SIZE)))

    prog = build_prog_from_dump(data, meta)
    comm = meta["comm"]
    print(f"[PID: {pid} COMM: {comm}]")
    for i, t in enumerate(meta["threads"]):
        tid = t["tid"]
        tcomm = t["comm"]
        print(f"  Thread {i} TID={tid} ('{tcomm}')")
        print("    " + t["kstack"].replace("\n", "\n    "))
        regs = make_fake_pt_regs(prog, base64.b64decode(t["regs"]))
        print_user_stack_trace(regs)


def dump_print(d: str):
    parser = argparse.ArgumentParser(
        description="print traces for dumped stacks"
    )
    parser.add_argument("directory", type=Path, help="output directory")
    args = parser.parse_args(sys.argv[2:])
    for f in args.directory.iterdir():
        if not f.name.endswith("-meta.json.gz"):
            continue
        dump_print_process(f)
        print()


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

    # Do one pass where we record the maximum extent of the mapping for each
    # file, and we also detect each executable mapping, for which we prepare
    # modules.
    file_vm_end: Dict[str, int] = {}
    VM_EXEC = 0x4
    for vma in for_each_vma(mm):
        if vma.vm_file:
            path = os.fsdecode(d_path(vma.vm_file.f_path))
            file_vm_end[path] = max(
                vma.vm_end.value_(), file_vm_end.get(path, 0)
            )
        if vma.vm_flags & VM_EXEC and vma.vm_file:
            try:
                statbuf = os.stat(path)
                if statbuf.st_ino != vma.vm_file.f_inode.i_ino.value_():
                    log.warning(
                        "file %s doesn't match the inode on-disk, it may"
                        " have been updated",
                        path,
                    )
            except OSError:
                pass
            file_start = (
                vma.vm_start - vma.vm_pgoff * mm.prog_["PAGE_SIZE"]
            ).value_()
            mod = up.extra_module(path, create=True)
            mod.address_range = (file_start, vma.vm_end.value_())

    # Now set the address ranges based on the observed file end, then load the
    # ELF files.
    for mod in up.modules():
        path = mod.name
        mod.address_range = (mod.address_range[0], file_vm_end[path])
        mod.try_file(path)

    return up


def pstack_print_process(task: Object) -> None:
    comm = task.comm.string_().decode("utf-8", errors="replace")
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
        tcomm = thread.comm.string_().decode("utf-8", errors="replace")
        print(f"  Thread {i} TID={tid} ('{tcomm}')")
        kstack = prog.stack_trace(thread)
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
    args = parser.parse_args(sys.argv[2:])
    for task in get_tasks(prog, args):
        pstack_print_process(task)
        print()


class Pstack(CorelensModule):
    """Select and print user + kernel stacks, if data is available"""

    name = "pstack"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        add_task_args(parser)

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        for task in get_tasks(prog, args):
            pstack_print_process(task)
            print()


if __name__ == "__main__":
    logging.basicConfig()
    prog: Program
    if len(sys.argv) <= 1 or sys.argv[1] not in ("dump", "print", "pstack"):
        sys.exit(
            f"usage: drgn [args...] {sys.argv} [dump | print | pstack] ..."
        )
    elif sys.argv[1] == "dump":
        dump(prog)  # noqa
    elif sys.argv[1] == "print":
        dump_print(sys.argv[2])
    elif sys.argv[1] == "pstack":
        pstack(prog)  # noqa
