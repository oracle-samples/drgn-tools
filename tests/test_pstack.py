# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
import gzip
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from drgn import Architecture
from drgn.helpers.linux import task_state_to_char
from drgn.helpers.linux.pid import find_task

from drgn_tools import pstack
from drgn_tools.task import task_cpu
from tests import DrgnToolsTestCase
from tests import skip_kernel_versions_below
from tests import skip_live
from tests import skip_unless_live
from tests import sleeping_proc


def do_test_task_running_pt_regs(test_case, prog, task):
    # Really, all task_running_pt_regs() does is take the registers dict from
    # the top stack frame, and convert it into a "struct pt_regs" according to
    # the particular architecture. So we can test its functionality on a kernel
    # stack, rather than a user stack. Verify that the original stack trace
    # matches the stack trace we get from the generated pt_regs.
    orig_trace = prog.stack_trace(task)
    pt_regs = pstack.task_running_pt_regs(orig_trace)
    new_trace = prog.stack_trace(pt_regs)
    test_case.assertEqual(len(orig_trace), len(new_trace))
    for orig, new in zip(orig_trace, new_trace):
        test_case.assertEqual(orig.pc, new.pc)


def build_args(
    output,
    max_stack_bytes=1024 * 1024,
    comm=None,
    state=None,
    all=False,
    online=False,
    pid=None,
):
    if comm is not None:
        comm = []
    if state is not None:
        state = []
    if pid is not None:
        state = []

    return argparse.Namespace(
        output=output,
        max_stack_bytes=max_stack_bytes,
        comm=comm,
        state=state,
        all=all,
        online=online,
        pid=pid,
    )


@skip_kernel_versions_below("4.14")
class TestPstack(DrgnToolsTestCase):
    @skip_unless_live
    def test_task_saved_pt_regs(self):
        with sleeping_proc() as proc:
            regs = pstack.task_saved_pt_regs(find_task(self.prog, proc.pid))

            # We can verify that the stack pointer points into a stack region of
            # the task, and that the instruction pointer points into a mapped
            # object file.
            if self.prog.platform.arch == Architecture.X86_64:
                pc = int(regs.ip)
                sp = int(regs.sp)
            else:
                pc = int(regs.pc)
                sp = int(regs.sp)

            pc_found = sp_found = False
            for line in open(f"/proc/{proc.pid}/maps", "r"):
                fields = line.split()
                start = int(fields[0].split("-")[0], 16)
                end = int(fields[0].split("-")[1], 16)
                permission = fields[1]
                file = fields[-1]

                if start <= pc < end:
                    pc_found = True
                    # It must be an ELF file:
                    self.assertEqual(open(file, "rb").read(4), b"\x7fELF")
                    # It must be an executable mapping:
                    self.assertIn("x", permission)
                if start <= sp < end:
                    sp_found = True
                    # It must be in a stack region
                    self.assertEqual(file, "[stack]")

            self.assertTrue(pc_found and sp_found)

    @skip_unless_live
    def test_task_running_pt_regs_live(self):
        with sleeping_proc() as proc:
            task = find_task(self.prog, proc.pid)
            do_test_task_running_pt_regs(self, self.prog, task)

    @skip_live
    def test_task_running_pt_regs_vmcore(self):
        task = find_task(self.prog, 1)
        do_test_task_running_pt_regs(self, self.prog, task)

    @skip_unless_live
    def test_dump(self):
        with sleeping_proc() as proc, TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            pid = proc.pid
            pstack.dump(self.prog, build_args(tmp_dir / "dump", pid=[pid]))
            with gzip.open(tmp_dir / "dump", "rb") as f:
                magic = f.read(8)
                self.assertEqual(magic, b"pstack\x00\x01")

                metadata = pstack.read_json_object(f)
                self.assertEqual(
                    metadata, {"page_size": int(self.prog["PAGE_SIZE"])}
                )

                task_meta = pstack.read_json_object(f)
                self.assertEqual(task_meta["pid"], proc.pid)
                self.assertEqual(
                    task_meta["comm"],
                    open(f"/proc/{pid}/comm").read().strip(),
                )
                self.assertFalse(task_meta["kernel"])
                self.assertEqual(len(task_meta["threads"]), 1)

                # Get executables from /proc/{pid}/maps and compare with the
                # metadata.
                executables = []
                start_addr = 0
                for line in open(f"/proc/{pid}/maps"):
                    fields = line.split(maxsplit=5)
                    if len(fields) != 6:
                        continue
                    filename = fields[-1].rstrip()
                    if filename[0] == "[":
                        continue
                    if int(fields[2], 16) == 0:
                        start_addr = int(fields[0].split("-")[0], 16)
                    if "x" in fields[1] and start_addr != 0:
                        executables.append((filename, start_addr))
                        start_addr = 0
                self.assertEqual(len(executables), len(task_meta["mm"]))
                for filename, start_addr in executables:
                    self.assertEqual(task_meta["mm"][filename][0], start_addr)

                # Now ensure the thread metadata is correct:
                thread = task_meta["threads"][0]
                self.assertEqual(thread["tid"], pid)
                self.assertEqual(thread["comm"], task_meta["comm"])
                self.assertEqual(
                    thread["kstack"], str(self.prog.stack_trace(pid))
                )
                self.assertEqual(
                    thread["cpu"], task_cpu(find_task(self.prog, pid))
                )
                self.assertFalse(thread["on_cpu"])
                self.assertEqual(thread["state"], "S")

                # Now ensure we have some stack data. Not too much verification
                # of correctness here, just want to ensure it is done correctly.
                end = b"\xff" * 8
                pgsize = int(self.prog["PAGE_SIZE"])
                while True:
                    header = f.read(8)
                    self.assertEqual(len(header), 8)
                    if header == end:
                        break
                    self.assertEqual(len(f.read(pgsize)), pgsize)

                # EOF
                self.assertEqual(f.read(), b"")

    @skip_unless_live
    def test_read_dump(self):
        with sleeping_proc() as proc, TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            pid = proc.pid
            with redirect_stdout(StringIO()):
                pstack.dump(self.prog, build_args(tmp_dir / "dump", pid=[pid]))

            with redirect_stdout(StringIO()) as stdout:
                pstack.dump_print(tmp_dir / "dump")
            stdout_from_dump = stdout.getvalue()

            with redirect_stdout(StringIO()) as stdout:
                pstack.pstack_print_process(find_task(self.prog, pid))
                print()
            stdout_from_pstack = stdout.getvalue()
            self.assertEqual(stdout_from_dump, stdout_from_pstack)

    def test_get_tasks_pid(self):
        args = build_args("IGNORE", pid=[1])
        result = pstack.get_tasks(self.prog, args)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].pid.value_(), 1)

    @skip_live  # this will flake on live systems
    def test_get_tasks_state_and_pid(self):
        args = build_args("IGNORE", pid=[1], state=["R"])
        result = pstack.get_tasks(self.prog, args)
        found_init = False
        for task in result:
            self.assertTrue(
                task_state_to_char(task) == "R" or task.pid.value_() == 1
            )
            found_init = found_init or task.pid.value_() == 1
        self.assertTrue(found_init)
