# Copyright (c) 2025, 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
from contextlib import redirect_stdout
from io import StringIO

from drgn import Architecture
from drgn.helpers.linux import task_state_to_char
from drgn.helpers.linux.pid import find_task

from drgn_tools import pstack
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
    def test_end_to_end(self):
        # Since live tests are now expected to run in an Oracle Linux rootfs, we
        # can be pretty confident that we have all the necessary userspace
        # debuginfo and .gnu_debugdata symbols to do the full unwind.
        with sleeping_proc() as proc:
            pid = proc.pid
            with redirect_stdout(StringIO()) as stdout:
                pstack.pstack_print_process(find_task(self.prog, pid))

            kernel, user = stdout.getvalue().split(
                "------ userspace ---------"
            )
            self.assertRegex(kernel, r".*#\d+ +schedule\b.*")
            self.assertRegex(kernel, r".*#\d+ +ksys_read\b.*")

            self.assertRegex(user, r".*#\d+ +_Py_read\b.*")
            self.assertRegex(user, r".*#\d+ +Py_(Run)?Main\b.*")
            self.assertRegex(user, r".*#\d+ +_start\b.*")

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
