# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from contextlib import redirect_stdout
from io import StringIO

from drgn.helpers.linux import for_each_task

from drgn_tools import lock
from drgn_tools import locking
from drgn_tools.bt import _remove_sym_suffixes
from tests import DrgnToolsTestCase
from tests import skip_live
from tests import skip_unless_have_kmod
from tests import skip_unless_vmcore
from tests import skip_vmcore


class TestLock(DrgnToolsTestCase):
    @skip_vmcore("*uek4*")
    def test_locks(self):
        lock.scan_lock(self.prog, stack=True)

    def _lockmod_threads(self):
        lockmod_threads = []
        for task in for_each_task(self.prog):
            if task.comm.string_().startswith(b"lockmod"):
                lockmod_threads.append(task)

        if not lockmod_threads:
            self.fail("no lockmod kthreads found")
        return lockmod_threads

    @skip_unless_have_kmod
    def test_scan_lock_live_with_kmod(self):
        self._lockmod_threads()
        with redirect_stdout(StringIO()) as stdout:
            lock.scan_lock(self.prog, stack=False)

        output = stdout.getvalue()
        self.assertIn("Mutex:", output)
        self.assertIn("Semaphore:", output)
        self.assertIn("Rwsem:", output)
        self.assertIn("lockmod-mutex", output)
        self.assertIn("lockmod-sem", output)
        self.assertIn("lockmod-rwsem", output)

    # the rwsem code does not support UEK4, no reason to add support
    @skip_live
    @skip_unless_vmcore("*lockmod*")
    def test_locking_with_lockmod_vmcore(self):
        self._check_locking_with_lockmod()

    @skip_unless_have_kmod
    def test_locking_live_with_kmod(self):
        self._check_locking_with_lockmod()

    def _check_locking_with_lockmod(self):
        seen_kinds = set()

        for task in self._lockmod_threads():
            print(
                f"PID {task.pid.value_()} COMM {task.comm.string_().decode()}"
            )
            comm = task.comm.string_()
            if b"owner" in comm:
                # this owns the locks
                continue

            if b"mutex" in comm:
                kind = "mutex"
                var = "lock"
                func_substr = "mutex_lock"
            elif b"rwsem" in comm:
                kind = "rw_semaphore"
                var = "sem"
                func_substr = "rwsem"
            else:
                kind = "semaphore"
                var = "sem"
                func_substr = "down"
            seen_kinds.add(kind)

            # There can be multiple frames which may contain the lock, we will need
            # to try all of them.
            trace = self.prog.stack_trace(task)
            frames = []
            for frame in trace:
                fn = _remove_sym_suffixes(frame.name)
                if fn and func_substr in fn:
                    frames.append(frame)
            if not frames:
                self.fail("could not find relevant stack frame in lockmod")

            # Test 1: if DWARF debuginfo is present, then this will try to use the
            # variable name to access the lock. Otherwise, for CTF we will fall back
            # to using the stack offsets.
            for frame in frames:
                value = locking.get_lock_from_frame(
                    self.prog, task, frame, kind, var
                )
                if value is not None:
                    break
            else:
                self.fail(f"Could not find lock using {self.debuginfo_type}")

            if self.debuginfo_type == "ctf":
                # The second test is redundant, skip it.
                continue

            # Test 2: if DWARF debuginfo is present, we can actually give a fake
            # variable name! This will force the code to fall back to the stack
            # offsets, which should still work. This essentially simulates the
            # possibility of a DWARF unwind where we get an absent object.
            for frame in frames:
                value = locking.get_lock_from_frame(
                    self.prog, task, frame, kind, "invalid variable name"
                )
                if value is not None:
                    break
            else:
                self.fail("Could not find lock using fallback method")

        self.assertEqual(
            {"mutex", "rw_semaphore", "semaphore"},
            seen_kinds,
        )
