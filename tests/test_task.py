# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.pid import for_each_task

from drgn_tools import task
from drgn_tools.workqueue import for_each_worker
from tests import DrgnToolsTestCase


class TestTask(DrgnToolsTestCase):
    def test_show_taskinfo(self):
        print("===== Task information in their last arrival order =====")
        task.show_tasks_last_runtime(for_each_task(self.prog))
        print("===== Display task information =====")
        task.show_taskinfo(self.prog, for_each_task(self.prog))

    def test_user_kernel_threads(self):
        init = find_task(self.prog, 1)
        assert task.is_user(init)
        assert task.is_group_leader(init)

        for worker in for_each_worker(self.prog):
            if worker.task:
                kworker = worker.task
                break
        else:
            self.fail("no kworker available to test kthread helper")

        assert task.is_kthread(kworker)
        assert not task.is_user(kworker)
        assert task.is_group_leader(kworker)

    def test_count_interruptible_tasks(self):
        task.count_tasks_in_state(self.prog, "TASK_INTERRUPTIBLE")

    def test_count_uninterruptible_tasks(self):
        task.count_tasks_in_state(self.prog, "TASK_UNINTERRUPTIBLE")

    def test_count_stopped_tasks(self):
        task.count_tasks_in_state(self.prog, "TASK_STOPPED")

    def test_count_traced_tasks(self):
        task.count_tasks_in_state(self.prog, "TASK_TRACED")

    def test_count_exit_dead_tasks(self):
        task.count_tasks_in_state(self.prog, "EXIT_DEAD")

    def test_count_exit_zombie_tasks(self):
        task.count_tasks_in_state(self.prog, "EXIT_ZOMBIE")

    def test_count_parked_tasks(self):
        task.count_tasks_in_state(self.prog, "TASK_PARKED")

    def test_count_dead_tasks(self):
        task.count_tasks_in_state(self.prog, "TASK_DEAD")

    def test_count_wakekill_tasks(self):
        task.count_tasks_in_state(self.prog, "TASK_WAKEKILL")

    def test_count_waking_tasks(self):
        task.count_tasks_in_state(self.prog, "TASK_WAKING")

    def test_count_noload_tasks(self):
        task.count_tasks_in_state(self.prog, "TASK_NOLOAD")

    def test_count_new_tasks(self):
        task.count_tasks_in_state(self.prog, "TASK_NEW")

    def test_count_killable_tasks(self):
        task.count_tasks_in_state(self.prog, "TASK_KILLABLE")

    def test_count_idle_tasks(self):
        task.count_tasks_in_state(self.prog, "TASK_IDLE")
