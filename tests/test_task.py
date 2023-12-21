# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn.helpers.linux.pid import for_each_task

from drgn_tools import task


def test_task_last_runtime(prog):
    task.show_tasks_last_runtime(for_each_task(prog))


def test_count_interruptible_tasks(prog):
    task.count_interruptible_tasks(prog)


def test_count_uninterruptible_tasks(prog):
    task.count_uninterruptible_tasks(prog)


def test_count_stopped_tasks(prog):
    task.count_stopped_tasks(prog)


def test_count_traced_tasks(prog):
    task.count_traced_tasks(prog)


def test_count_exit_dead_tasks(prog):
    task.count_exit_dead_tasks(prog)


def test_count_exit_zombie_tasks(prog):
    task.count_exit_zombie_tasks(prog)


def test_count_parked_tasks(prog):
    task.count_parked_tasks(prog)


def test_count_dead_tasks(prog):
    task.count_dead_tasks(prog)


def test_count_wakekill_tasks(prog):
    task.count_wakekill_tasks(prog)


def test_count_waking_tasks(prog):
    task.count_waking_tasks(prog)


def test_count_noload_tasks(prog):
    task.count_noload_tasks(prog)


def test_count_new_tasks(prog):
    task.count_new_tasks(prog)


def test_count_killable_tasks(prog):
    task.count_killable_tasks(prog)


def test_count_idle_tasks(prog):
    task.count_idle_tasks(prog)
