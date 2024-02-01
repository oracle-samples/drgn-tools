# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.pid import for_each_task

from drgn_tools import task
from drgn_tools.workqueue import for_each_worker


def test_show_taskinfo(prog):
    print("===== Task information in their last arrival order =====")
    task.show_tasks_last_runtime(for_each_task(prog))
    print("===== Display task information =====")
    task.show_taskinfo(prog, for_each_task(prog))


def test_user_kernel_threads(prog):
    init = find_task(prog, 1)
    assert task.is_user(init)
    assert task.is_group_leader(init)

    kworker = next(for_each_worker(prog)).task
    assert task.is_kthread(kworker)
    assert not task.is_user(kworker)
    assert task.is_group_leader(kworker)
