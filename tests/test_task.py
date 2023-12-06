# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn.helpers.linux.pid import for_each_task

from drgn_tools import task


def test_show_taskinfo(prog):
    print("===== Task information in their last arrival order =====")
    task.show_tasks_last_runtime(for_each_task(prog))
    print("===== Display task information =====")
    task.show_taskinfo(prog, for_each_task(prog))
