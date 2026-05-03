# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Help detect hang issues
"""
import argparse

from drgn import Program
from drgn.helpers.common import escape_ascii_string
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.sched import task_state_to_char

from drgn_tools.bt import bt
from drgn_tools.corelens import CorelensModule
from drgn_tools.task import task_lastrun2now
from drgn_tools.util import timestamp_str


def for_each_tasks_in_d_state(prog: Program):
    for task in for_each_task(prog):
        st = task_state_to_char(task)
        if st != "D":
            continue
        yield task


def detect_hang(prog: Program, stack: bool, time: int) -> None:
    """
    Scan hung tasks.

    :param prog: drgn program
    :param stack: bool
    :param time: int
    """
    n_hung_tasks = 0
    tasks = list(for_each_tasks_in_d_state(prog))
    if not tasks:
        print("There is no tasks in D state.")
        return

    tasks.sort(key=task_lastrun2now, reverse=True)
    longest_hang_task = tasks[0]
    longest_hang_time = task_lastrun2now(longest_hang_task) / 1e9
    for task in tasks:
        run_time = task_lastrun2now(task)
        comm = escape_ascii_string(task.comm.string_())
        pid = task.pid.value_()
        prio = task.prio.value_()
        if run_time / 1e9 > time:
            n_hung_tasks += 1
            print(
                f"PID: {pid:<6d}  TASK: {task.value_():x}  PRIO: {prio}"
                f'  COMMAND: "{comm}"'
                f"  HUNG TIME: {timestamp_str(run_time)}",
            )
            if stack:
                print("Calltrace:")
                bt(task)
                print()

    print(
        f"There are {n_hung_tasks} tasks hung (in D state) for more than {time} seconds as above."
    )
    print(
        f"The longest hung task as below has remained in the D state for {longest_hang_time:.2f} seconds."
    )
    bt(longest_hang_task)


class Hang(CorelensModule):
    """Detectors for hang issues"""

    name = "hang"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--stack",
            action="store_true",
            help="Print the stacks. Only the stack of longest hung task is printed if not set.",
        )
        parser.add_argument(
            "--time",
            "-t",
            type=float,
            default=10,
            help="list all the processes that have been hung more than <time> seconds",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        detect_hang(prog, args.stack, args.time)
