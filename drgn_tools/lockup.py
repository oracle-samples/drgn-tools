# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse

from drgn import Program
from drgn.helpers.common import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.percpu import per_cpu

from drgn_tools.bt import bt
from drgn_tools.corelens import CorelensModule
from drgn_tools.task import task_lastrun2now
from drgn_tools.util import timestamp_str


def scan_lockup(
    prog: Program, min_run_time_seconds: int = 1, skip_swapper: bool = True
) -> None:
    """
    Scan potential lockups on cpus.

    :param prog: drgn program
    :param min_run_time_seconds: int
    :param skip_swapper: bool
    """
    nr_processes = 0
    for cpus in for_each_online_cpu(prog):
        runqueue = per_cpu(prog["runqueues"], cpus)
        curr_task_addr = runqueue.curr.value_()
        curr_task = runqueue.curr[0]
        comm = escape_ascii_string(curr_task.comm.string_())
        pid = curr_task.pid.value_()
        run_time = task_lastrun2now(curr_task)
        prio = curr_task.prio.value_()
        if run_time < min_run_time_seconds * 1e9:
            continue
        if skip_swapper and comm == f"swapper/{cpus}":
            continue
        print(f"CPU {cpus} RUNQUEUE: {runqueue.address_of_().value_():x}")
        print(
            f"  PID: {pid:<6d}  TASK: {curr_task_addr:x}  PRIO: {prio}"
            f'  COMMAND: "{comm}"',
            f"  LOCKUP TIME: {timestamp_str(run_time)}",
        )
        print("\nCalltrace:")
        bt(task_or_prog=curr_task.address_of_())
        print()
        nr_processes += 1

    print(
        f"We found {nr_processes} processes running more than {min_run_time_seconds} seconds."
    )


class LockUp(CorelensModule):
    """Print tasks which have been on-cpu for too long"""

    name = "lockup"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--time",
            "-t",
            type=float,
            default=2,
            help="list all the processes that have been running more than <time> seconds",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        scan_lockup(prog, args.time)
