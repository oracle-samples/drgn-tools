# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse

from drgn import container_of
from drgn import Object
from drgn import Program
from drgn.helpers.common import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.percpu import per_cpu

from drgn_tools.corelens import CorelensModule
from drgn_tools.task import task_lastrun2now
from drgn_tools.util import timestamp_str

# List runqueus per cpu


def _print_rt_runq(runqueue: Object) -> None:
    count = 0
    prio_array = hex(runqueue.rt.active.address_ - 16)
    print("  RT PRIO_ARRAY:", prio_array)
    rt_prio_array = runqueue.rt.active.queue
    for que in rt_prio_array:
        for t in list_for_each_entry(
            "struct sched_rt_entity", que.address_of_(), "run_list"
        ):
            tsk = container_of(t, "struct task_struct", "rt")
            if tsk == runqueue.curr:
                continue
            count += 1
            print(
                " " * 4,
                '[{:3d}] PID: {:<6d} TASK: {} COMMAND: "{}"'.format(
                    tsk.prio.value_(),
                    tsk.pid.value_(),
                    hex(tsk),
                    escape_ascii_string(tsk.comm.string_()),
                ),
            )
    if count == 0:
        print("     [no tasks queued]")


def _print_cfs_runq(runqueue: Object) -> None:
    cfs_root = hex(runqueue.cfs.tasks_timeline.address_of_().value_())
    print("  CFS RB_ROOT:", cfs_root)
    count = 0
    runq = runqueue.address_of_()
    for t in list_for_each_entry(
        "struct task_struct", runq.cfs_tasks.address_of_(), "se.group_node"
    ):
        if t == runqueue.curr:
            continue
        count += 1
        print(
            " " * 4,
            '[{:3d}] PID: {:<6d} TASK: {}  COMMAND: "{}"'.format(
                t.prio.value_(),
                t.pid.value_(),
                hex(t),
                escape_ascii_string(t.comm.string_()),
            ),
        )
    if count == 0:
        print("     [no tasks queued]")


def run_queue(prog: Program) -> None:
    """
    Print tasks which are in the RT and CFS runqueues on each CPU.
    processes running more than x seconds.

    :param prog: drgn program
    """

    # _cpu = drgn.helpers.linux.cpumask.for_each_online_cpu(prog)
    for cpus in for_each_online_cpu(prog):
        runqueue = per_cpu(prog["runqueues"], cpus)
        curr_task_addr = runqueue.curr.value_()
        curr_task = runqueue.curr[0]
        comm = escape_ascii_string(curr_task.comm.string_())
        pid = curr_task.pid.value_()
        run_time = task_lastrun2now(curr_task)
        prio = curr_task.prio.value_()
        print(f"CPU {cpus} RUNQUEUE: {runqueue.address_of_().value_():x}")
        print(
            f"  CURRENT:   PID: {pid:<6d}  TASK: {curr_task_addr:x}  PRIO: {prio}"
            f'  COMMAND: "{comm}"'
            f"  RUNTIME: {timestamp_str(run_time)}",
        )
        # RT PRIO_ARRAY
        _print_rt_runq(runqueue)
        # CFS RB_ROOT
        _print_cfs_runq(runqueue)
        print()


class RunQueue(CorelensModule):
    """
    List process that are in RT and CFS queue.
    """

    name = "runq"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        run_queue(prog)
