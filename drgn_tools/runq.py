# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
from typing import Iterator
from typing import Set

from drgn import container_of
from drgn import Object
from drgn import Program
from drgn import sizeof
from drgn.helpers.common import escape_ascii_string
from drgn.helpers.linux.bitops import for_each_set_bit
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.llist import llist_empty
from drgn.helpers.linux.llist import llist_for_each_entry
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry

from drgn_tools.corelens import CorelensModule
from drgn_tools.task import task_lastrun2now
from drgn_tools.util import timestamp_str

EXPLAIN_WAKELIST = """
[TASKS ON WAKE LIST]
    A runq's wakelist temporarily holds tasks that are about to be woken
    up on that CPU. If this list has multiple tasks, it usually means that
    this CPU has missed multiple scheduler IPIs. This can imply issues
    like IRQs being disabled for too long, IRQ delivery issues between hypervisor
    and VM, or some other issue.
"""
EXPLAIN_IDLE_RUNQ = """
[IDLE RUN QUEUE]
    An idle runq:
        * should have current pid as 0.
        * should have nr_running as 0.
        * ideally should not have any tasks.
          this is not necessarily an error because
          scheduler may just be bringing it out of idle.
"""


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


def for_each_task_on_cfs_rq(prog: Program, cpu: int) -> Iterator[Object]:
    """
    Iterate through all tasks, on a CPU's CFS runq.

    :param prog: drgn program
    :param cpu: cpu number
    :return: Iterator of ``struct task_struct *`` objects
    """
    runq = per_cpu(prog["runqueues"], cpu)
    cfs_rq = runq.cfs
    rb_root = cfs_rq.tasks_timeline.rb_root
    for se in rbtree_inorder_for_each_entry(
        "struct sched_entity", rb_root, "run_node"
    ):
        task = container_of(se, "struct task_struct", "se")
        yield task


def num_tasks_on_cfs_rq(prog: Program, cpu: int) -> int:
    """
    Get number of tasks, on a CPU's CFS runq.

    :param cpu: cpu number
    :return: number of tasks
    """
    return len(list(for_each_task_on_cfs_rq(prog, cpu)))


def for_each_task_on_rt_rq(prog: Program, cpu: int) -> Iterator[Object]:
    """
    Iterate through all tasks, on a CPU's RT runq.

    :param prog: drgn program
    :param cpu: cpu number
    :return: Iterator of ``struct task_struct *`` objects
    """
    runq = per_cpu(prog["runqueues"], cpu)
    rt_rq = runq.rt
    active = rt_rq.active
    queues = active.queue
    for prio in for_each_set_bit(active.bitmap, sizeof(active.bitmap) * 8):
        head = queues[prio]
        if prio > 99:
            break

        for se in list_for_each_entry(
            "struct sched_rt_entity", head.address_of_(), "run_list"
        ):
            task = container_of(se, "struct task_struct", "rt")
            yield task


def num_tasks_on_rt_rq(prog: Program, cpu: int) -> int:
    """
    Get number of tasks, on a CPU's RT runq.

    :param cpu: cpu number
    :return: number of tasks
    """
    return len(list(for_each_task_on_rt_rq(prog, cpu)))


def for_each_task_on_dl_rq(prog: Program, cpu: int) -> Iterator[Object]:
    """
    Iterate through all tasks, on a CPU's DL runq.

    :param prog: drgn program
    :param cpu: cpu number
    :return: Iterator of ``struct task_struct *`` objects
    """
    runq = per_cpu(prog["runqueues"], cpu)
    dl_rq = runq.dl
    rb_root = dl_rq.root.rb_root
    for dl in rbtree_inorder_for_each_entry(
        "struct sched_dl_entity", rb_root, "rb_node"
    ):
        task = container_of(dl, "struct task_struct", "dl")
        yield task


def num_tasks_on_dl_rq(prog: Program, cpu: int) -> int:
    """
    Get number of tasks, on a CPU's DL runq.

    :param prog: drgn program
    :param cpu: cpu number
    :return: number of tasks
    """
    return len(list(for_each_task_on_dl_rq(prog, cpu)))


def for_each_task_on_rq(prog: Program, cpu: int) -> Iterator[Object]:
    """
    Iterate through all tasks, on a CPU's runq.

    :param prog: drgn program
    :param cpu: cpu number
    :return: Iterator of ``struct task_struct *`` objects
    """

    yield from for_each_task_on_rt_rq(prog, cpu)
    yield from for_each_task_on_cfs_rq(prog, cpu)
    yield from for_each_task_on_dl_rq(prog, cpu)


def for_each_task_on_rq_wake_list(prog: Program, cpu: int) -> Iterator[Object]:
    """
    Iterate through all tasks, on a CPU's wake_list.

    A CPU's wake_list contains tasks, that are in the process of being woken
    up and have not yet landed on a CPU runq after wakeup.
    Tasks should not reside here for long.

    :param prog: drgn program
    :param cpu: cpu number
    :return: Iterator of ``struct task_struct *`` objects
    """

    runq = per_cpu(prog["runqueues"], cpu)
    for task in llist_for_each_entry(
        "struct task_struct", runq.wake_list.first, "wake_entry"
    ):
        yield task


def check_idle_runq(prog: Program, cpu: int, explanations: Set[str]) -> None:
    """
    Check an idle runq.

    :param prog: drgn program
    :param cpu: cpu number
    """
    runq = per_cpu(prog["runqueues"], cpu)
    if runq.curr.pid.value_() != 0:
        return

    explanations.add(EXPLAIN_IDLE_RUNQ)
    if runq.nr_running.value_() != 0:
        print(f"Idle cpu: {cpu} has non-zero nr_running")

    nr_cfs_task = num_tasks_on_cfs_rq(prog, cpu)
    nr_rt_task = num_tasks_on_rt_rq(prog, cpu)
    nr_dl_task = num_tasks_on_dl_rq(prog, cpu)

    if nr_cfs_task != 0:
        print(f"Idle cpu: {cpu} has {nr_cfs_task} tasks on CFS runq")

    if nr_rt_task != 0:
        print(f"Idle cpu: {cpu} has {nr_rt_task} tasks on RT runq")

    if nr_dl_task != 0:
        print(f"Idle cpu: {cpu} has {nr_dl_task} tasks on DL runq")
    print("See IDLE RUN QUEUE below")


def check_runq_wakelist(
    prog: Program, cpu: int, explanations: Set[str]
) -> None:
    """
    Check runq's wakelist.

    :param prog: drgn program
    :param cpu: cpu number
    """
    runq = per_cpu(prog["runqueues"], cpu)
    if llist_empty(runq.wake_list):
        return

    print("\n")
    explanations.add(EXPLAIN_WAKELIST)
    print(f"cpu: {cpu} has following tasks in its runq wake_list:")
    for task in for_each_task_on_rq_wake_list(prog, cpu):
        print(
            f"task pid: {task.pid.value_()}, comm:  {task.comm.string_().decode()}"
        )
    print("See TASKS ON WAKE LIST below")


def dump_rt_runq_wait_summary(
    prog: Program, cpu: int, qduration_thresh_ms: int = 1000
):
    """
    Iterate through all tasks, on a CPU's runq and list tasks that have been queued
    for greater than specified threshold in ms (default 1000 ms).

    :param prog: drgn Program
    :param cpu: cpu number
    :param qduration_thresh_ms: threshold for wait duration on runq
    """
    runq = per_cpu(prog["runqueues"], cpu)
    for task in for_each_task_on_rt_rq(prog, cpu):
        try:
            if (
                task.sched_info.last_queued.value_() > 0
                and task.sched_info.last_queued.value_()
                > task.sched_info.last_arrival.value_()
            ):
                qduration = (
                    runq.clock.value_() - task.sched_info.last_queued.value_()
                )
                print(
                    f"cpu: {cpu} pid: {task.pid.value_()} prio: {task.prio.value_()} queued for {qduration} nsecs"
                )
        except AttributeError:
            pass


def dump_cfs_runq_wait_summary(
    prog: Program, cpu: int, qduration_thresh_ms: int = 1000
):
    """
    Iterate through all tasks, on a CPU's runq and list tasks that have been queued
    for greater than specified threshold in ms (default 1000 ms).

    :param prog: drgn Program
    :param cpu: cpu number
    :param qduration_thresh_ms: threshold for wait duration on runq
    """
    runq = per_cpu(prog["runqueues"], cpu)
    for task in for_each_task_on_cfs_rq(prog, cpu):
        try:
            if (
                task.sched_info.last_queued.value_() > 0
                and task.sched_info.last_queued.value_()
                > task.sched_info.last_arrival.value_()
            ):
                qduration = (
                    runq.clock.value_() - task.sched_info.last_queued.value_()
                )
                print(
                    f"cpu: {cpu} pid: {task.pid.value_()} prio: {task.prio.value_()} queued for {qduration} nsecs"
                )
        except AttributeError:
            pass


def dump_runq_wait_summary(
    prog: Program, cpu: int, qduration_thresh_ms: int = 1000
):
    """
    Iterate through all tasks, on a CPU's runq and list tasks that have been queued
    for greater than specified threshold in ms (default 1000 ms).

    :param prog: drgn Program
    :param cpu: cpu number
    :param qduration_thresh_ms: threshold for wait duration on runq
    """
    dump_cfs_runq_wait_summary(prog, cpu, qduration_thresh_ms)
    dump_rt_runq_wait_summary(prog, cpu, qduration_thresh_ms)


def run_queue_check(prog: Program) -> None:
    """
    Check and report runqueue anomalies.

    :param prog: drgn program
    """

    explanations: Set[str] = set()
    for cpu in for_each_online_cpu(prog):
        check_idle_runq(prog, cpu, explanations)
        check_runq_wakelist(prog, cpu, explanations)
        dump_runq_wait_summary(prog, cpu)
        print("\n")

    if not explanations:
        return
    print("Note: found some possible run queue issues. Explanations below:")
    for explanation in explanations:
        print(explanation)


class RunQueueCheck(CorelensModule):
    """
    Check and report runqueue anomalies.
    The content of this report does not necessarily mean an
    error condition or a problem. But it mentions things that
    don'y happen usually, so should not be ignored.
    """

    name = "runqcheck"
    live_ok = False

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        run_queue_check(prog)


class RunQueue(CorelensModule):
    """
    List process that are in RT and CFS queue.
    """

    name = "runq"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        run_queue(prog)
