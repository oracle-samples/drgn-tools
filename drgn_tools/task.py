# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers related to accessing fields of task_struct in a compatible way.

The ``struct task_struct`` is a constantly evolving struct, and it can be
impacted by many configuration options. This module aims to help paper over
those many differences so your code will run on a variety of kernel versions
and configurations.
"""
import argparse
from typing import Iterable

import drgn
from drgn import Object
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.sched import cpu_curr
from drgn.helpers.linux.sched import task_state_to_char

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table
from drgn_tools.util import has_member

# tsk->state values
TASK_RUNNING = 0x0000
TASK_INTERRUPTIBLE = 0x0001
TASK_UNINTERRUPTIBLE = 0x0002
__TASK_STOPPED = 0x0004
__TASK_TRACED = 0x0008
# Used in tsk->exit_state
EXIT_DEAD = 0x0010
EXIT_ZOMBIE = 0x0020
# Used in tsk->state again
TASK_PARKED = 0x0040
TASK_DEAD = 0x0080
TASK_WAKEKILL = 0x0100
TASK_WAKING = 0x0200
TASK_NOLOAD = 0x0400
TASK_NEW = 0x0800

TASK_KILLABLE = TASK_WAKEKILL | TASK_UNINTERRUPTIBLE
TASK_STOPPED = TASK_WAKEKILL | __TASK_STOPPED
TASK_TRACED = TASK_WAKEKILL | __TASK_TRACED
TASK_IDLE = TASK_UNINTERRUPTIBLE | TASK_NOLOAD

def nanosecs_to_secs(nanosecs: int) -> float:
    """
    Convert from nanosecs to secs

    :param nanosecs: time duration in nano secs
    :returns: time duration in secs
    """
    val = nanosecs // 1000000
    return val / 1000


def get_task_arrival_time(task: Object) -> int:
    """
    Get a task's arrival time on cpu

    A task's arrival time is only updated when the task is put ON a cpu via
    context_switch.

    :param task: ``struct task_struct *``
    :returns: arrival time instance in ns granularity
    """

    if has_member(task, "last_run"):
        arrival_time = task.last_run.value_()
    elif has_member(task, "timestamp"):
        arrival_time = task.timestamp.value_()
    else:
        arrival_time = task.sched_info.last_arrival.value_()

    return arrival_time


def runq_clock(prog: drgn.Program, cpu: int) -> int:
    """
    Get clock of cpu runqueue ``struct rq``

    :param prog: drgn program
    :param cpu: cpu index
    :returns: cpu runqueue clock in ns granularity
    """
    rq = per_cpu(prog["runqueues"], cpu)
    return rq.clock.value_()


def task_lastrun2now(task: drgn.Object) -> int:
    """
    Get the duration from task last run timestamp to now

    The return duration will cover task's last run time on cpu and also
    the time staying in current status, usually the time slice for task
    on cpu will be short, so this can roughly tell how long this task
    has been staying in current status.
    For task status in "RU" status, if it's still on cpu, then this return
    the duration time this task has been running, otherwise it roughly tell
    how long this task has been staying in runqueue.

    :param prog: drgn program
    :param task: ``struct task_struct *``
    :returns: duration in ns granularity
    """
    prog = task.prog_
    arrival_time = get_task_arrival_time(task)
    rq_clock = runq_clock(prog, task_cpu(task))

    return rq_clock - arrival_time


def get_current_run_time(prog: drgn.Program, cpu: int) -> int:
    """
    Get running duration of the current task on some cpu

    :param prog: drgn program
    :param cpu: cpu index
    :returns: duration in ns granularity
    """
    return task_lastrun2now(cpu_curr(prog, cpu))


def get_runq_lag(prog: drgn.Program, cpunum: int) -> int:
    """
    Get time lag of given CPU's runq clock, relative to most recent runq
    timestamp

    A CPU's runq clock may be lagging due to reasons such as dyntick idle,
    missing sched tick updates etc.
    This helper can be used in cases where we need to make sure that a cpu's
    runq clock is uptodate.

    :param prog: drgn program
    :param cpunum: cpu index
    :returns: lag amount in ns granularity
    """
    runq_clocks = [runq_clock(prog, cpu) for cpu in for_each_online_cpu(prog)]
    runq_clocks.sort()
    runq_clock_nolag = runq_clocks[-1]
    runq_clock_thiscpu = runq_clock(prog, cpunum)

    return runq_clock_nolag - runq_clock_thiscpu


def task_thread_info(task: drgn.Object) -> drgn.Object:
    """
    Return a task's ``thread_info``

    This is an equivalent to the kernel function / inline / macro
    ``task_thread_info()``, but it must cover a wide variety of versions and
    configurations.

    :param task: Object of type ``struct task_struct *``
    :returns: The ``struct thread_info *`` for this task
    """
    if has_member(task, "thread_info"):
        return task.thread_info.address_of_()
    return drgn.cast("struct thread_info *", task.stack)


def task_cpu(task: drgn.Object) -> int:
    """
    Return the CPU on which a task is running.

    This is an equivalent to the kernel function ``task_cpu()``, but it covers
    a wide variety of variations in kernel version and configuration. It would
    be a bit impractical to spell out all the variants, but essentially, if
    there's a "cpu" field in ``struct task_struct``, then we can just use that.
    Otherwise, we need to get it from the ``thread_info``.

    :param task: Object of type ``struct task_struct *``
    :retruns: The cpu as a Python int
    """
    if has_member(task, "cpu"):
        return task.cpu.value_()
    return task_thread_info(task).cpu.value_()


def format_nanosecond_duration(nanosecs: int) -> str:
    """
    :returns: conversion of nanoseconds to [dd hh:mm:ss.ms] format
    """
    secs = nanosecs_to_secs(nanosecs)
    dd, rem = divmod(secs, 86400)
    hh, rem = divmod(rem, 3600)
    mm, secs = divmod(rem, 60)
    return "%02ld %02ld:%02ld:%06.3f" % (dd, hh, mm, secs)


def get_pid(task: Object) -> int:
    """
    :returns: PID of the task
    """
    return task.pid.value_()


def get_command(task: Object) -> str:
    """
    :returns: name of the command
    """
    return escape_ascii_string(task.comm.string_())


def show_tasks_last_runtime(tasks: Iterable[Object]) -> None:
    """
    Display task information in their last arrival order.
    """
    rows = [["LAST_ARRIVAL", "ST", "PID", "TASK", "CPU", "COMMAND"]]
    tasks = list(tasks)
    tasks.sort(key=task_lastrun2now)
    for t in tasks:
        cpu = str(task_cpu(t))
        pid = str(get_pid(t))
        state = task_state_to_char(t)
        command = get_command(t)
        time_nanosec = task_lastrun2now(t)
        last_arrival = format_nanosecond_duration(time_nanosec)
        rows.append([last_arrival, state, pid, hex(t.value_()), cpu, command])
    print_table(rows)

def is_task_in_state(task: drgn.Object, state: int) -> bool:
    """
    Check if a task is in a given state.

    :param task: ``struct task_struct *``
    :param state: specified state of task
    :returns: True if task is in specified state, False otherwise.
    """
    return task.state.value_() == state


def is_task_runnable(task: drgn.Object) -> bool:
    """
    Check if a task is in ``TASK_RUNNING`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``TASK_RUNNING`` state, False otherwise.
    """
    return is_task_in_state(task, TASK_RUNNING)


def is_task_interruptible(task: drgn.Object) -> bool:
    """
    Check if a task is in ``TASK_INTERRUPTIBLE`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``TASK_INTERRUPTIBLE`` state, False otherwise.
    """
    return is_task_in_state(task, TASK_INTERRUPTIBLE)


def is_task_uninterruptible(task: drgn.Object) -> bool:
    """
    Check if a task is in ``TASK_UNINTERRUPTIBLE`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``TASK_UNINTERRUPTIBLE`` state, False otherwise.
    """
    return is_task_in_state(task, TASK_UNINTERRUPTIBLE)


def is_task_stopped(task: drgn.Object) -> bool:
    """
    Check if a task is in ``TASK_STOPPED`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``TASK_STOPPED`` state, False otherwise.
    """
    return is_task_in_state(task, TASK_STOPPED)


def is_task_traced(task: drgn.Object) -> bool:
    """
    Check if a task is in ``TASK_TRACED`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``TASK_TRACED`` state, False otherwise.
    """
    return is_task_in_state(task, TASK_TRACED)


def is_task_exit_dead(task: drgn.Object) -> bool:
    """
    Check if a task is in ``EXIT_DEAD`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``EXIT_DEAD`` state, False otherwise.
    """
    return is_task_in_state(task, EXIT_DEAD)


def is_task_exit_zombie(task: drgn.Object) -> bool:
    """
    Check if a task is in ``EXIT_ZOMBIE`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``EXIT_ZOMBIE`` state, False otherwise.
    """
    return is_task_in_state(task, EXIT_ZOMBIE)


def is_task_parked(task: drgn.Object) -> bool:
    """
    Check if a task is in ``TASK_PARKED`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``TASK_PARKED`` state, False otherwise.
    """
    return is_task_in_state(task, TASK_PARKED)


def is_task_dead(task: drgn.Object) -> bool:
    """
    Check if a task is in ``TASK_DEAD`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``TASK_DEAD`` state, False otherwise.
    """
    return is_task_in_state(task, TASK_DEAD)


def is_task_wakekill(task: drgn.Object) -> bool:
    """
    Check if a task is in ``TASK_WAKEKILL`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``TASK_WAKEKILL`` state, False otherwise.
    """
    return is_task_in_state(task, TASK_WAKEKILL)


def is_task_waking(task: drgn.Object) -> bool:
    """
    Check if a task is in ``TASK_WAKING`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``TASK_WAKING`` state, False otherwise.
    """
    return is_task_in_state(task, TASK_WAKING)


def is_task_new(task: drgn.Object) -> bool:
    """
    Check if a task is in ``TASK_NEW`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``TASK_NEW`` state, False otherwise.
    """
    return is_task_in_state(task, TASK_NEW)


def is_task_noload(task: drgn.Object) -> bool:
    """
    Check if a task is in ``TASK_NOLOAD`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``TASK_NOLOAD`` state, False otherwise.
    """
    return is_task_in_state(task, TASK_NOLOAD)


def is_task_idle(task: drgn.Object) -> bool:
    """
    Check if a task is in ``TASK_IDLE`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``TASK_IDLE`` state, False otherwise.
    """
    return is_task_in_state(task, TASK_IDLE)


def is_task_killable(task: drgn.Object) -> bool:
    """
    Check if a task is in ``TASK_KILLABLE`` state.

    :param task: ``struct task_struct *``
    :returns: True if task is in ``TASK_KILLABLE`` state, False otherwise.
    """
    return is_task_in_state(task, TASK_KILLABLE)


def is_task_struct_leaking(prog: drgn.Program) -> bool:
    """
    Check if task_struct is leaking due to mismanagement of
    ref count.

    :param prog: drgn program
    :returns: True if task_struct objects are leaking, False
              otherwise.
    """

    slab_cache = find_slab_cache(prog, "task_struct")
    if slab_cache_is_merged(slab_cache):
        print(
            "Can't accurately get all task_struct objects, because task_struct slab cache is merged."
        )
        return False
    task_struct_count = sum(
        1
        for _ in slab_cache_for_each_allocated_object(
            slab_cache, "struct task_struct"
        )
    )
    task_count = sum(1 for _ in for_each_task(prog))

    return task_count != task_struct_count


def for_each_task_in_state(prog: drgn.Program, state: int) -> Iterable[Object]:
    """
    Iterate over all tasks in a given state.

    :param prog: drgn program
    :param state: specified state of task
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task(prog):
        if is_task_in_state(task, state):
            yield task


def for_each_runnable_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``TASK_RUNNING`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, TASK_RUNNING):
        yield task

    # init_task is always runnable and its not allocated from task_struct slab cache
    return prog["init_task"].address_of_()


def for_each_interruptible_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``TASK_INTERRUPTIBLE`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, TASK_INTERRUPTIBLE):
        yield task


def for_each_uninterruptible_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``TASK_UNINTERRUPTIBLE`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, TASK_UNINTERRUPTIBLE):
        yield task


def for_each_stopped_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``TASK_STOPPED`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, TASK_STOPPED):
        yield task


def for_each_traced_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``TASK_TRACED`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, TASK_TRACED):
        yield task


def for_each_exit_dead_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``EXIT_DEAD`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, EXIT_DEAD):
        yield task


def for_each_exit_zombie_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``EXIT_ZOMBIE`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, EXIT_ZOMBIE):
        yield task


def for_each_parked_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``TASK_PARKED`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, TASK_PARKED):
        yield task


def for_each_dead_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``TASK_DEAD`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, TASK_DEAD):
        yield task


def for_each_wakekill_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``TASK_WAKEKILL`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, TASK_WAKEKILL):
        yield task


def for_each_waking_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``TASK_WAKING`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, TASK_WAKING):
        yield task


def for_each_noload_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``TASK_NOLOAD`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, TASK_NOLOAD):
        yield task


def for_each_new_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``TASK_NEW`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, TASK_NEW):
        yield task


def for_each_killable_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``TASK_KILLABLE`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, TASK_KILLABLE):
        yield task


def for_each_idle_task(prog: drgn.Program) -> Iterable[Object]:
    """
    Iterate over all ``TASK_IDLE`` tasks in a system.

    :param prog: drgn program
    :returns: Iterator of ``struct task_struct *`` objects.
    """
    for task in for_each_task_in_state(prog, TASK_IDLE):
        yield task


def count_runnable_tasks(prog: drgn.Program) -> int:
    """
    Count all ``TASK_RUNNING`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``TASK_RUNNING`` state
    """
    count = sum(1 for _ in for_each_runnable_task(prog))

    # add 1 to final count to account for init_task, which is always runnable
    return count + 1


def count_interruptible_tasks(prog: drgn.Program) -> int:
    """
    Count all ``TASK_INTERRUPTIBLE`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``TASK_INTERRUPTIBLE`` state
    """
    count = sum(1 for _ in for_each_interruptible_task(prog))

    return count


def count_uninterruptible_tasks(prog: drgn.Program) -> int:
    """
    Count all ``TASK_UNINTERRUPTIBLE`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``TASK_UNINTERRUPTIBLE`` state
    """
    count = sum(1 for _ in for_each_uninterruptible_task(prog))

    return count


def count_stopped_tasks(prog: drgn.Program) -> int:
    """
    Count all ``TASK_STOPPED`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``TASK_STOPPED`` state
    """
    count = sum(1 for _ in for_each_stopped_task(prog))

    return count


def count_traced_tasks(prog: drgn.Program) -> int:
    """
    Count all ``TASK_TRACED`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``TASK_TRACED`` state
    """
    count = sum(1 for _ in for_each_traced_task(prog))

    return count


def count_exit_dead_tasks(prog: drgn.Program) -> int:
    """
    Count all ``EXIT_DEAD`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``EXIT_DEAD`` state
    """
    count = sum(1 for _ in for_each_exit_dead_task(prog))

    return count


def count_exit_zombie_tasks(prog: drgn.Program) -> int:
    """
    Count all ``EXIT_ZOMBIE`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``EXIT_ZOMBIE`` state
    """
    count = sum(1 for _ in for_each_exit_zombie_task(prog))

    return count


def count_parked_tasks(prog: drgn.Program) -> int:
    """
    Count all ``TASK_PARKED`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``TASK_PARKED`` state
    """
    count = sum(1 for _ in for_each_parked_task(prog))

    return count


def count_dead_tasks(prog: drgn.Program) -> int:
    """
    Count all ``TASK_DEAD`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``TASK_DEAD`` state
    """
    count = sum(1 for _ in for_each_dead_task(prog))

    return count


def count_wakekill_tasks(prog: drgn.Program) -> int:
    """
    Count all ``TASK_WAKEKILL`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``TASK_WAKEKILL`` state
    """

    count = sum(1 for _ in for_each_wakekill_task(prog))
    return count


def count_waking_tasks(prog: drgn.Program) -> int:
    """
    Count all ``TASK_WAKING`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``TASK_WAKING`` state
    """

    count = sum(1 for _ in for_each_waking_task(prog))
    return count


def count_noload_tasks(prog: drgn.Program) -> int:
    """
    Count all ``TASK_NOLOAD`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``TASK_NOLOAD`` state
    """

    count = sum(1 for _ in for_each_noload_task(prog))
    return count


def count_new_tasks(prog: drgn.Program) -> int:
    """
    Count all ``TASK_NEW`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``TASK_NEW`` state
    """

    count = sum(1 for _ in for_each_new_task(prog))
    return count


def count_killable_tasks(prog: drgn.Program) -> int:
    """
    Count all ``TASK_KILLABLE`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``TASK_KILLABLE`` state
    """

    count = sum(1 for _ in for_each_killable_task(prog))
    return count


def count_idle_tasks(prog: drgn.Program) -> int:
    """
    Count all ``TASK_IDLE`` tasks in a system.

    :param prog: drgn program
    :returns: number of tasks in ``TASK_IDLE`` state
    """
    count = sum(1 for _ in for_each_idle_task(prog))

    return count

class Taskinfo(CorelensModule):
    """
    Corelens Module for ps
    """

    name = "ps"

    default_args = ["-m"]

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "-m",
            dest="last_run",
            action="store_true",
            help="show last run information",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if args.last_run:
            show_tasks_last_runtime(for_each_task(prog))
        else:
            raise NotImplementedError("currently, only ps -m is implemented")
