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
from drgn.helpers.linux.sched import task_state_to_char

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table
from drgn_tools.util import has_member


def nanosecs_to_secs(nanosecs: int) -> float:
    """
    Convert from nanosecs to secs

    :param nanosecs: time duration in nano secs
    :returns: time duration in secs
    """
    val = nanosecs // 1000000
    return val / 1000


def get_current_task(prog: drgn.Program, cpu: int) -> Object:
    """
    Get current task of a cpu

    :param prog: drgn program
    :param cpu: cpu index
    :returns: ``struct task_struct *`` for current task of cpu
    """
    return per_cpu(prog["runqueues"], cpu).curr


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
    current = get_current_task(prog, cpu)

    return task_lastrun2now(current)


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


class Taskinfo(CorelensModule):
    """
    Corelens Module for ps
    """

    name = "ps"

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
