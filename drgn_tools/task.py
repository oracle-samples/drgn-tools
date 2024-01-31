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
from typing import Dict
from typing import Iterable
from typing import NamedTuple
from typing import Optional

import drgn
from drgn import Object
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.sched import cpu_curr
from drgn.helpers.linux.sched import task_state_to_char

from drgn_tools.corelens import CorelensModule
from drgn_tools.mm import totalram_pages
from drgn_tools.table import print_table
from drgn_tools.util import has_member

ByteToKB = 1024


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


def get_ppid(task: Object) -> int:
    """
    :returns: Parent PID of the task
    """
    return task.parent.pid.value_()


class TaskRss(NamedTuple):
    """
    Represent's a task's resident set size in pages. See task_rss().
    """

    rss_file: int
    rss_anon: int
    rss_shmem: int

    @property
    def total(self) -> int:
        return self.rss_file + self.rss_anon + self.rss_shmem


def get_task_rss(task: Object, cache: Optional[Dict[int, TaskRss]]) -> TaskRss:
    """
    Return the task's resident set size (RSS) in pages

    The task's RSS is the number of pages which are currently resident in
    memory. The RSS values can be broken down into anonymous pages (not bound to
    any file), file pages (those associated with memory mapped files), and
    shared memory pages (those which aren't associated with on-disk files, but
    belonging to shared memory mappings). This function returns a tuple
    containing each category, but the common behavior is to use the "total"
    value which sums them up.

    :param task: ``struct task_struct *`` for which to compute RSS
    :param cache: if provided, we can use this to cache the mapping of
      "mm_struct" to RSS. This helps avoid re-computing the RSS value for
      processes with many threads, but note that it could result in out of date
      values on a live system.
    :returns: the file, anon, and shmem page values
    """
    mmptr = task.mm.value_()
    if mmptr and cache and mmptr in cache:
        return cache[mmptr]

    # Kthreads have a NULL mm, simply skip them, returning 0.
    if not task.mm:
        return TaskRss(0, 0, 0)

    prog = task.prog_

    MM_FILEPAGES = prog.constant("MM_FILEPAGES").value_()
    MM_ANONPAGES = prog.constant("MM_ANONPAGES").value_()
    try:
        MM_SHMEMPAGES = prog.constant("MM_SHMEMPAGES").value_()
    except LookupError:
        MM_SHMEMPAGES = -1

    # Start with the counters from the mm_struct
    filerss = anonrss = shmemrss = 0

    filerss += task.mm.rss_stat.count[MM_FILEPAGES].counter.value_()
    anonrss += task.mm.rss_stat.count[MM_ANONPAGES].counter.value_()
    if MM_SHMEMPAGES >= 0:
        shmemrss += task.mm.rss_stat.count[MM_SHMEMPAGES].counter.value_()

    ltask = task.group_leader

    filerss += ltask.rss_stat.count[MM_FILEPAGES].value_()
    anonrss += ltask.rss_stat.count[MM_ANONPAGES].value_()
    if MM_SHMEMPAGES >= 0:
        shmemrss += ltask.rss_stat.count[MM_SHMEMPAGES].value_()

    # Finally, augment the values with the ones from the rest of the thread
    # group.

    for gtask in list_for_each_entry(
        "struct task_struct",
        task.group_leader.thread_group.address_of_(),
        "thread_group",
    ):
        filerss += gtask.rss_stat.count[MM_FILEPAGES].value_()
        anonrss += gtask.rss_stat.count[MM_ANONPAGES].value_()
        if MM_SHMEMPAGES >= 0:
            shmemrss += gtask.rss_stat.count[MM_SHMEMPAGES].value_()
    rss = TaskRss(filerss, anonrss, shmemrss)
    if cache is not None:
        cache[mmptr] = rss

    return rss


def get_vmem(task: Object) -> float:
    """
    Return virtual memory size of the task
    """
    prog = task.prog_
    page_size = prog["PAGE_SIZE"].value_()
    try:
        vmem = (task.mm.total_vm.value_() * page_size) // ByteToKB
    except drgn.FaultError:
        vmem = 0
    return vmem


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


def show_taskinfo(prog: Program, tasks: Iterable[Object]) -> None:
    """
    Display task information.
    """
    rows = [["PID", "PPID", "CPU", "TASK", "ST", "%MEM", "VSZ", "RSS", "COMM"]]
    tasks = list(tasks)
    tasks.sort(key=get_pid)
    page_size = int(prog["PAGE_SIZE"])
    total_mem = int(totalram_pages(prog))
    rss_cache: Dict = {}
    for t in tasks:
        task_rss = get_task_rss(t, rss_cache)
        rss_kb = task_rss.total * page_size // ByteToKB
        pct_mem = task_rss.total * 100 / total_mem
        rows.append(
            [
                str(get_pid(t)),
                str(get_ppid(t)),
                str(task_cpu(t)),
                hex(t.value_()),
                task_state_to_char(t),
                str("%.1f" % pct_mem),
                str(get_vmem(t)),
                str(rss_kb),
                get_command(t),
            ]
        )
    print_table(rows)


class Taskinfo(CorelensModule):
    """
    Corelens Module for ps
    """

    name = "ps"

    default_args = [["-m"]]

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "-m",
            dest="last_run",
            action="store_true",
            help="show last run information",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        tasks = for_each_task(prog)
        if args.last_run:
            show_tasks_last_runtime(tasks)
        else:
            show_taskinfo(prog, tasks)
