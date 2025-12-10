# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
import typing
from typing import Callable

import drgn
from drgn import Program
from drgn.helpers.common import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.percpu import per_cpu

from drgn_tools.bt import bt
from drgn_tools.bt import bt_has_any
from drgn_tools.corelens import CorelensModule
from drgn_tools.smp import _irq_enabled
from drgn_tools.table import print_table
from drgn_tools.task import task_lastrun2now
from drgn_tools.util import timestamp_str


def dump_tasks_waiting_on_event(
    prog: Program,
    min_run_time_seconds: int,
    tasks_waiting_func: Callable,
    wait_desc: str,
) -> None:
    """
    Prints tasks waiting on a specific event with details.

    :param prog: drgn program
    :param min_run_time_seconds: int
    :param tasks_waiting_func: function to fetch waiting tasks
    :param wait_desc: description for the wait type (for printing)
    """
    tasks_waiting = tasks_waiting_func(prog)
    output = [["TASK", "NAME", "PID", "PENDING_TIME"]]
    tasks_pids = set()
    if tasks_waiting:
        for t, _ in tasks_waiting:
            pending_time = timestamp_str(task_lastrun2now(t))
            pid = t.pid.value_()
            if pid not in tasks_pids and task_lastrun2now(t) > min_run_time_seconds * 1e9:
                output.append(
                    [
                        hex(t.value_()),
                        escape_ascii_string(t.comm.string_()),
                        pid,
                        pending_time,
                    ]
                )
                tasks_pids.add(pid)
    print()
    print(f"We found below tasks waiting for {wait_desc} over {min_run_time_seconds} seconds:")
    print_table(output)


def tasks_waiting_rcu_gp(prog: Program) -> typing.List[typing.Tuple[drgn.Object, drgn.StackFrame]]:
    """
    Detects tasks waiting RCU grace period

    :param prog: drgn program
    """
    rcu_gp_fn = ["percpu_ref_switch_to_atomic_sync", "__wait_rcu_gp"]
    return bt_has_any(prog, rcu_gp_fn)


def tasks_waiting_spinlock(prog: Program) -> typing.List[typing.Tuple[drgn.Object, drgn.StackFrame]]:
    """
    Detects tasks waiting on spinlocks

    :param prog: drgn program
    """
    spinlock_spinner_fn = [
        "__pv_queued_spin_lock_slowpath",
        "native_queued_spin_lock_slowpath",
        "queued_spin_lock_slowpath",
    ]
    return bt_has_any(prog, spinlock_spinner_fn)


def tasks_waiting_fsnotify(prog: Program) -> typing.List[typing.Tuple[drgn.Object, drgn.StackFrame]]:
    """
    Detects tasks waiting on fsnotify

    :param prog: drgn program
    """
    spinlock_spinner_fn = ["__fsnotify_update_child_dentry_flags"]
    return bt_has_any(prog, spinlock_spinner_fn)


def dump_tasks_waiting_rcu_gp(prog, min_run_time_seconds: int) -> None:
    dump_tasks_waiting_on_event(
        prog,
        min_run_time_seconds,
        tasks_waiting_rcu_gp,
        "rcu grace period",
    )


def dump_tasks_waiting_spinlock(prog, min_run_time_seconds: int) -> None:
    dump_tasks_waiting_on_event(
        prog,
        min_run_time_seconds,
        tasks_waiting_spinlock,
        "spinlock",
    )


def dump_tasks_waiting_fsnotify(prog, min_run_time_seconds: int) -> None:
    dump_tasks_waiting_on_event(
        prog,
        min_run_time_seconds,
        tasks_waiting_fsnotify,
        "fsnotify",
    )


def scan_lockup(
    prog: Program, stack: bool, min_run_time_seconds: int = 1, top_k: int = -1, skip_swapper: bool = True
) -> None:
    """
    Scan potential lockups on CPUs and tasks waiting for RCU.
    Collect all long-running tasks, rank them by run time, and print top_k.

    :param prog: drgn program
    :param stack: bool
    :param min_run_time_seconds: int
    :param top_k: int
    :param skip_swapper: bool
    """
    entries = []

    for cpu in for_each_online_cpu(prog):
        runqueue = per_cpu(prog["runqueues"], cpu)
        curr_task_addr = runqueue.curr.value_()
        curr_task = runqueue.curr[0]
        comm = escape_ascii_string(curr_task.comm.string_())
        pid = curr_task.pid.value_()
        prio = curr_task.prio.value_()
        run_time = task_lastrun2now(curr_task)  # ns
        if run_time < min_run_time_seconds * 1e9:
            continue

        if skip_swapper and comm == f"swapper/{cpu}":
            continue

        entries.append({
            "cpu": cpu,
            "runqueue": runqueue,
            "task_addr": curr_task_addr,
            "task": curr_task,
            "comm": comm,
            "pid": pid,
            "prio": prio,
            "runtime": run_time,
        })

    entries.sort(key=lambda x: x["runtime"], reverse=True)

    # detect lockup type (soft or hard)
    longest_running_task = entries[0]
    irq_enabled = _irq_enabled(prog, longest_running_task['cpu'])

    # convert ns -> s
    runtime_s = longest_running_task["runtime"] / 1e9

    SOFT_LOCKUP_THRESHOLD = 20
    HARD_LOCKUP_THRESHOLD = 10

    if irq_enabled and runtime_s > SOFT_LOCKUP_THRESHOLD:
        print(
            f"Soft lockup detected - CPU#{longest_running_task['cpu']} "
            f"stuck for {runtime_s:.0f}s! "
            f"[{longest_running_task['comm']}:{longest_running_task['pid']}]"
        )

    elif (not irq_enabled) and runtime_s > HARD_LOCKUP_THRESHOLD:
        print(
            f"Hard lockup detected - CPU#{longest_running_task['cpu']} "
            f"stuck for {runtime_s:.0f}s! "
            f"[{longest_running_task['comm']}:{longest_running_task['pid']}]"
        )

    total_entries = len(entries)

    if top_k > 0:
        entries = entries[:top_k]

    # print results
    for e in entries:
        cpu = e["cpu"]
        runqueue = e["runqueue"]
        curr_task_addr = e["task_addr"]
        curr_task = e["task"]
        comm = e["comm"]
        pid = e["pid"]
        prio = e["prio"]
        run_time = e["runtime"]

        print(f"CPU {cpu} RUNQUEUE: {runqueue.address_of_().value_():x}")
        print(
            f"  PID: {pid:<6d}  TASK: {curr_task_addr:x}  PRIO: {prio}"
            f'  COMMAND: "{comm}"'
            f"  LOCKUP TIME: {timestamp_str(run_time)}",
        )
        if stack:
            print("\nCalltrace:")
            bt(task_or_prog=curr_task.address_of_())
            print()

    print(f"We found {total_entries} processes exceeding {min_run_time_seconds} seconds.")
    if top_k > 0:
        print(f"Longest {len(entries)} processes are printed above.")

    dump_tasks_waiting_rcu_gp(prog, min_run_time_seconds)
    dump_tasks_waiting_spinlock(prog, min_run_time_seconds)
    dump_tasks_waiting_fsnotify(prog, min_run_time_seconds)


class LockUp(CorelensModule):
    """Print tasks which have been on-cpu for too long (possible RCU blockers) and tasks waiting RCU grace period if any"""

    name = "lockup"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--stack",
            action="store_true",
            help="Print the stacks."
        )
        parser.add_argument(
            "--time",
            "-t",
            type=float,
            default=2,
            help="list all the processes that have been running more than <time> seconds",
        )
        parser.add_argument(
            "--top_k",
            "-k",
            type=int,
            default=-1,
            help="list top k processes in terms of runtime",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        scan_lockup(prog, args.stack, args.time, args.top_k)
