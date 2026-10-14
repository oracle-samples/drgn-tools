# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
from typing import Iterable

from drgn import Object
from drgn import Program
from drgn.helpers.common import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.sched import cpu_curr

from drgn_tools.bt import bt
from drgn_tools.corelens import CorelensModule
from drgn_tools.task import task_cpu
from drgn_tools.task import task_lastrun2now
from drgn_tools.util import timestamp_str
from drgn_tools.workqueue import for_each_cpu_worker_pool


def _get_watchdog_thresh_seconds(prog: Program) -> int:
    """Get the wq_watchdog_threshold. Default to 30 secs."""
    try:
        return int(prog["wq_watchdog_thresh"].value_())
    except KeyError:
        return 30


def _iter_worker_pool_workers(pool: Object) -> Iterable[Object]:
    return list_for_each_entry(
        "struct worker", pool.workers.address_of_(), "node"
    )


def _current_work_func_name(worker: Object) -> str:
    prog = worker.prog_
    try:
        return prog.symbol(worker.current_func.value_()).name
    except LookupError:
        return f"UNKNOWN: 0x{worker.current_func.value_():x}"


def _task_sched_class(task: Object) -> str:
    prio = task.prio.value_()
    if prio < 100:
        return "RT"
    return "CFS"


def _print_cpu_current_task(prog: Program, cpu: int) -> None:
    curr = cpu_curr(prog, cpu)
    pid = curr.pid.value_()
    comm = escape_ascii_string(curr.comm.string_())
    prio = curr.prio.value_()
    sched_class = _task_sched_class(curr)
    print(
        f"  CURRENT_TASK_ON_CPU: PID: {pid:<6d}  TASK: {curr.value_():x}"
        f'  PRIO: {prio} ({sched_class})  COMMAND: "{comm}"'
    )


def scan_workqueue_lockup(prog: Program) -> None:
    thresh_seconds = _get_watchdog_thresh_seconds(prog)
    thresh_ns = thresh_seconds * 1_000_000_000
    print("Workqueue watchdog threshold:" f" {thresh_seconds} seconds")
    print()

    lockup_count = 0
    for cpu in for_each_online_cpu(prog):
        for pool in for_each_cpu_worker_pool(prog, cpu):
            for worker in _iter_worker_pool_workers(pool):
                if not worker.current_work:
                    continue
                task = worker.task
                runtime = task_lastrun2now(task)
                if runtime < thresh_ns:
                    continue
                lockup_count += 1
                wq_name = "unknown"
                pwq = worker.current_pwq
                if pwq:
                    try:
                        wq_name = escape_ascii_string(
                            pwq.wq.name.string_(),
                            escape_backslash=True,
                        )
                    except Exception:
                        wq_name = "unknown"
                work_addr = worker.current_work.value_()
                func_name = _current_work_func_name(worker)
                pid = task.pid.value_()
                comm = escape_ascii_string(task.comm.string_())
                prio = task.prio.value_()
                sched_class = _task_sched_class(task)
                print(
                    f"CPU {task_cpu(task)} pool {pool.id.value_()}"
                    f" workqueue: {wq_name} pwq: 0x{pwq.value_():x}"
                )
                _print_cpu_current_task(prog, cpu)
                print()
                print(
                    f"  CURRENT_WORKER_TASK:   PID: {pid:<6d}  TASK:"
                    f" {task.value_():x}  PRIO: {prio}"
                    f' ({sched_class})  COMMAND: "{comm}"'
                )
                print(f"  WORK:      0x{work_addr:x}" f"  FUNC: {func_name}")
                print("  RUNTIME:", timestamp_str(runtime))
                print("  Calltrace:")
                bt(task_or_prog=task, indent=4)
                print()

    if lockup_count == 0:
        print(
            "Workqueue lockup not detected. No workqueue workers appear to be stuck past watchdog threshold."
        )
    else:
        print(
            f"Workqueue lockup detected! Found {lockup_count} workqueue workers past watchdog threshold."
        )


class WorkQueueLockup(CorelensModule):
    """
    Detect workqueue lockup issues
    """

    name = "workqueue_lockup"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        scan_workqueue_lockup(prog)
