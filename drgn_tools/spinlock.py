# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
import os
import re
import shutil
import subprocess
from collections import defaultdict
from typing import DefaultDict
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.sched import cpu_curr

from drgn_tools.bt import frame_name
from drgn_tools.corelens import CorelensModule
from drgn_tools.table import FixedTable
from drgn_tools.task import get_command
from drgn_tools.task import get_current_run_time
from drgn_tools.util import timestamp_str

# must have cscope installed
# must have uek source code repo set here
UEK_CODE_DIR = ""

"""
Find this C symbol:
Find this function definition:
Find functions called by this function:
Find functions calling this function:
Find this text string:
Change this text string:
Find this egrep pattern:
Find this file:
Find files #including this file:
"""


def query_cscope(
    nums: List, pattern: str, keyword: str = "", target_dir: str = UEK_CODE_DIR
) -> str:
    """Run cscope query with grep filter and return the output as a string."""
    results = ""
    for num in nums:
        try:
            result = subprocess.check_output(
                f"cscope -d -L -{num}{pattern} | grep -E '{keyword}'",
                universal_newlines=True,
                shell=True,
                cwd=target_dir,
            )
            results += result

        except subprocess.CalledProcessError:
            continue

    return results


def query_sed(
    file_path: str, line_num: str, target_dir: str = UEK_CODE_DIR
) -> str:
    """Run sed to get the function in a specifc line in a file"""
    try:
        output = subprocess.check_output(
            f"sed -n '{line_num}p' {file_path}",
            universal_newlines=True,
            shell=True,
            cwd=target_dir,
        )
        return output.strip()
    except subprocess.CalledProcessError:
        return ""


_QSPINLOCK_UNLOCKED_VAL = 0


def qspinlock_is_locked(qsp: Object) -> str:
    """
    Check if a qspinlock is locked or not

    :param qsp: ``struct qspinlock *``
    :returns: True if qspinlock is locked, False otherwise.
    """
    return str(qsp.locked.value_() != _QSPINLOCK_UNLOCKED_VAL)


def get_qspinlock_tail_cpu(qsp: Object) -> int:
    """
    Get tail cpu that spins on the  qspinlock

    :param qsp: ``struct qspinlock *``
    :returns: tail cpu that spins on the qspinlock, -1 if None
    """
    tail = qsp.tail.value_()
    tail_cpu = (tail >> 2) - 1
    return tail_cpu


def get_tail_cpu_qnode(qsp: Object) -> Iterable[Object]:
    """
    Only for UEK6 and above.
    Given a qspinlock, find qnodes associated with the tail cpu spining on the qspinlock.

    :param qsp: ``struct qspinlock *``
    :returns: Iterator of qnode
    """
    tail_cpu = get_qspinlock_tail_cpu(qsp)
    prog = qsp.prog_
    if tail_cpu < 0:
        return []
    tail_qnodes = per_cpu(prog["qnodes"], tail_cpu)
    for qnode in tail_qnodes:
        yield qnode


def dump_qnode_address_for_each_cpu(prog: Program, cpu: int = -1) -> None:
    """
    Only for UEK6 and above.
    Dump all qnode addresses per cpu. If cpu is specified, dump qnode address on that cpu only.

    :param prog: drgn program
    :param cpu: cpu id
    """
    print(
        "%-20s %-20s"
        % (
            "cpu",
            "qnode",
        )
    )
    online_cpus = list(for_each_online_cpu(prog))
    if cpu > -1:
        if cpu in online_cpus:
            qnode_addr = per_cpu(prog["qnodes"], cpu).address_of_().value_()
            print("%-20s %-20lx" % (cpu, qnode_addr))
    else:
        for cpu_id in online_cpus:
            qnode_addr = per_cpu(prog["qnodes"], cpu_id).address_of_().value_()
            print("%-20s %-20lx" % (cpu_id, qnode_addr))


def scan_bt_for_spinners(prog: Program) -> Tuple[Dict, Dict, Set]:
    """
    Scan spinlocks spinners on bt and dump their info.

    :param prog: drgn program
    :param show_unlocked_only: bool
    """
    wait_on_spin_lock_key_words = {
        "__pv_queued_spin_lock_slowpath",
        "native_queued_spin_lock_slowpath",
        "queued_spin_lock_slowpath",
    }

    spinners = {}
    sp_ids = defaultdict(list)
    sp_sources = set()
    for cpu in for_each_online_cpu(prog):
        task = cpu_curr(prog, cpu)
        try:
            trace = prog.stack_trace(task)
        except ValueError:
            continue  # cannot unwind stack of running task
        frames = []
        # store the index where the keyword appears
        spin_lock_key_word_idx = -1

        for idx, frame in enumerate(trace):
            f_name = frame_name(prog, frame).split(" ")[0]
            try:
                source = frame.source()
            except LookupError:  # source code location not available
                source = (str(frame), f_name)
            frames.append((f_name, source))
            if f_name in wait_on_spin_lock_key_words:
                spin_lock_key_word_idx = idx
                run_time = timestamp_str(get_current_run_time(prog, cpu))
                pid = task.pid.value_()
                cmd = get_command(task)
                task_addr = task.value_()
                if "lock" in frame.locals():
                    sp = frame["lock"]
                    if not sp.absent_:
                        try:
                            sp.val.read_()
                            sp_addr = sp.value_()
                            is_locked = qspinlock_is_locked(sp)
                        except FaultError:
                            sp_addr = "Unknown"
                            is_locked = "Unknown"
                            pass

                spinners[cpu] = [
                    sp_addr,
                    is_locked,
                    task_addr,
                    pid,
                    run_time,
                    cmd,
                ]

        # the caller function should be the first function before the frame containing keyword
        # that does not contain _spin_lock substring (might exist corner cases where the caller indeed contains such substring?)
        if spin_lock_key_word_idx > -1:
            for f_name, source in frames[spin_lock_key_word_idx + 1 :]:
                if "_spin_lock" not in f_name:
                    sp_id, _ = get_spinlock_id(f_name, source) or (None, None)
                    if sp_id:
                        sp_ids[sp_id].append(cpu)
                        sp_sources.add(source)
                    break
    return spinners, sp_ids, sp_sources


def get_spinlock_line(
    funcname: str, source: Optional[Tuple], check_lock: bool
) -> str:
    """
    Try to look for a spinlock keyword in a function definition. Look for unlock keyword if check_lock is False

    :param funcname: str
    :param source: str
    :param check_lock: bool
    """
    lock_keyword = r"spin_lock\(|spin_lock_irq|spin_lock_irqsave|spin_lock_bh"
    unlock_keyword = (
        r"spin_unlock\(|spin_unlock_irq|spin_unlock_irqsave|spin_unlock_bh"
    )

    spinlock_line = ""
    if source and len(source) == 3:
        file_path, line_num = source[0], source[1]
        if file_path and line_num:
            spinlock_line = query_sed(file_path, line_num)
            spinlock_line = str(line_num) + " " + spinlock_line
    if not spinlock_line:
        skip_list = ["raw_spin_rq_lock_nested"]
        if funcname in skip_list:
            return ""

        output = query_cscope(
            [2],
            funcname,
            keyword=lock_keyword if check_lock else unlock_keyword,
        )
        # line of code that invokes spin_lock(), spin_lock_irqsave(),..
        if output:
            match = re.search(r"\s{1}(\d+)\s{1}(.*)", output)
            if match:
                spinlock_line = match.group(2)
                spinlock_line = str(output.split(" ")[2]) + " " + spinlock_line

    return spinlock_line


def get_spinlock_id(
    funcname: str, source: Optional[Tuple] = None, check_lock: bool = True
) -> Optional[Tuple]:
    """
    Get the struct type that contains this spinlock, its spinlock field name and line number.
    spinlock_id is a tuple of (struct type, field name)

    :param funcname: str
    :param source: Tuple
    :param check_lock bool: get unlock keywords if False
    """
    # get the spinlock name first
    spinlock_line = get_spinlock_line(funcname, source, check_lock)
    if not spinlock_line:
        return None
    spinlock_name = ""
    match = re.search(r"\((.*?)\)", spinlock_line)
    if match:
        spinlock_name = match.group(1).split(",")[0].lstrip("&")

    # get the container instance first
    spinlock_container_instance = None
    spinlock_field = ""
    if "->" in spinlock_name:
        spinlock_container_instance, spinlock_field = (
            spinlock_name.split("->")[0],
            spinlock_name.split("->")[1],
        )
    elif "." in spinlock_name:
        spinlock_container_instance, spinlock_field = (
            spinlock_name.split(".")[0],
            spinlock_name.split(".")[1],
        )
    else:
        return None

    # then get the struct type of the instance
    # there could be multiple matches, and we are looking for "struct A a" pattern to get A
    outputs = query_cscope([0, 1], spinlock_container_instance).split("\n")
    for output in outputs:
        output = output.strip("{;").strip()
        match = re.search(r"\s{1}(\d+)\s{1}(.*)", output)
        if match:
            match = re.search(r"struct\s{1}(.*)", match.group(2))
            if match:
                candidate = match.group(1).split(" ")
                if len(candidate) > 1:
                    return (candidate[0], spinlock_field), int(
                        spinlock_line.split(" ")[0]
                    )
    return None


def scan_bt_for_owners(prog: Program) -> None:
    """
    Scan spinlocks owners on bt and dump their info.

    :param prog: drgn program
    """
    spinners, sp_ids, sp_sources = scan_bt_for_spinners(prog)
    # number of spinlocks
    nr_locks = len(set([v[0] for v in spinners.values()]))
    print(f"There are {nr_locks} spinlock(s) detected.")
    nr_lock_owners_found = 0
    lock_info: DefaultDict[Tuple, int] = defaultdict(int)
    for cpu in for_each_online_cpu(prog):
        task = cpu_curr(prog, cpu)
        try:
            trace = prog.stack_trace(task)
        except ValueError:
            continue  # cannot unwind stack of running task

        for frame in reversed(trace):
            f_name = frame_name(prog, frame).split(" ")[0]
            try:
                sp_source = frame.source()
            except LookupError:  # source code location not available
                sp_source = (str(frame), f_name)
            if sp_source in sp_sources:
                continue  # this is a spinner

            # maybe the case where sp_source is missing needs to be better handled here
            sp_id, sp_line_num = get_spinlock_id(f_name, check_lock=False) or (
                None,
                None,
            )
            if (
                sp_id
                and isinstance(sp_source[1], int)
                and sp_line_num <= sp_source[1]
            ):
                lock_info[(sp_id, frame, f_name, cpu)] = max(
                    lock_info[(sp_id, frame, f_name, cpu)] - 1, 0
                )
            sp_id, sp_line_num = get_spinlock_id(f_name) or (None, None)
            if sp_id and (
                not isinstance(sp_source[1], int)
                or sp_line_num <= sp_source[1]
            ):
                lock_info[(sp_id, frame, f_name, cpu)] += 1

    for (sp_id, frame, f_name, cpu), count in lock_info.items():
        if sp_id in sp_ids and count > 0:  # unreleased spinlocks
            nr_lock_owners_found += 1
            print(f"{nr_lock_owners_found}/{nr_locks} of lock owner(s) found!")
            print(f"{frame}({f_name}) is a spinlock owner: ")

            tbl = FixedTable(
                [
                    "CPU:>",
                    "TASK:>x",
                    "PID:>",
                    "CURRENT HOLDTIME:>",
                    "COMMAND:>",
                ]
            )

            hold_time = timestamp_str(get_current_run_time(prog, cpu))
            task = cpu_curr(prog, cpu)
            pid = task.pid.value_()
            cmd = get_command(task)
            task_addr = task.value_()
            tbl.row(cpu, task_addr, pid, hold_time, cmd)
            tbl.write()

            print("It has below spinners: ")
            spinner_cpus = sp_ids[sp_id]
            tbl = FixedTable(
                [
                    "CPU:>",
                    "SPINLOCK:>x",
                    "TASK:>x",
                    "PID:>",
                    "CURRENT SPINTIME:>",
                    "COMMAND:>",
                ]
            )
            for sp_cpu in spinner_cpus:
                tbl.row(
                    sp_cpu,
                    spinners[sp_cpu][0],
                    spinners[sp_cpu][2],
                    spinners[sp_cpu][3],
                    spinners[sp_cpu][4],
                    spinners[sp_cpu][5],
                )
            tbl.write()


class Spinlock(CorelensModule):
    """
    Print out spinlock owners and spinners.
    """

    name = "spinlock"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if not UEK_CODE_DIR or not os.path.isdir(UEK_CODE_DIR):
            print(
                "UEK source code not found. Please set UEK_CODE_DIR correctly."
            )
            return
        if not shutil.which("cscope"):
            print("cscope not installed or not in PATH.")
            return

        scan_bt_for_owners(prog)
