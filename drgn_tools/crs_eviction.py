# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Help detect crs eviction issues
"""
import argparse
from typing import Optional

import drgn
from drgn import ObjectAbsentError
from drgn import Program
from drgn.helpers.linux.sched import cpu_curr

from drgn_tools.corelens import CorelensModule
from drgn_tools.dentry import dentry_for_each_child
from drgn_tools.dentry import dentry_is_negative
from drgn_tools.file import __path_by_inode
from drgn_tools.lockup import tasks_waiting_fsnotify
from drgn_tools.lockup import tasks_waiting_rcu_gp
from drgn_tools.lockup import tasks_waiting_spinlock
from drgn_tools.task import get_pid


def crs_eviction_waiting_for_rcu(prog: Program) -> None:
    """Different types of issues related to rcu"""
    if not tasks_waiting_rcu_gp(prog):
        return

    # spinlock contention issue
    if tasks_waiting_spinlock(prog):
        # due to fsnotify
        frame_list = tasks_waiting_fsnotify(prog)
        if frame_list:
            for task, frame in frame_list:
                if frame.name == "__fsnotify_update_child_dentry_flags":
                    if "alias" in frame.locals():
                        dentry = frame["alias"]
                        try:
                            path_name = __path_by_inode(dentry.d_inode)
                            total_count = 0
                            negative_count = 0
                            for child in dentry_for_each_child(dentry):
                                total_count += 1
                                if dentry_is_negative(child):
                                    negative_count += 1
                        except ObjectAbsentError:
                            continue

                        print(
                            "CRS eviction caused by spinlock contention due to fsnotify detected."
                        )
                        print(f"PID: {get_pid(task)}")
                        print(f"Directory being iterated: {path_name}")
                        print(f"Total dentries: {total_count}")
                        print(f"Negative dentries: {negative_count}")
                        if total_count:
                            print(
                                f"% Negative dentries: {negative_count / total_count:.2%}"
                            )


def panic_triggered_by_crs_eviction(prog: Program) -> Optional[drgn.Thread]:
    # dectect panic triggered by crs eviction
    try:
        panic_thread = prog.crashed_thread()
    except Exception:
        pid = cpu_curr(prog, prog["crashing_cpu"]).pid.value_()
        panic_thread = prog.thread(pid)
    if panic_thread and panic_thread.name in {"cssdmonitor", "ocssd.bin"}:
        return panic_thread
    return None


def scan_crs_eviction(prog: Program) -> None:
    if panic_triggered_by_crs_eviction(prog):
        # run a list of detectors
        crs_eviction_waiting_for_rcu(prog)


class CrsEviction(CorelensModule):
    """Detectors for crs eviction related issues"""

    name = "crs_eviction"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        scan_crs_eviction(prog)
