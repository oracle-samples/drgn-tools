# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
“corelens lock ”  should support :
1.      Should find process stuck in  mutex or semaphore.
2.      Find the contested mutex
3.      List all waiters on that lock and the time of wait

Target Mutex API list for the lock contentation:
void mutex_lock(struct mutex *lock);
void mutex_lock_nested(struct mutex *lock, unsigned int subclass);
int mutex_lock_interruptible_nested(struct mutex *lock,
                                    unsigned int subclass);
int mutex_lock_interruptible(struct mutex *lock);
int atomic_dec_and_mutex_lock(atomic_t *cnt, struct mutex *lock);

TRY variats of mutex are ignored as they will not block.
The common function used in all these api's is:
__mutex_lock() and is sufficant to trap all block by mutexes.

For semaphores,
There is no woners, and waiters generally have the common functions
as : "__down_common" and "__down" depending upon releases. So trapping
these two function is sufficent to check the semaphore waiters.
"""
import argparse
from typing import List

import drgn
from drgn import Program

from drgn_tools.bt import bt
from drgn_tools.bt import bt_has
from drgn_tools.corelens import CorelensModule
from drgn_tools.locking import for_each_mutex_waiter
from drgn_tools.locking import for_each_rwsem_waiter
from drgn_tools.locking import mtx_owner
from drgn_tools.locking import show_lock_waiter


def scan_mutex_lock(prog: Program, stk: bool) -> None:
    """Scan for mutex and show deitals"""

    frame_list = bt_has(prog, "__mutex_lock")
    lock_detected = bool(frame_list)

    arr_lock: List = []

    if not lock_detected:
        return

    for task, frame in frame_list:
        # Debug...
        # pid = task.pid.value_()
        # comm = task.comm.string_().decode("utf-8")
        # print("%-15s %-15s" %(pid,comm))

        mtx = frame["lock"]
        struct_owner = mtx_owner(prog, mtx)

        duplock = 1
        if not arr_lock:
            arr_lock.append(mtx)
        else:
            for locks in arr_lock:
                if locks == mtx:
                    duplock = 0

        if duplock == 1:
            arr_lock.append(mtx)
            index = 1
            print("Mutex:", hex(mtx.owner.counter.address_of_().value_()))
            print("Mutex OWNER:", struct_owner.comm.string_().decode("utf-8"))
            print("")
            if stk:
                bt(struct_owner.pid)
                print("")
            print(
                "Mutex WAITERS (Index, cpu, comm, pid, state, wait time (d hr:min:sec:ms)):"
            )
            for waiter in for_each_mutex_waiter(prog, mtx):
                show_lock_waiter(prog, waiter, index, stacktrace=stk)
                index = index + 1
            print("")


sem_lock: List = []


def show_sem_lock(prog: Program, frame_list, stk: bool) -> None:
    """Show semaphore details"""
    for task, frame in frame_list:
        try:
            sem = frame["sem"]
            semaddr = sem.value_()
        except drgn.ObjectAbsentError:
            continue

        duplock = 1

        if not sem_lock:
            sem_lock.append(semaddr)
        else:
            for locks in sem_lock:
                if locks == semaddr:
                    duplock = 0

        if duplock == 1:
            sem_lock.append(semaddr)
            index = 1
            print("Semaphore:", hex(semaddr))
            print(
                "Semaphore WAITERS (Index, cpu, comm, pid, state, wait time (d hr:min:sec:ms)):"
            )
            for waiter in for_each_rwsem_waiter(prog, sem):
                show_lock_waiter(prog, waiter, index, stacktrace=stk)
                index = index + 1

            print("")


def scan_sem_lock(prog: Program, stk: bool) -> None:
    """Scan for semphores"""
    frame_list = bt_has(prog, "__down")
    lock_detected = bool(frame_list)
    if lock_detected:
        show_sem_lock(prog, frame_list, stk)

    frame_list = bt_has(prog, "__down_common")
    lock_detected = bool(frame_list)
    if lock_detected:
        show_sem_lock(prog, frame_list, stk)


def scan_task(prog: Program, stk: bool) -> None:
    """Scan tasks for Mutex and Semaphore"""
    print("Scanning Mutexes ...")
    print("")
    scan_mutex_lock(prog, stk)

    print("Scanning Semaphores...")
    print("")
    scan_sem_lock(prog, stk)


class Locking(CorelensModule):
    """Display active mutex and semaphoes and their waiters"""

    name = "lock"
    need_dwarf = True

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--stack", action="store_true", help="Print the stack."
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        scan_task(prog, args.stack)
