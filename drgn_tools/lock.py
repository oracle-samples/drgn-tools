# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
``corelens lock`` should support:

1. Should find process stuck in  mutex or semaphore.
2. Find the contested mutex
3. List all waiters on that lock and the time of wait

Target Mutex API list for the lock contentation::

    void mutex_lock(struct mutex *lock);
    void mutex_lock_nested(struct mutex *lock, unsigned int subclass);
    int mutex_lock_interruptible_nested(struct mutex *lock,
                                        unsigned int subclass);
    int mutex_lock_interruptible(struct mutex *lock);
    int atomic_dec_and_mutex_lock(atomic_t *cnt, struct mutex *lock);

Try variants of mutex are ignored as they will not block.  The common function
used in all these api's is: ``__mutex_lock()`` and is sufficant to trap all
block by mutexes.

For semaphores, There is no owners, and waiters generally have the common
functions as: ``__down_common`` and ``__down`` depending upon releases. So
trapping these two function is sufficient to check the semaphore waiters.
"""
import argparse
from typing import Set

import drgn
from drgn import Program

from drgn_tools.bt import bt
from drgn_tools.bt import bt_has_any
from drgn_tools.corelens import CorelensModule
from drgn_tools.locking import for_each_mutex_waiter
from drgn_tools.locking import for_each_rwsem_waiter
from drgn_tools.locking import mutex_owner
from drgn_tools.locking import show_lock_waiter


def scan_mutex_lock(prog: Program, stack: bool) -> None:
    """Scan for mutex and show deitals"""

    frame_list = bt_has_any(prog, ["__mutex_lock"])
    if not frame_list:
        return

    seen_mutexes: Set[int] = set()

    warned_absent = False
    for task, frame in frame_list:
        try:
            mutex = frame["lock"]
            mutex_addr = mutex.value_()
        except drgn.ObjectAbsentError:
            if not warned_absent:
                print(
                    "warning: failed to get mutex from stack frame"
                    "- information is incomplete"
                )
                warned_absent = True
            continue

        struct_owner = mutex_owner(prog, mutex)

        if mutex_addr in seen_mutexes:
            continue
        seen_mutexes.add(mutex_addr)

        index = 1
        print(f"Mutex: 0x{mutex_addr:x}")
        print("Mutex OWNER:", struct_owner.comm.string_().decode("utf-8"))
        print("")
        if stack:
            bt(struct_owner.pid)
            print("")
        print(
            "Mutex WAITERS (Index, cpu, comm, pid, state, wait time (d hr:min:sec:ms)):"
        )
        for waiter in for_each_mutex_waiter(prog, mutex):
            show_lock_waiter(prog, waiter, index, stacktrace=stack)
            index = index + 1
        print("")


def show_sem_lock(prog: Program, frame_list, seen_sems, stack: bool) -> None:
    """Show semaphore details"""
    warned_absent = False
    for task, frame in frame_list:
        try:
            sem = frame["sem"]
            semaddr = sem.value_()
        except drgn.ObjectAbsentError:
            if not warned_absent:
                print(
                    "warning: failed to get semaphore from stack frame"
                    "- information is incomplete"
                )
                warned_absent = True
            continue

        if semaddr in seen_sems:
            continue
        seen_sems.add(semaddr)

        index = 1
        print(f"Semaphore: 0x{semaddr:x}")
        print(
            "Semaphore WAITERS (Index, cpu, comm, pid, state, wait time (d hr:min:sec:ms)):"
        )
        for waiter in for_each_rwsem_waiter(prog, sem):
            show_lock_waiter(prog, waiter, index, stacktrace=stack)
            index = index + 1

        print("")


def scan_sem_lock(prog: Program, stack: bool) -> None:
    """Scan for semphores"""
    seen_sems: Set[int] = set()
    functions = [
        "__down",
        "__down_common",
        "__down_interruptible",
        "__down_killable",
        "__down_timeout",
    ]
    frame_list = bt_has_any(prog, functions)
    if frame_list:
        show_sem_lock(prog, frame_list, seen_sems, stack)


def scan_lock(prog: Program, stack: bool) -> None:
    """Scan tasks for Mutex and Semaphore"""
    print("Scanning Mutexes ...")
    print("")
    scan_mutex_lock(prog, stack)

    print("Scanning Semaphores...")
    print("")
    scan_sem_lock(prog, stack)


class Locking(CorelensModule):
    """Display active mutex and semaphores and their waiters"""

    name = "lock"
    need_dwarf = True

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--stack", action="store_true", help="Print the stack."
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        scan_lock(prog, args.stack)
