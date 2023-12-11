# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper for linux kernel locking
"""
from typing import Iterable

import drgn
from drgn import Object
from drgn import Program
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.sched import task_cpu
from drgn.helpers.linux.sched import task_state_to_char

from drgn_tools.bt import bt
from drgn_tools.task import task_lastrun2now
from drgn_tools.util import timestamp_str

MUTEX_FLAGS = 0x7


def mutex_owner(prog: Program, mutex: drgn.Object) -> drgn.Object:
    owner = mutex.owner.counter.value_()
    if owner < 0:
        owner = 2**64 + owner - 1
    Owner = owner & (~MUTEX_FLAGS)
    struct_owner = Object(prog, "struct task_struct *", value=Owner)
    return struct_owner


def show_lock_waiter(
    prog: Program, task: Object, index: int, stacktrace: bool
) -> None:
    """
    Show lock waiter

    :param prog: drgn program
    :param task: ``struct task_struct *``
    :param index: index of waiter
    :param stacktrace: true to dump stack trace of the waiter
    :returns: None
    """
    prefix = "[%d] " % index
    ncpu = task_cpu(task)
    print(
        "%12s: %-4s %-4d %-16s %-8d %-6s %-16s"
        % (
            prefix,
            "cpu:",
            ncpu,
            task.comm.string_().decode(),
            task.pid.value_(),
            task_state_to_char(task),
            timestamp_str(task_lastrun2now(task)),
        )
    )
    if stacktrace:
        print("")
        bt(task)


def for_each_rwsem_waiter(prog: Program, rwsem: Object) -> Iterable[Object]:
    """
    List task waiting on the rw semaphore

    :param prog: drgn program
    :param rwsem: ``struct rw_semaphore *``
    :returns: ``struct task_struct *``
    """
    for waiter in list_for_each_entry(
        prog.type("struct rwsem_waiter"), rwsem.wait_list.address_of_(), "list"
    ):
        yield waiter.task


def for_each_mutex_waiter(prog: Program, mutex: Object) -> Iterable[Object]:
    """
    List task waiting on the mutex

    :param prog: drgn program
    :param mutex: ``struct mutex *``
    :returns: ``struct task_struct *``
    """
    for waiter in list_for_each_entry(
        prog.type("struct mutex_waiter"), mutex.wait_list.address_of_(), "list"
    ):
        yield waiter.task
