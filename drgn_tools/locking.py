# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper for linux kernel locking
"""
from typing import Iterable

import drgn
from drgn import cast
from drgn import NULL
from drgn import Object
from drgn import Program
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.sched import task_cpu
from drgn.helpers.linux.sched import task_state_to_char

from drgn_tools.bt import bt
from drgn_tools.task import task_lastrun2now
from drgn_tools.util import per_cpu_owner
from drgn_tools.util import timestamp_str

######################################
# osq lock
######################################
_OSQ_UNLOCKED_VAL = 0


def osq_is_locked(osq: Object) -> bool:
    """
    Check if an osq is locked or not

    :param osq: ``struct optimistic_spin_queue *``
    :returns: True if osq is locked, False otherwise.
    """

    return osq.tail.counter.value_() != _OSQ_UNLOCKED_VAL


def get_osq_owner_cpu(osq: Object) -> int:
    """
    Get owner cpu of an osq.

    :param osq: ``struct optimistic_spin_queue *``
    :returns: cpu that owns this osq, -1 otherwise
    """

    if not osq_is_locked(osq):
        return -1

    prog = osq.prog_
    tail = osq.tail.counter.value_()
    osq_node = per_cpu(prog["osq_node"], tail - 1)
    if not osq_node.prev.value_():
        return tail - 1

    while osq_node.prev and osq_node.prev.next == osq_node.address_of_():
        osq_node = Object(
            prog, "struct optimistic_spin_node", address=osq_node.prev.value_()
        )

    return per_cpu_owner("osq_node", osq_node)


def tail_osq_node_to_spinners(osq_node: Object) -> Iterable[int]:
    """
    Given an osq_node, find owner and all spinners of same osq

    MCS/OSQ locks are unique in the sense that for these locks both
    the owners and waiters spin, albeit on different things.
    The owner spins, usually to optimistically grab a sleeping lock but
    the waiters spin on some per-cpu entity.

    :param osq_node: ``struct optimistic_spin_node *``
    :returns: Iterator of spinning CPUs
    """

    prog = osq_node.prog_
    tail_osq_node = osq_node
    while (
        tail_osq_node.prev
        and tail_osq_node.prev.next == tail_osq_node.address_of_()
    ):
        yield per_cpu_owner("osq_node", tail_osq_node)
        tail_osq_node = Object(
            prog,
            "struct optimistic_spin_node",
            address=tail_osq_node.prev.value_(),
        )

    yield per_cpu_owner("osq_node", tail_osq_node)


def for_osq_owner_and_each_spinner(osq: Object) -> Iterable[int]:
    """
    Given an osq, find its owner and all spinners

    MCS/OSQ locks are unique in the sense that for these locks both
    the owners and waiters spin, albeit on different things.
    The owner spins, usually to optimistically grab a sleeping lock but
    the waiters spin on some per-cpu entity.

    :param osq: ``struct optimistic_spin_queue *``
    :returns: Iterator of spinning CPUs
    """
    if not osq_is_locked(osq):
        return -1

    prog = osq.prog_
    tail = osq.tail.counter.value_()
    tail_cpu = tail - 1
    tail_osq_node = per_cpu(prog["osq_node"], tail_cpu)

    if not tail_osq_node.prev.value_():
        return -1

    for cpu in tail_osq_node_to_spinners(tail_osq_node):
        yield cpu


MUTEX_FLAGS = 0x7


def mutex_owner(prog: Program, mutex: drgn.Object) -> drgn.Object:
    """
    Get mutex owner

    :param prog: drgn program
    :param mutex: ``struct mutex *``
    :param : ``struct task_struct *``
    :returns: ``struct task_struct *`` corresponding to owner,
              or NULL if there is no owner
    """

    try:
        owner = mutex.owner
        if owner.type_.type_name() == "struct task_struct *":
            return owner
        elif owner.value_():
            # Since Linux kernel commit 3ca0ff571b09 ("locking/mutex: Rework mutex::owner")
            # (in v4.10) count has been replaced with atomic_long_t owner that contains the
            # owner information (earlier available under task_struct *owner) and uses lower
            # bits for mutex state
            owner = cast("unsigned long", owner.counter.read_()) & ~MUTEX_FLAGS
            return Object(
                prog, "struct task_struct", address=owner
            ).address_of_()
        else:
            return NULL(prog, "struct task_struct *")
    except AttributeError:
        print("Mutex does not have owner information")
        return NULL(prog, "struct task_struct *")


def mutex_is_locked(lock: Object) -> bool:
    """
    Check if a mutex is locked or not

    :param lock: ``struct mutex *``
    :returns: True if mutex is locked, False otherwise.
    """

    try:
        count = lock.count
        if count.counter.value_() != 1:
            return True
        else:
            return False
    except AttributeError:
        ret = True if mutex_owner(lock.prog_, lock) else False
        return ret


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
