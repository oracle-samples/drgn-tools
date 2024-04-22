# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper for linux kernel locking
"""
import enum
from typing import Iterable
from typing import Tuple

import drgn
from drgn import cast
from drgn import FaultError
from drgn import IntegerLike
from drgn import NULL
from drgn import Object
from drgn import Program
from drgn import sizeof
from drgn.helpers.linux.list import list_empty
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.sched import cpu_curr
from drgn.helpers.linux.sched import task_cpu
from drgn.helpers.linux.sched import task_state_to_char

from drgn_tools.bt import bt
from drgn_tools.table import FixedTable
from drgn_tools.task import get_current_run_time
from drgn_tools.task import task_lastrun2now
from drgn_tools.util import kernel_version
from drgn_tools.util import per_cpu_owner
from drgn_tools.util import timestamp_str

rw_semaphore_frame_names = [
    "rwsem_down_read_slowpath",
    "rwsem_down_write_slowpath",
    "__rwsem_down_read_failed_common",
    "__rwsem_down_write_failed_common",
]


def get_lock_from_stack_frame(
    prog: Program, pid: IntegerLike, frame: Object, lock_type: str
) -> Object:
    """
    Get lock address from a given stack frame.

    This has been tested only for UEKs 5,6,7 and 8 and for mutexes,
    semaphores and rw_semaphore.

    For cases, where frame["lock"] can't provide the lock address and gives
    ObjectAbsent exception, this can be used as fallback method to obtain
    lock addresses.
    There can still be cases where for other kernels or other configurations
    or for same kernel/configuration compiled with a different gcc versions,
    the lock address may not be available at offsets used here, but the idea
    here is that since we are mostly debugging released kernels built using
    Jenkins pipelines, we should not see gcc or kernel configuration variation
    and this helper will avoid need to manually check stack frames to locate
    the locks when frame["lock"] method does not work.

    :param pid: PID of task
    :param frame: StackFrame that should be checked for lock
    :param lock_type: type of lock i.e mutex, semaphore or rw_semaphore
    :returns: True if task is blocked on given lock, False otherwise.
    """

    kmaj, kmin, _ = kernel_version(prog)
    if lock_type == "rw_semaphore":
        if frame.name in rw_semaphore_frame_names:
            lock_addr = prog.read_word(
                frame.register("rbp") - 5 * sizeof(prog.type("void *"))
            )
            lock = Object(prog, "struct " + lock_type, address=lock_addr)
            if is_task_blocked_on_lock(pid, lock_type, lock.address_of_()):
                return lock.address_of_()
        elif frame.name == "__schedule":
            for offset in 5, 6, 7:
                lock_addr = prog.read_word(
                    frame.sp + offset * sizeof(prog.type("void *"))
                )
                lock = Object(prog, "struct " + lock_type, address=lock_addr)
                if is_task_blocked_on_lock(pid, lock_type, lock.address_of_()):
                    return lock.address_of_()
    elif lock_type == "semaphore":
        if frame.name == "__down_common":
            if kmaj == 6 and kmin == 6:
                offsets = [
                    0,
                ]
            elif kmaj == 5 and kmin == 15:
                offsets = [13, 14]
            else:
                offsets = [8, 9]
            for offset in offsets:
                lock_addr = prog.read_word(
                    frame.sp + offset * sizeof(prog.type("void *"))
                )
                lock = Object(prog, "struct " + lock_type, address=lock_addr)
                if is_task_blocked_on_lock(pid, lock_type, lock.address_of_()):
                    return lock.address_of_()
    elif lock_type == "mutex":
        if frame.name == "__mutex_lock":
            offsets = [12, 17]
        elif frame.name == "__schedule":
            offsets = [7, 8]
        for offset in offsets:
            lock_addr = prog.read_word(
                frame.sp + offset * sizeof(prog.type("void *"))
            )
            lock = Object(prog, "struct " + lock_type, address=lock_addr)
            if is_task_blocked_on_lock(pid, lock_type, lock.address_of_()):
                return lock.address_of_()

    return NULL(prog, "struct " + lock_type + " *")


def is_task_blocked_on_lock(
    pid: IntegerLike, lock_type: str, lock: Object
) -> bool:
    """
    Check if a task is blocked on a given lock or not

    :param pid: PID of task
    :param lock_type: type of lock i.e mutex, semaphore or rw_semaphore
    :param lock: ``struct mutex *`` or ``struct semaphore *`` or ``struct rw_semaphore *``
    :returns: True if task is blocked on given lock, False otherwise.
    """

    try:
        if lock_type == "semaphore" or lock_type == "rw_semaphore":
            return pid in [
                waiter.pid.value_()
                for waiter in for_each_rwsem_waiter(lock.prog_, lock)
            ]
        elif lock_type == "mutex":
            return pid in [
                waiter.pid.value_()
                for waiter in for_each_mutex_waiter(lock.prog_, lock)
            ]
        else:
            return False
    except FaultError:
        # print("Could not retrieve list of waiters.")
        return False


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
        osq_node = osq_node.prev[0]

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

    tail_osq_node = osq_node
    while (
        tail_osq_node.prev
        and tail_osq_node.prev.next == tail_osq_node.address_of_()
    ):
        yield per_cpu_owner("osq_node", tail_osq_node)
        tail_osq_node = tail_osq_node.prev[0]

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
        return []

    prog = osq.prog_
    tail = osq.tail.counter.value_()
    tail_cpu = tail - 1
    tail_osq_node = per_cpu(prog["osq_node"], tail_cpu)

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


######################################
# rwsem
######################################

# Masks for rwsem.count
_RWSEM_WRITER_LOCKED = 1 << 0
_RWSEM_FLAG_WAITERS = 1 << 1
_RWSEM_FLAG_HANDOFF = 1 << 2
# Bits 8-62(i.e. 55 bits of counter indicate number of current readers that hold the lock)
_RWSEM_READER_MASK = 0x7FFFFFFFFFFFFF00  # Bits 8-62 - 55-bit reader count
_RWSEM_WRITER_MASK = 1 << 0
_RWSEM_READER_SHIFT = 8

# Masks for rwsem.owner
_RWSEM_READER_OWNED = 1 << 0
_RWSEM_ANONYMOUSLY_OWNED = 1 << 0  # For old kernels
_RWSEM_RD_NONSPINNABLE = 1 << 1
_RWSEM_WR_NONSPINNABLE = 1 << 2

# Linux kernel commit 617f3ef95177840c77f59c2aec1029d27d5547d6 ("locking/rwsem:
# Remove reader optimistic spinning") (in v5.11) removed optimistic spinning for
# readers and hence left one bit to check for spinnable
_RWSEM_NONSPINNABLE = 1 << 1


class RwsemStateCode(enum.Enum):
    UNLOCKED = "unlocked"
    READER_OWNED = "reader owned"
    WRITER_OWNED = "writer owned"
    ANONYMOUSLY_OWNED = "anonymously owned (owned by reader(s) or writer owner has not yet set the owner field)"
    # Even though we don't have (reliable) owner info for reader owned or anonymously
    # owned rwsems, but in these cases at least rwsems's count and/or owner bits
    # correspond to a known state set by kernel.
    # Below is for (very unlikely) corner cases, where rwsem's count and/or owner bits
    # could not match any of the above 4 states.
    OWNER_TYPE_UNKNOWN = "owned by owner of unknown type"


def rwsem_has_spinner(rwsem: Object) -> bool:
    """
    Check if rwsem has optimistic spinners or not

    :param rwsem: ``struct rw_semaphore *``
    :returns: True if rwsem has optimistic spinners, False otherwise.
    """
    return osq_is_locked(rwsem.osq.address_of_())


def for_each_rwsem_waiter_entity(rwsem: Object) -> Iterable[Object]:
    """
    Find rwsem_waiter(s) for given rwsem

    :param rwsem: ``struct rw_semaphore *``
    :returns: Iterator of ``struct rwsem_waiter``
    """

    for waiter in list_for_each_entry(
        "struct rwsem_waiter", rwsem.wait_list.address_of_(), "list"
    ):
        yield waiter


def get_rwsem_owner(rwsem: Object) -> Tuple[Object, "RwsemStateCode"]:
    """
    Find owner of  given rwsem

    :param rwsem: ``struct rw_semaphore *``
    :returns: type of owner and ``struct task_struct *`` if owner can be found, NULL otherwise
    """
    prog = rwsem.prog_
    if not rwsem.count.counter.value_():
        return NULL(prog, "struct task_struct *"), RwsemStateCode.UNLOCKED

    if is_rwsem_writer_owned(rwsem):
        if rwsem.owner.type_.type_name() != "atomic_long_t":
            if rwsem.owner.value_() & _RWSEM_ANONYMOUSLY_OWNED:
                return (
                    NULL(prog, "struct task_struct *"),
                    RwsemStateCode.ANONYMOUSLY_OWNED,
                )
            else:
                return rwsem.owner, RwsemStateCode.WRITER_OWNED
        else:
            owner = cast("struct task_struct *", rwsem.owner.counter)
            return owner, RwsemStateCode.WRITER_OWNED
    elif is_rwsem_reader_owned(rwsem):
        return NULL(prog, "struct task_struct *"), RwsemStateCode.READER_OWNED
    else:
        return (
            NULL(prog, "struct task_struct *"),
            RwsemStateCode.OWNER_TYPE_UNKNOWN,
        )


def get_rwsem_waiter_type(rwsem_waiter: Object) -> str:
    """
    Find type of an rwsem waiter

    :param rwsem_waiter: ``struct rwsem_waiter``
    :returns: str indicating type of rwsem waiter
    """

    prog = rwsem_waiter.prog_
    if (
        rwsem_waiter.type.value_()
        == prog.constant("RWSEM_WAITING_FOR_WRITE").value_()
    ):
        waiter_type = "down_write"
    elif (
        rwsem_waiter.type.value_()
        == prog.constant("RWSEM_WAITING_FOR_READ").value_()
    ):
        waiter_type = "down_read"
    else:
        waiter_type = "waiter type unknown"

    return waiter_type


def get_rwsem_waiters_info(rwsem: Object, callstack: int = 0) -> None:
    """
    Get a summary of rwsem waiters.
    The summary consists of ``struct task_struct *``, pid and type of waiters

    :param rwsem: ``struct rw_semaphore *``
    """

    waiter_type = "none"
    print("The waiters of rwsem are as follows: ")
    tbl = FixedTable(["TASK:>x", "PID:>", "TYPE:16s", "CPU:>", "ST", "WAIT:>"])
    for waiter in for_each_rwsem_waiter_entity(rwsem):
        waiter_type = get_rwsem_waiter_type(waiter)
        task = waiter.task
        tbl.row(
            task.value_(),
            task.pid.value_(),
            waiter_type,
            task_cpu(task),
            task_state_to_char(task),
            timestamp_str(task_lastrun2now(task)),
        )
        if callstack:
            print("call stack of waiter:\n ")
            bt(task)
    tbl.write()


def get_rwsem_spinners_info(rwsem: Object, callstack: int = 0) -> None:
    """
    Get a summary of rwsem spinners.
    The summary consists of ``struct task_struct *``, pid, CPU, state
    and spin time

    :param rwsem: ``struct rw_semaphore *``
    """

    prog = rwsem.prog_
    spinner_list = [
        cpu for cpu in for_osq_owner_and_each_spinner(rwsem.osq.address_of_())
    ]
    print(f"rwsem has {len(spinner_list)} spinners, which are as follows: ")
    tbl = FixedTable(["TASK:>x", "PID:>", "CPU:>", "CURRENT SPINTIME:>"])
    for cpu in spinner_list:
        task = cpu_curr(prog, cpu)
        tbl.row(
            task.value_(),
            task.pid.value_(),
            task_cpu(task),
            timestamp_str(get_current_run_time(prog, cpu)),
        )
        if callstack:
            print("call stack of spinner:\n ")
            bt(task)
    tbl.write()


def is_rwsem_reader_owned(rwsem: Object) -> bool:
    """
    Check if rwsem is reader owned or not

    :param rwsem: ``struct rw_semaphore *``
    :returns: True if rwsem is reader owned, False otherwise (including the
              case when type of owner could not be determined or when rwsem
              is free.)
    """
    if not rwsem.count.counter.value_():  # rwsem is free
        return False
    if rwsem.owner.type_.type_name() == "atomic_long_t":
        owner_is_writer = rwsem.count.counter.value_() & _RWSEM_WRITER_LOCKED
        owner_is_reader = (
            (rwsem.count.counter.value_() & _RWSEM_READER_MASK)
            and (rwsem.owner.counter.value_() & _RWSEM_READER_OWNED)
            and (owner_is_writer == 0)
        )

        return bool(owner_is_reader)
    else:
        if not rwsem.owner.value_():
            print(
                "rwsem is being acquired but owner info has not yet been set."
            )
            return False
        owner_is_reader = rwsem.owner.value_() == _RWSEM_READER_OWNED
        return owner_is_reader


def is_rwsem_writer_owned(rwsem: Object) -> bool:
    """
    Check if rwsem is writer owned or not

    :param rwsem: ``struct rw_semaphore *``
    :returns: True if rwsem is writer owned, False otherwise (including the
              case when type of owner could not be determined or when rwsem
              was free.)
    """
    if not rwsem.count.counter.value_():  # rwsem is free
        return False

    if rwsem.owner.type_.type_name() == "atomic_long_t":
        owner_is_writer = rwsem.count.counter.value_() & _RWSEM_WRITER_LOCKED
        return bool(owner_is_writer)
    else:
        if not rwsem.owner.value_():
            print(
                "rwsem is being acquired but owner info has not yet been set."
            )
            return False

        owner_is_reader = rwsem.owner.value_() == _RWSEM_READER_OWNED
        return not owner_is_reader


def get_rwsem_info(rwsem: Object, callstack: int = 0) -> None:
    """
    Get information about given rwsem.
    This consists of type of owner, ``struct task_struct *``, pid(s) and type
    of waiter(s)

    :param rwsem: ``struct rw_semaphore *``
    :param callstack: bool. False by default. True if call stack of waiters are
                      needed.
    """

    # This helper supports LTS versions since v4.14. It may work with
    # other versions too but has not been tested with other versions.
    # Now from v4.14 to v5.2 ->owner is of type task_struct * and ->count
    # is adjusted/interpreted according different BIAS(es) like
    # ACTIVE_BIAS, WRITE_BIAS etc.
    # Linux kernel commit 94a9717b3c40 ('locking/rwsem: Make rwsem->owner
    # an atomic_long_t') (since v5.3.1) changed ->owner type and Linux kernel
    # commit 64489e78004c ('locking/rwsem: Implement a new locking scheme')
    # (also since v5.3.1) removed usage of different BIAS(es) and re-defined
    # usage and interpretation of ->count bits.
    # So although type change of ->owner and re-definition of ->count bits
    # happened in 2 different commits, both of these changes are available
    # since v5.3.1.
    # So we can use ->owner type to distinguish between new and old usage
    # of rwsem ->count and ->owner bits.

    print(f"({rwsem.type_.type_name()})0x{rwsem.value_():x}")
    if not rwsem.count.counter.value_():
        print("rwsem is free.")
        return

    if rwsem_has_spinner(rwsem):
        get_rwsem_spinners_info(rwsem, callstack)
    else:
        print("rwsem has no spinners.")

    owner_task, owner_type = get_rwsem_owner(rwsem)

    if owner_task:
        # Only for a writer owned rwsem, we get task_struct of owner
        print(
            f"Writer owner ({owner_task.type_.type_name()})0x{owner_task.value_():x}: (pid){owner_task.pid.value_()}"
        )
    elif owner_type == RwsemStateCode.READER_OWNED:
        # For reader owned rwsems, we can get number of readers in newer kernels( >= v5.3.1).
        # So try to retrieve that info.
        if rwsem.owner.type_.type_name() == "atomic_long_t":
            num_readers = (
                rwsem.count.counter.value_() & _RWSEM_READER_MASK
            ) >> _RWSEM_READER_SHIFT
            print(f"Owned by {num_readers} reader(s)")
        else:
            print("rwsem is owned by one or more readers")
    else:
        print(f" rwsem is {owner_type.value}")

    if list_empty(rwsem.wait_list.address_of_()):
        print("There are no waiters")
    else:
        get_rwsem_waiters_info(rwsem, callstack)
