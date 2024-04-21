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
from collections import defaultdict
from typing import DefaultDict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

import drgn
from drgn import Object
from drgn import Program
from drgn import StackFrame
from drgn.helpers.linux.cpumask import for_each_present_cpu
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.pid import find_task

from drgn_tools.bt import bt
from drgn_tools.bt import bt_has_any
from drgn_tools.corelens import CorelensModule
from drgn_tools.locking import _RWSEM_READER_MASK
from drgn_tools.locking import _RWSEM_READER_SHIFT
from drgn_tools.locking import for_each_mutex_waiter
from drgn_tools.locking import for_each_rwsem_waiter
from drgn_tools.locking import get_lock_from_stack_frame
from drgn_tools.locking import get_rwsem_owner
from drgn_tools.locking import get_rwsem_spinners_info
from drgn_tools.locking import mutex_owner
from drgn_tools.locking import rwsem_has_spinner
from drgn_tools.locking import RwsemStateCode
from drgn_tools.locking import show_lock_waiter
from drgn_tools.locking import tail_osq_node_to_spinners
from drgn_tools.task import get_current_run_time
from drgn_tools.task import nanosecs_to_secs
from drgn_tools.task import task_lastrun2now


def scan_osq_node(prog: Program, verbosity: int = 0) -> None:
    """
    Show CPUs spinning to grab sleeping lock(s).

    :param prog: drgn.Program
    :param verbosity: specify verbosity of report as follows:
                      0: Show which CPUs are spinning
                      1: Show which CPUs are spinning and for how long
                      2: Show spinning CPUs, their spin duration and call stack
                         till the point of spin
    """

    osq_spinners: DefaultDict[int, List[int]] = defaultdict(list)
    for cpu in for_each_present_cpu(prog):
        osq_node = per_cpu(prog["osq_node"], cpu)
        if not osq_node.next.value_():
            continue

        while osq_node.next.value_():
            osq_node = osq_node.next[0]

        if osq_node.address_ in osq_spinners.keys():
            continue

        for spinner_cpu in tail_osq_node_to_spinners(osq_node):
            osq_spinners[osq_node.address_].append(spinner_cpu)

    if not len(osq_spinners):
        print("There are no spinners on any osq_lock")
        return

    print("There are spinners on one or more osq_lock")
    for key in osq_spinners.keys():
        print(f"CPU(s): {osq_spinners[key]} are spinning on same osq_lock")
        if verbosity >= 1:
            cpu_list = osq_spinners[key]
            for cpu in cpu_list:
                run_time_ns = get_current_run_time(prog, cpu)
                run_time_s = nanosecs_to_secs(run_time_ns)
                print(
                    f"CPU: {cpu} has been spinning for {run_time_s} secs, since it last got on CPU."
                )

                if (
                    verbosity == 2
                ):  # for max verbosity dump call stack of spinners
                    print("\nCall stack at cpu: ", cpu)
                    bt(prog, cpu=cpu)


def scan_mutex_lock(
    prog: Program,
    stack: bool,
    time: Optional[int] = None,
    pid: Optional[int] = None,
) -> None:
    """Scan for mutex and show details"""
    wtask = None
    if pid is not None:
        wtask = find_task(prog, pid)

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

        index = 0
        print(f"Mutex: 0x{mutex_addr:x}")
        print(
            "Mutex OWNER:",
            struct_owner.comm.string_().decode("utf-8"),
            "PID :",
            struct_owner.pid.value_(),
        )
        print("")
        if stack:
            bt(struct_owner.pid)
        print("")

        print(
            "Mutex WAITERS (Index, cpu, comm, pid, state, wait time (d hr:min:sec:ms)):"
        )
        if pid is None:
            if time is None:
                time = 0
            for waiter in for_each_mutex_waiter(prog, mutex):
                waittime = task_lastrun2now(waiter)
                timens = time * 1000000000
                index = index + 1

                if waittime > timens or timens == 0:
                    show_lock_waiter(prog, waiter, index, stacktrace=stack)
                else:
                    continue
        else:
            show_lock_waiter(prog, wtask, index, stacktrace=stack)

        print("")


def show_sem_lock(
    prog: Program,
    frame_list,
    seen_sems,
    stack: bool,
    time: Optional[int] = None,
    pid: Optional[int] = None,
) -> None:
    """Show semaphore details"""
    warned_absent = False
    wtask = None
    seen_sems_waiters: Set[int] = set()

    if pid is not None:
        wtask = find_task(prog, pid)

    for task, frame in frame_list:
        if task.pid.value_() in seen_sems_waiters:
            continue

        try:
            sem = frame["sem"]
        except drgn.ObjectAbsentError:
            sem = get_lock_from_stack_frame(
                prog, task.pid.value_(), frame, "semaphore"
            )
            if not sem:
                if not warned_absent:
                    print(
                        "warning: failed to get semaphore from stack frame"
                        "- information is incomplete"
                    )
                    warned_absent = True

        if not sem:
            continue

        semaddr = sem.value_()
        if semaddr in seen_sems:
            continue
        seen_sems.add(semaddr)
        seen_sems_waiters.update(
            [
                waiter.pid.value_()
                for waiter in for_each_rwsem_waiter(prog, sem)
            ]
        )

        index = 0
        print(f"Semaphore: 0x{semaddr:x}")
        print(
            "Semaphore WAITERS (Index, cpu, comm, pid, state, wait time (d hr:min:sec:ms)):"
        )
        if pid is None:
            if time is None:
                time = 0
            for waiter in for_each_rwsem_waiter(prog, sem):
                waittime = task_lastrun2now(waiter)
                timens = time * 1000000000
                index = index + 1

                if waittime > timens or timens == 0:
                    show_lock_waiter(prog, waiter, index, stacktrace=stack)
                else:
                    continue
        else:
            show_lock_waiter(prog, wtask, index, stacktrace=stack)

        print("")


def show_rwsem_lock(
    prog: Program,
    frame_list: List[Tuple[Object, StackFrame]],
    seen_rwsems: Set[int],
    stack: bool,
    time: Optional[int] = None,
    pid: Optional[int] = None,
) -> None:
    """Show rw_semaphore details"""
    warned_absent = False
    wtask = None
    seen_rwsems_waiters: Set[int] = set()

    if pid is not None:
        wtask = find_task(prog, pid)

    for task, frame in frame_list:
        # If rwsem can't be located using frame["sem"], then we rely on
        # locating it at certain known offsets within a frame and this is
        # an expensive operation,
        # So keep a set of already seen waiters because these waiters and the
        # rwsems, these waiters are blocked on, have already been accounted for.
        if task.pid.value_() in seen_rwsems_waiters:
            continue

        try:
            rwsem = frame["sem"]
        except drgn.ObjectAbsentError:
            rwsem = get_lock_from_stack_frame(
                prog, task.pid.value_(), frame, "rw_semaphore"
            )
            if not rwsem:
                task_frame_list = prog.stack_trace(task.pid.value_())
                for tmp_frame in task_frame_list:
                    if tmp_frame.name != "__schedule":
                        continue

                    rwsem = get_lock_from_stack_frame(
                        prog, task.pid.value_(), tmp_frame, "rw_semaphore"
                    )
                    if not rwsem:
                        if not warned_absent:
                            print(
                                "warning: failed to get rwsemaphore from stack frame"
                                "- information is incomplete"
                            )
                            warned_absent = True

        if not rwsem:
            continue

        rwsemaddr = rwsem.value_()
        if rwsemaddr in seen_rwsems:
            continue
        seen_rwsems.add(rwsemaddr)
        seen_rwsems_waiters.update(
            [
                waiter.pid.value_()
                for waiter in for_each_rwsem_waiter(prog, rwsem)
            ]
        )

        index = 0
        print(f"Rwsem: ({rwsem.type_.type_name()})0x{rwsem.value_():x}")
        if rwsem_has_spinner(rwsem):
            get_rwsem_spinners_info(rwsem, stack)
        else:
            print("rwsem has no spinners.")

        owner_task, owner_type = get_rwsem_owner(rwsem)

        if owner_task:
            # Only for a writer owned rwsem, we get task_struct of owner
            print(
                f"Writer owner ({owner_task.type_.type_name()})0x{owner_task.value_():x}: (pid){owner_task.pid.value_()}"
            )
            print("")
            if stack:
                bt(owner_task.pid)
            print("")
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

        print(
            "Rwsem WAITERS (Index, cpu, comm, pid, state, type, wait time (d hr:min:sec:ms)):"
        )
        if pid is None:
            if time is None:
                time = 0

            for waiter in for_each_rwsem_waiter(prog, rwsem):
                waittime = task_lastrun2now(waiter)
                timens = time * 1000000000
                index = index + 1

                if waittime > timens or timens == 0:
                    show_lock_waiter(prog, waiter, index, stacktrace=stack)
                else:
                    continue
        else:
            show_lock_waiter(prog, wtask, index, stacktrace=stack)

        print("")


def scan_sem_lock(
    prog: Program,
    stack: bool,
    time: Optional[int] = None,
    pid: Optional[int] = None,
) -> None:
    """Scan for semaphores"""
    wtask = None
    if pid is not None:
        wtask = find_task(prog, pid)

    seen_sems: Set[int] = set()
    functions = [
        "__down",
        "__down_common",
        "__down_interruptible",
        "__down_killable",
        "__down_timeout",
    ]
    frame_list = bt_has_any(prog, functions, wtask)
    if frame_list:
        show_sem_lock(prog, frame_list, seen_sems, stack, time, pid)


def scan_rwsem_lock(
    prog: Program,
    stack: bool,
    time: Optional[int] = None,
    pid: Optional[int] = None,
) -> None:
    """Scan for read-write(rw) semphores"""
    wtask = None
    if pid is not None:
        wtask = find_task(prog, pid)

    seen_rwsems: Set[int] = set()
    functions = [
        "__rwsem_down_write_failed_common",
        "__rwsem_down_read_failed_common",
        "rwsem_down_write_slowpath",
        "rwsem_down_read_slowpath",
    ]
    frame_list = bt_has_any(prog, functions, wtask)
    if frame_list:
        show_rwsem_lock(prog, frame_list, seen_rwsems, stack, time, pid)


def scan_lock(
    prog: Program,
    stack: bool,
    time: Optional[int] = None,
    pid: Optional[int] = None,
) -> None:
    """Scan tasks for Mutex and Semaphore"""
    print("Scanning Mutexes...")
    print("")
    scan_mutex_lock(prog, stack, time, pid)

    print("Scanning Semaphores...")
    print("")
    scan_sem_lock(prog, stack, time, pid)

    print("Scanning RWSemaphores...")
    print("")
    scan_rwsem_lock(prog, stack, time, pid)


class Locking(CorelensModule):
    """Display active mutex and semaphores and their waiters"""

    name = "lock"
    need_dwarf = True

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--stack", action="store_true", help="Print the stack."
        )
        parser.add_argument(
            "--time",
            nargs="?",
            const=0,
            type=int,
            default=None,
            help="Show process with wait time more than the specified time in sec",
        )
        parser.add_argument(
            "--pid",
            nargs="?",
            const=0,
            type=int,
            default=None,
            help="Filter with process id",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if args.time is not None and args.time < 0:
            print("Wait time is less than Zero")
            return
        if args.pid is not None and args.pid < 0:
            print("pid is less than zero, Error")
            return
        if args.pid is not None and args.time is not None:
            print("Dont filter with both time and PID")
            return
        scan_lock(prog, args.stack, args.time, args.pid)
