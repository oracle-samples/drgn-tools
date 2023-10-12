# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Decode CSD/CFD info"""
import argparse
from typing import Iterator
from typing import Tuple

import drgn
from drgn import Object
from drgn import Program
from drgn import Type
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.llist import llist_empty
from drgn.helpers.linux.llist import llist_for_each_entry
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.percpu import per_cpu_ptr

from drgn_tools.bt import bt
from drgn_tools.bt import bt_frames
from drgn_tools.corelens import CorelensModule
from drgn_tools.task import get_current_run_time
from drgn_tools.task import get_current_task
from drgn_tools.task import get_runq_lag
from drgn_tools.task import has_member
from drgn_tools.task import nanosecs_to_secs


def _get_csd_type(prog: drgn.Program) -> Type:
    try:
        return prog.type("struct __call_single_data ")
    except LookupError:
        return prog.type("struct call_single_data ")


def _irq_enabled(prog, cpu) -> bool:
    """
    Determine irq state on a CPU, based on call stack at that CPU.

    :param cpu: The cpu to check
    :returns: True if irq was enabled, False if irq was disabled.
              One exception is for the cpu that triggered the panic.
              For such a case, this helper will return False since
              panic disables irq but actual irq status before panic
              can't be deduced by this helper. Such case would need
              manual review of panic call trace to determine the
              irq status before panic was triggered.

    """
    _X86_EFLAGS_TF = 1 << 9
    frames = bt_frames(prog, cpu=cpu)
    ret = False
    for frame in frames:
        # panic() disables irq anyways, so we don't want to check
        # irq state (i.e RFLAGS) later in call stack
        if frame.name is not None:
            if "crash_" in frame.name or "kexec" in frame.name:
                continue

            if frame.interrupted:
                # We are relying on presence of an interrupted stack
                # frame to get irq status, since normal stack frames
                # would not have recorded RFLAGS.
                # Since each CPU will at least get an NMI via crash
                # mechanism, we will get at least one interrupted
                # stack frame on each CPU.
                # For the special cases where a CPU directly invokes
                # panic() or if crash is triggered via sysrq the CPU
                # invoking panic() or doing sysrq will not get crash
                # mechanism's NMI and hence it may not have any
                # interrupted stack frame. For such case we report
                # irq state as "undetermined" on this CPU

                if frame.registers()["rflags"] & _X86_EFLAGS_TF:
                    ret = True
                    break
                else:
                    ret = False
                    break
    return ret


def is_cur_csd_pending(prog: drgn.Program, cpu: int) -> bool:
    """
    Return whether cur_csd.func of a CPU is still under execution.

    For kernels that have ``cur_csd_func`` and ``cur_csd``, before starting
    execution of csd function at destination CPU, both of these per-cpu
    variables are updated and just after executing csd function cur_csd is made
    NULL.

    So for a CPU if ``cur_csd_func`` is same as ``cur_csd.func``, that would
    mean that the CPU is in the middle of executing csd function or it has just
    finished the execution of csd function but has noy yet updated cur_csd to
    NULL.

    If ``cur_csd.func`` and ``cur_csd_func`` are not same, ``cur_csd_func``
    gives last csd function that this CPU executed.

    :param cpu: The cpu to check.
    :returns: True if ``cur_csd_func`` equals ``cur_csd.func``, False otherwise

    """
    try:
        cur_csd = prog["cur_csd"]
    except KeyError:
        print("This kernel does not have per-cpu CSD pointers.")
        return False

    try:
        cur_csd_func = prog["cur_csd_func"]
    except KeyError:
        print("This kernel does not have per-cpu CSD function pointers.")
        return False

    csd = per_cpu(cur_csd, cpu)
    csd_func = per_cpu(cur_csd_func, cpu)
    if not csd:
        return False
    else:
        return csd_func == csd.func


def is_call_single_queue_empty(prog: drgn.Program, cpu: int) -> bool:
    """
    Return whether ``call_single_queue`` of a CPU is empty or not.

    :param cpu: The cpu to check.
    :returns: True if ``call_single_queue`` is empty, False otherwise

    """
    return llist_empty(per_cpu(prog["call_single_queue"], cpu).address_of_())


def for_each_cur_csd(prog: drgn.Program) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over all CSDs pointed to by per-cpu ``cur_csd``

    :returns: Iterator of cpu number and ``struct __call_single_data *``
      or iterator of cpu number and ``struct call_single_data *``
    """
    try:
        cur_csd = prog["cur_csd"]
        for cpu in for_each_possible_cpu(prog):
            yield cpu, per_cpu(cur_csd, cpu)
    except KeyError:
        print("This kernel does not have per-cpu CSD pointers.")
        return None


def for_each_cur_csd_func(prog: drgn.Program) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over all functions pointed to by per-cpu ``cur_csd_func``

    :returns: Iteator of cpu number and ``void (*smp_call_func_t)(void*)``
    """
    try:
        cur_csd_func = prog["cur_csd_func"]
        for cpu in for_each_possible_cpu(prog):
            yield cpu, per_cpu(cur_csd_func, cpu)
    except KeyError:
        print("This kernel does not have per-cpu CSD function pointers.")
        return None


def for_each_call_single_queue(
    prog: drgn.Program,
) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over list of per-cpu ``call_single_queue`` objects

    :returns: Iteator of cpu number and ``struct llist_head *``
    """
    for cpu in for_each_possible_cpu(prog):
        yield cpu, per_cpu(prog["call_single_queue"], cpu).address_of_()


def for_each_cfd_data(prog: drgn.Program) -> Iterator[Tuple[int, Object]]:
    """
    Iterate over per-cpu ``cfd_data``

    :returns: Iteator of cpu number and ``struct call_function_data *``
    """
    for cpu in for_each_possible_cpu(prog):
        yield cpu, per_cpu(prog["cfd_data"], cpu).address_of_()


def dump_pending_csd_for_all_cpus(prog: drgn.Program) -> None:
    """
    Dump ``call_single_queue`` list of all CPUs
    """
    for cpu, csq in for_each_call_single_queue(prog):
        if llist_empty(csq):
            print("call_single_queue is empty for cpu: ", cpu)
        else:
            print(f"dumping call_single_queue for {cpu}")
            csd_type = _get_csd_type(prog)
            llist = "llist" if csd_type.has_member("llist") else "node.llist"
            for csd in llist_for_each_entry(csd_type, csq.first, llist):
                print(csd)


def dump_cfd_at_all_cpus(prog: drgn.Program) -> None:
    """
    Dump per-cpu ``cfd_data``

    There is a per-cpu ``struct call_function_data`` object (``cfd_data``) for
    each cpu and cpus can use the underlying per-cpu csd to send csd requests.

    This helper dumps CSDs within ``cfd_data`` of each cpu.
    """
    for cpu, cfd in for_each_cfd_data(prog):
        print(f"cfd_data at {cpu}")
        for n in for_each_possible_cpu(prog):
            if has_member(cfd, "pcpu"):
                csd = per_cpu_ptr(cfd.pcpu, n).csd
            else:
                csd = per_cpu_ptr(cfd.csd, n)
            print(f"\t csd for cpu: {n}")
            print("\t", csd)


def dump_smp_ipi_objects(prog: drgn.Program) -> None:
    """
    Dump objects of smp ipi subsystem

    1. per cpu ``call_single_queue`` list of each CPU

    2. per cpu ``cur_csd`` of each CPU

    3. per cpu ``cur_csd_func`` of each CPU
    """

    print("dumping call_single_queue at each CPU")
    dump_pending_csd_for_all_cpus(prog)

    try:
        _ = prog["cur_csd"]
        print("dumping cur_csd of each CPU")
        for cpu, csd in for_each_cur_csd(prog):
            if not csd:
                print(f"cpu: {cpu} cur_csd: {hex(csd)}")
            else:
                print(
                    f"cpu: {cpu} cur_csd: {hex(csd)} cur_csd.func: {hex(csd.func)}"
                )
    except KeyError:
        pass

    try:
        _ = prog["cur_csd_func"]
        print("dumping cur_csd_func of each CPU")
        for cpu, csd_func in for_each_cur_csd_func(prog):
            print(f"cpu: {cpu} cur_csd_func: {hex(csd_func)}")
    except KeyError:
        pass


def dump_smp_ipi_state(prog: drgn.Program) -> None:
    """
    Dump state of SMP IPI subsystem

    1. Which CPUs have pending smp ipis, what they are doing and
       whether they have interrupts disabled.

    2. Which CPUs are waiting in csd lock, at what place and for
       how long.

    3. Is there any pending csd for an offline CPU?

    """

    csd_type = _get_csd_type(prog)
    if not csd_type.has_member("src") and not csd_type.has_member("node"):
        print(
            "This kernel does not record CSD src and destination information"
        )
        return

    for cpu, csq in for_each_call_single_queue(prog):
        if llist_empty(csq):
            continue

        llist = "llist" if csd_type.has_member("llist") else "node.llist"

        for csd in llist_for_each_entry(csd_type, csq.first, llist):
            if csd_type.has_member("src"):
                src = csd.src.value_()
            else:
                src = csd.node.src.value_()
            print(f"\ncpu: {cpu} has pending csd requests from cpu:", src)

            print("\nCall stack at source cpu: ", src)
            bt(prog, cpu=src)
            waiter_task = get_current_task(prog, src)
            wait_time_ns = get_current_run_time(prog, src)
            wait_time_s = nanosecs_to_secs(wait_time_ns)
            waiter_name = escape_ascii_string(
                waiter_task.comm.string_(), escape_backslash=True
            )
            waiter_pid = waiter_task.pid.value_()
            if not waiter_task.pid.value_():
                print(
                    "\nWaiter CPU is idle. Waiter of a csd lock can't be idle."
                )
            else:
                print(
                    f'\ncsd lock waiter "{waiter_name}:{waiter_pid}" has been waiting for:{wait_time_s} secs.'
                )

        print("\nCall stack at destination cpu: ", cpu)
        bt(prog, cpu=cpu)
        dst_task = get_current_task(prog, cpu)
        run_time_ns = get_current_run_time(prog, cpu)
        run_time_s = nanosecs_to_secs(run_time_ns)
        dst_task_name = escape_ascii_string(
            dst_task.comm.string_(), escape_backslash=True
        )
        dst_task_pid = dst_task.pid.value_()
        enabled = _irq_enabled(prog, cpu)
        if enabled:
            irq_state = "IRQs enabled"
        else:
            irq_state = (
                "IRQs disabled or IRQs enablement could not be determined"
            )

        if not dst_task.pid.value_():
            print(
                "\ndestination is idle. CSD destination should not be idle when there are pending CSD requests."
            )
        else:
            print(
                f'\ndestination state task: "{dst_task_name}:{dst_task_pid}" running for {run_time_s} secs with {irq_state}'
            )

        rq_lag_ns = get_runq_lag(prog, cpu)
        rq_lag_s = nanosecs_to_secs(rq_lag_ns)
        if rq_lag_s:
            print(
                f"\ndestination CPU's runq clock is lagging by {rq_lag_s} secs"
            )


class SmpIpiModule(CorelensModule):
    """Display the state of the SMP IPI subsystem"""

    name = "smp"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        dump_smp_ipi_state(prog)
