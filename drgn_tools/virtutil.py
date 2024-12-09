# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Utilities for virtualization
"""
import argparse
from typing import Iterable

from drgn import cast
from drgn import Object
from drgn import Program
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.sched import task_state_to_char
from drgn.helpers.linux.xarray import xa_for_each

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table
from drgn_tools.util import has_member


KVM_VCPU_STATE = {
    0: "RUNNABLE",
    1: "UNINITIALIZED",
    2: "INIT_RECEIVED",
    3: "HALTED",
    4: "SIPI_RECEIVED",
    5: "STOPPED",
    6: "CHECK_STOP",
    7: "OPERATING",
    8: "LOAD",
}


def get_vm_list(prog: Program) -> Iterable[Object]:
    """
    Returns list of Object of type ``struct kvm *
    """
    vm_list = []
    try:
        vm_list = list(
            list_for_each_entry(
                "struct kvm", prog["vm_list"].address_of_(), "vm_list"
            )
        )
    except KeyError:
        print("No VMs running")

    return vm_list


def print_vm_list(prog: Program) -> None:
    """
    Print information for all the VMs
    """
    vm_list = get_vm_list(prog)

    print(" =============<< VM LIST >>=================")
    print("\n")
    rows = [
        [
            "KVM",
            "ONL",
            "CRT",
            "MEMSLOT_0",
            "MEMSLOT_1",
            "VCPUS",
            "KVM_ARCH",
            "KVM_STAT",
            "PID",
            "TASK",
            "CPU",
            "ST",
        ]
    ]

    for vm in vm_list:
        kvm_addr = hex(vm.value_())
        pid = vm.userspace_pid.value_()
        task = find_task(prog, pid)
        if has_member(task, "cpu"):
            cpu = task.cpu.value_()
        else:
            cpu = task.recent_used_cpu.value_()

        if has_member(vm, "vcpus"):
            vcpu = hex(vm.vcpus.address_of_())
        else:
            vcpu = hex(vm.vcpu_array.address_of_())

        rows.append(
            [
                kvm_addr,
                vm.online_vcpus.counter.value_(),
                vm.created_vcpus.value_(),
                hex(vm.memslots[0].value_()),
                hex(vm.memslots[1].value_()),
                vcpu,
                hex(vm.arch.address_of_()),
                hex(vm.stat.address_of_()),
                pid,
                hex(task.value_()),
                cpu,
                task_state_to_char(task),
            ]
        )
    print_table(rows)


def print_vcpu_list(prog: Program) -> None:
    """
    Print information for all the vcpus of each VM
    """
    vm_list = get_vm_list(prog)
    print(" =============<< VCPU LIST >>=================")
    print("\n")
    rows = [
        [
            "KVM",
            "VCPU",
            "ID",
            "IDX",
            "ARCH",
            "STAT",
            "STAT_ID",
            "STATE",
            "CPU",
            "TASK",
        ]
    ]

    # for UEK5 to UEK7:
    for vm in vm_list:
        if has_member(vm, "vcpus"):
            struct_vcpu = vm.vcpus
            for i in range(len(struct_vcpu)):
                if hex(struct_vcpu[i].value_()) == "0x0":
                    break
                vcpu = hex(struct_vcpu[i].value_())
                id = struct_vcpu[i].vcpu_id.value_()
                if has_member(struct_vcpu[i], "vcpu_idx"):
                    idx = struct_vcpu[i].vcpu_idx.value_()
                else:
                    idx = i
                arch = hex(struct_vcpu[i].arch.address_of_())
                stat = hex(struct_vcpu[i].stat.address_of_())
                if has_member(struct_vcpu[i], "stats_id"):
                    stat_id = struct_vcpu[i].stats_id.string_().decode("utf-8")
                else:
                    # The UEK5 does not have kvm_vcpu.stats_id structure member. Print None instead.
                    stat_id = None
                state = struct_vcpu[i].arch.mp_state.value_()
                cpu = struct_vcpu[i].cpu.value_()
                if has_member(struct_vcpu[i], "wait"):
                    task = hex(struct_vcpu[i].wait.task.value_())
                else:
                    # The UEK5 does not have kvm_vcpu.wait structure member. Print None instead.
                    task = None
                rows.append(
                    [
                        hex(vm.value_()),
                        vcpu,
                        id,
                        idx,
                        arch,
                        stat,
                        stat_id,
                        KVM_VCPU_STATE[state],
                        cpu,
                        str(task),
                    ]
                )
        # For UEK-NEXT:
        else:
            for _, entry in xa_for_each(vm.vcpu_array.address_of_()):
                struct_vcpu = cast("struct kvm_vcpu *", entry)
                if hex(struct_vcpu.value_()) == "0x0":
                    break
                vcpu = hex(struct_vcpu.value_())
                id = struct_vcpu.vcpu_id.value_()
                idx = struct_vcpu.vcpu_idx.value_()
                arch = hex(struct_vcpu.arch.address_of_())
                stat = hex(struct_vcpu.stat.address_of_())
                stat_id = struct_vcpu.stats_id.string_().decode("utf-8")
                state = struct_vcpu.arch.mp_state.value_()
                cpu = struct_vcpu.cpu.value_()
                task = hex(struct_vcpu.wait.task.value_())

                rows.append(
                    [
                        hex(vm.value_()),
                        vcpu,
                        id,
                        idx,
                        arch,
                        stat,
                        stat_id,
                        KVM_VCPU_STATE[state],
                        cpu,
                        str(task),
                    ]
                )

    print_table(rows)


def get_platform_arch(prog: Program) -> str:
    """
    Returns platform architecture
    """
    try:
        dump_stack_arch_desc = prog["dump_stack_arch_desc_str"]
    except KeyError:
        # For UEK6 kernels with CTF debuginfo, the "dump_stack_arch_desc_str"
        # variable doesn't have type information, despite appearing in the
        # symbol table. This is a CTF generation bug. Regardless, the variable
        # is declared as char[128], so let's go ahead and use the available
        # symbol and hard-code the type.
        sym = prog.symbol("dump_stack_arch_desc_str")
        dump_stack_arch_desc = Object(prog, "char[128]", address=sym.address)
    str_dump_stack_arch_desc = dump_stack_arch_desc.string_().decode("utf-8")
    return str_dump_stack_arch_desc


def get_platform_hypervisor(prog: Program) -> str:
    """
    Returns hypervisor type
    Note: This is x86 specific
    """
    try:
        return prog["x86_hyper_type"].format_(type_name=False)
    except KeyError:
        return "UNKNOWN Hypervisor (Platform not supported)"


def get_cpuhp_state(prog: Program, cpu: int) -> str:
    """
    Return CPU state for a given CPU
    """
    try:
        cpuhp_state = per_cpu(prog["cpuhp_state"], cpu).state
    except KeyError:
        # Variable cpuhp_state is introduced in cff7d378d3fd ("cpu/hotplug:
        # Convert to a state machine for the control processor"), so it is not
        # present in UEK4. It is expected for this to fail there.
        return "UNKNOWN (missing 'cpuhp_state' variable)"
    return cpuhp_state.format_(type_name=False)


def show_cpuhp_state(prog: Program) -> None:
    """
    Display cpu state for all possible CPUs
    """
    for cpu in for_each_possible_cpu(prog):
        state = get_cpuhp_state(prog, cpu)
        print(f"CPU [{cpu:3d}]: {state}")


def get_platform(prog: Program) -> str:
    """
    Return platform type
    """
    str_platform = (
        get_platform_arch(prog) + " " + get_platform_hypervisor(prog)
    )
    return str_platform


def show_platform(prog: Program) -> None:
    """
    Prints platfrom type
    """
    platform = get_platform(prog)
    print(platform)


class VirtUtil(CorelensModule):
    """
    This module contains helper regarding virtualization.
    Current functionality are :
    cpu hotplug state
    platform type, which includes architecture and hypervisor type
    """

    name = "virt"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "-kvm",
            dest="list_vm",
            action="store_true",
            help="show all VM info",
        )
        parser.add_argument(
            "-vcpu",
            dest="vcpu_list",
            action="store_true",
            help="show all vcpu info",
        )
        parser.add_argument(
            "-p",
            dest="show_platform",
            action="store_true",
            help="show platfrom related information",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if args.show_platform:
            show_platform(prog)
        elif args.list_vm:
            print_vm_list(prog)
        elif args.vcpu_list:
            print_vcpu_list(prog)

        return
