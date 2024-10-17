# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Utilities for virtualization
"""
import argparse

from drgn import Object
from drgn import Program
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.percpu import per_cpu

from drgn_tools.corelens import CorelensModule


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

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        show_platform(prog)
        return
