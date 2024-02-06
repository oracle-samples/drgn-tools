# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Utilities for virtualization
"""
import argparse

from drgn import Program
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.percpu import per_cpu

from drgn_tools.corelens import CorelensModule


def get_platform_arch(prog: Program) -> str:
    """
    Returns platform architecture
    """
    dump_stack_arch_desc = prog["dump_stack_arch_desc_str"]
    str_dump_stack_arch_desc = dump_stack_arch_desc.string_().decode("utf-8")
    if "QEMU Standard PC" in str_dump_stack_arch_desc:
        return "QEMU"

    return "BareMetal"


def get_platform_hypervisor(prog: Program) -> str:
    """
    Returns hypervisor type
    Note: This is x86 specific
    """
    str_hyper_type = ""
    try:
        hyper_type = prog["x86_hyper_type"]
        str_hyper_type = str(hyper_type).split(")")[1]
    except KeyError:
        print("Platform not supported.")

    return str_hyper_type


def get_cpuhp_state(prog, cpu: int) -> str:
    cpuhp_state = per_cpu(prog["cpuhp_state"], cpu).state
    index = cpuhp_state.value_()
    enums = cpuhp_state.type_.enumerators
    cpuhp_state_str = ""
    for e in enums:
        if e.value == index:
            cpuhp_state_str = e.name
            break
    return cpuhp_state_str


def show_cpuhp_state(prog) -> None:
    for cpu in for_each_possible_cpu(prog):
        state = get_cpuhp_state(prog, cpu)
        cpu_state_str = "CPU [" + str(cpu) + "] : " + state
        print(cpu_state_str)


def show_platform(prog: Program) -> None:
    """
    Prints the kernel command line
    """
    str_platform = (
        "Platform : "
        + get_platform_arch(prog)
        + " "
        + get_platform_hypervisor(prog)
    )
    print(str_platform)


class VirtUtil(CorelensModule):
    """Display the kernel command line"""

    name = "virtutil"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        show_platform(prog)
