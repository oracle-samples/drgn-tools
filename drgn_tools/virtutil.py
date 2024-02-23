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
    return str_dump_stack_arch_desc


def get_platform_hypervisor(prog: Program) -> str:
    """
    Returns hypervisor type
    Note: This is x86 specific
    """
    try:
        return prog["x86_hyper_type"].format_(type_name=False)
    except KeyError:
        print("Platform not supported.")
    return ""


def get_cpuhp_state(prog: Program, cpu: int) -> str:
    cpuhp_state = per_cpu(prog["cpuhp_state"], cpu).state
    return cpuhp_state.format_(type_name=False)


def show_cpuhp_state(prog: Program) -> None:
    for cpu in for_each_possible_cpu(prog):
        state = get_cpuhp_state(prog, cpu)
        print(f"CPU [{cpu:3d}]: {state}")


def show_platform(prog: Program) -> str:
    """
    Prints the kernel command line
    """
    str_platform = (
        get_platform_arch(prog) + " " + get_platform_hypervisor(prog)
    )
    return str_platform


class VirtUtil(CorelensModule):
    """"""

    name = "virtutil"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        return
