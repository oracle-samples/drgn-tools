# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers related to kernel irq management framework under kernel/irq.

"""
import argparse
from typing import Any
from typing import Iterator
from typing import List

from drgn import NULL
from drgn import Object
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_present_cpu
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.radixtree import radix_tree_lookup

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table
from drgn_tools.util import cpumask_to_cpulist
from drgn_tools.util import has_member
from drgn_tools.util import uek4_radix_tree_lookup


def _sparse_irq_supported(prog: Program) -> bool:
    try:
        _ = prog["irq_desc_tree"]
        return True
    except KeyError:
        return False


def _kstat_irqs_cpu(prog: Program, irq: int, cpu: int) -> int:
    desc = irq_to_desc(prog, irq)
    if not desc:
        return 0

    addr = per_cpu_ptr(desc.kstat_irqs, cpu)
    return Object(prog, "int", address=addr).value_()


def _irq_count(prog: Program, irq: int) -> int:
    total_count = 0
    for cpu in for_each_present_cpu(prog):
        kstat_irqs = _kstat_irqs_cpu(prog, irq, cpu)
        if not kstat_irqs:
            continue
        total_count += kstat_irqs

    return total_count


def irq_in_use(prog: Program, irq: int) -> bool:
    """
    Check if a given irq number is in use or not.
    An irq number is considered to be in use by the kernel, if the kernel
    has allocated a irq descriptor for it. The irq may not yet have any
    registered irq handlers.

    :param prog: drgn program
    :param irq: irq number

    :return: True if irq is in use, False otherwise
    """
    desc = irq_to_desc(prog, irq)
    # An irq number is in use if irq_desc object has been allocated for it
    return bool(desc)


def irq_has_action(prog: Program, irq: int) -> bool:
    """
    Check if a given irq has handler(s) registered or not.

    :param prog: drgn program
    :param irq: irq number

    :return: True if irq has registered handler(s), False otherwise
    """

    desc = irq_to_desc(prog, irq)
    return bool(desc and desc.action)


def for_each_in_use_irq_num(prog: Program) -> Iterator[int]:
    """
    Iterate through all inuse irq numbers.

    :param prog: drgn program

    :return: Iterator of possible irq numbers
    """
    nr_irqs = prog["nr_irqs"].value_()
    for irq_num in range(nr_irqs):
        if irq_in_use(prog, irq_num):
            yield irq_num


def for_each_irq_desc(prog: Program) -> Iterator[Object]:
    """
    Iterate through all allocated irq descriptors.

    :param prog: drgn program

    :return: Iterator of ``struct irq_desc *`` objects.
    """
    for irq_num in for_each_in_use_irq_num(prog):
        yield irq_to_desc(prog, irq_num)


def irq_name_to_desc(prog: Program, name: str) -> Object:
    """
    Get ``struct irq_desc *`` for irq handler of given name

    :param prog: drgn program
    :param name: name of irq handler

    :return: ``struct irq_desc *`` object if irq descriptor is found.
             NULL otherwise
    """
    for desc in for_each_irq_desc(prog):
        if desc.action:
            tmp_name = escape_ascii_string(
                desc.action.name.string_(), escape_backslash=True
            )

            if tmp_name == name:
                return desc

    return NULL(prog, "void *")


def irq_to_desc(prog: Program, irq: int) -> Object:
    """
    Get ``struct irq_desc *`` for given irq number

    :param prog: drgn program
    :param irq: irq number

    :return: ``struct irq_desc *`` object if irq descriptor is found.
             NULL otherwise
    """
    if _sparse_irq_supported(prog):
        try:
            if prog.type("struct radix_tree_node").has_member("shift"):
                addr = radix_tree_lookup(
                    prog["irq_desc_tree"].address_of_(), irq
                )
            else:
                addr = uek4_radix_tree_lookup(
                    prog["irq_desc_tree"].address_of_(), irq
                )
        except LookupError:
            addr = radix_tree_lookup(prog["irq_desc_tree"].address_of_(), irq)

        if addr:
            return Object(prog, "struct irq_desc", address=addr).address_of_()
        else:
            return NULL(prog, "void *")
    else:
        return (prog["irq_desc"][irq]).address_of_()


def get_irq_affinity(prog: Program, irq: int) -> Object:
    """
    Get ``struct cpumask`` for given irq's cpu affinity

    :param prog: drgn program
    :param irq: irq number

    :return: ``struct cpumask`` object if irq descriptor is found.
             None otherwise
    """

    if not irq_in_use(prog, irq):
        print(f"No irq descriptor found for irq: {irq}")
        return None

    irq_desc = irq_to_desc(prog, irq)

    # if CONFIG_CPUMASK_OFFSTACK is enabled then affinity is an array
    # of cpumask objects otherwise it is pointer to a cpumask object
    if has_member(irq_desc, "irq_common_data"):
        try:
            _ = len(irq_desc.irq_common_data.affinity)
            addr = irq_desc.irq_common_data.affinity.address_
        except TypeError:
            addr = irq_desc.irq_common_data.affinity.value_()
    elif has_member(irq_desc, "irq_data"):
        try:
            _ = len(irq_desc.irq_data.affinity)
            addr = irq_desc.irq_data.affinity.address_
        except TypeError:
            addr = irq_desc.irq_data.affinity.value_()
    else:
        return None

    return Object(prog, "struct cpumask", address=addr)


def get_irq_affinity_list(prog: Program, irq: int) -> Object:
    """
    Get affinity of a given cpu.

    :param prog: drgn program
    :param irq: irq number

    :return: range of cpus to which irq is affined to
    """

    affinity = get_irq_affinity(prog, irq)
    if affinity is not None:
        return cpumask_to_cpulist(affinity)
    else:
        return None


def show_irq_num_stats(prog: Program, irq: int) -> None:
    """
    Show stats for a given irq number

    :param prog: drgn program
    :param irq: irq number

    :return: None
    """

    if not irq_in_use(prog, irq):
        print(f"irq: {irq} is not in use")
        return

    if not irq_has_action(prog, irq):
        print(f"irq: {irq} has no handlers registered")
        return

    print_header = True
    total_count = 0
    for cpu in for_each_present_cpu(prog):
        kstat_irqs = _kstat_irqs_cpu(prog, irq, cpu)
        if not kstat_irqs:
            continue
        desc = irq_to_desc(prog, irq)
        name = escape_ascii_string(
            desc.action.name.string_(), escape_backslash=True
        )
        affinity = get_irq_affinity_list(prog, irq)
        if print_header:
            print(
                f"irq: {irq} name: {name} ({desc.type_.type_name()})0x{desc.value_():x} current_affinity: {affinity}"
            )
            print_header = False

        total_count += kstat_irqs
        print(f"    CPU: {cpu}  \t count: {kstat_irqs}")

    print(f"    Total: {total_count}")


def show_irq_name_stats(prog: Program, irq_name: str) -> None:
    """
    Show irq stats for irqs whose handler have specified name or
    for irqs whose handler names begin with specified string.

    :param prog: drgn program
    :param irq_name: name or beginning of name of irq handler

    :return: None
    """

    found = False
    for irq in for_each_in_use_irq_num(prog):
        if irq_has_action(prog, irq):
            desc = irq_to_desc(prog, irq)
            name = escape_ascii_string(
                desc.action.name.string_(), escape_backslash=True
            )
            if name.startswith(irq_name):
                found = True
                show_irq_num_stats(prog, irq)

    if not found:
        print(
            f"Found no irq with name: {irq_name} or with name starting with: {irq_name}"
        )


def show_irq_stats(prog: Program) -> None:
    """
    Show stats for all irqs.
    :param prog: drgn program

    :return: None
    """
    for irq in for_each_in_use_irq_num(prog):
        if irq_has_action(prog, irq):
            show_irq_num_stats(prog, irq)


def show_cpu_irq_num_stats(prog: Program, cpu: int, irq: int) -> None:
    """
    Show irq stats of a cpu for a given irq number

    :param prog: drgn program
    :param cpu: cpu index
    :param irq: irq number

    :return: None
    """

    if not irq_in_use(prog, irq):
        print(f"irq: {irq} is not in use")
        return

    if not irq_has_action(prog, irq):
        print(f"irq: {irq} has no handlers registered")
        return

    print(f"IRQ stats for cpu: {cpu}")
    desc = irq_to_desc(prog, irq)
    name = escape_ascii_string(
        desc.action.name.string_(), escape_backslash=True
    )
    kstat_irqs = _kstat_irqs_cpu(prog, irq, cpu)
    print(
        f"    irq: {irq} name: {name} ({desc.type_.type_name()})0x{desc.value_():x} count: {kstat_irqs}"
    )


def show_cpu_irq_name_stats(prog: Program, cpu: int, irq_name: str) -> None:
    """
    Show irq stats of a cpu for irqs whose handler have specified name or
    for irqs whose handler names begin with specified string.

    :param prog: drgn program
    :param cpu: cpu index
    :param irq_name: name or beginning of name of irq handler

    :return: None
    """

    found = False
    total_irqs_on_cpu = 0
    print(f"IRQ stats for cpu: {cpu}")
    for irq in for_each_in_use_irq_num(prog):
        if irq_has_action(prog, irq):
            desc = irq_to_desc(prog, irq)
            name = escape_ascii_string(
                desc.action.name.string_(), escape_backslash=True
            )
            if name.startswith(irq_name):
                found = True
                kstat_irqs = _kstat_irqs_cpu(prog, irq, cpu)
                if not kstat_irqs:
                    continue
                total_irqs_on_cpu += kstat_irqs
                print(
                    f"    irq: {irq} name: {name} ({desc.type_.type_name()})0x{desc.value_():x} count: {kstat_irqs}"
                )

    if not found:
        print(
            f"Found no irq with name: {irq_name} or with name starting with: {irq_name}"
        )
    else:
        print(f"Total: {total_irqs_on_cpu}")


def show_cpu_irq_stats(prog: Program, cpu: int) -> None:
    """
    Show irq stats for specified cpu.

    :param prog: drgn program
    :param cpu: cpu index

    :return: None
    """
    total_irqs_on_cpu = 0
    print(f"IRQ stats for cpu: {cpu}")
    for irq in for_each_in_use_irq_num(prog):
        if irq_has_action(prog, irq):
            kstat_irqs = _kstat_irqs_cpu(prog, irq, cpu)
            if not kstat_irqs:
                continue

            desc = irq_to_desc(prog, irq)
            name = escape_ascii_string(
                desc.action.name.string_(), escape_backslash=True
            )
            print(
                f"    irq: {irq} name: {name} ({desc.type_.type_name()})0x{desc.value_():x} count: {kstat_irqs}"
            )
            total_irqs_on_cpu += kstat_irqs

    print(f"Total: {total_irqs_on_cpu}")


def show_each_cpu_irq_stats(prog: Program) -> None:
    """
    Show irq stats for each cpu.

    :param prog: drgn program

    :return: None
    """
    for cpu in for_each_present_cpu(prog):
        show_cpu_irq_stats(prog, cpu)
        print("\n")


def print_irq_affinity(prog: Program, irq: int) -> None:
    """
    Print cpu affinity of specified irq.

    :param prog: drgn program
    :param irq: irq number

    :return: None
    """

    if not irq_in_use(prog, irq):
        print(f"irq: {irq} is not in use")
        return

    if not irq_has_action(prog, irq):
        print(f"irq: {irq} has no handlers registered")
        return

    desc = irq_to_desc(prog, irq)
    name = escape_ascii_string(
        desc.action.name.string_(), escape_backslash=True
    )
    affinity = get_irq_affinity_list(prog, irq)
    print(f"irq: {irq} name: {name} affinity: {affinity}")


def print_irqs_affinities(prog: Program) -> None:
    """
    Print cpu affinities for all irqs in use.

    :param prog: drgn program

    :return: None
    """
    for irq in for_each_in_use_irq_num(prog):
        if irq_has_action(prog, irq):
            print_irq_affinity(prog, irq)


def print_all_irqs(prog: Program, ignore_zero: bool = False) -> None:
    """
    Print number, name, ``struct irq_desc *`` and current affinity for all irqs in use.

    :param prog: drgn program

    :return: None
    """
    rows: List[List[Any]] = [
        ["IRQ", "NAME", "DESC(struct irq_desc *)", "AFFINITY", "COUNT"]
    ]
    for irq in for_each_in_use_irq_num(prog):
        if irq_has_action(prog, irq):
            desc = irq_to_desc(prog, irq)
            name = escape_ascii_string(
                desc.action.name.string_(), escape_backslash=True
            )
            affinity = get_irq_affinity_list(prog, irq)
            count = _irq_count(prog, irq)
            if count or not ignore_zero:
                rows.append([irq, name, hex(desc.value_()), affinity, count])
    print_table(rows)


class IrqModule(CorelensModule):
    """Print basic IRQ information"""

    name = "irq"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_all_irqs(prog)
