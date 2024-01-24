# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
from typing import Iterable

from _drgn import FaultError
from drgn import Object
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.corelens import CorelensModule
from drgn_tools.module import KernelModule
from drgn_tools.table import print_table


def for_each_module_use(source_list_addr: Object) -> Iterable[Object]:
    """
    Provide the list of ``struct module_use`` as an iterable object

    :param source_list_addr: ``struct module_use.source_list`` Object.
    :returns: A list of ``struct module.source_list`` as an iterable object
    """
    return list_for_each_entry(
        "struct module_use", source_list_addr, "source_list"
    )


def print_module_parameters(prog: Program) -> None:
    """Prints each loaded module and its parameter values"""
    for mod in KernelModule.all(prog):
        print("\n")
        print("MODULE NAME:".ljust(15), mod.name)
        print("PARAM COUNT:", str(mod.obj.num_kp.value_()))
        print("ADDRESS    :", hex(mod.obj.num_kp.address_of_()))
        if not mod.obj.num_kp:
            continue

        table_value = []
        table_value.append(["PARAMETER", "ADDRESS", "TYPE", "VALUE"])
        for name, info in mod.params().items():
            try:
                if info.value is None:
                    formatted = ""
                elif info.type_name == "charp" and not info.value:
                    formatted = "(null)"
                elif info.type_name in ("charp", "string"):
                    formatted = escape_ascii_string(
                        info.value.string_(),
                        escape_double_quote=True,
                        escape_backslash=True,
                    )
                    formatted = f'"{formatted}"'
                elif info.type_name == "bool":
                    formatted = "Y" if info.value else "N"
                else:
                    formatted = info.value.format_(type_name=False)
            except FaultError:
                # As mentioned in decode_param() docstring, a FaultError can
                # occur when a module parameter variable is marked __initdata.
                formatted = "(page fault)"
            table_value.append(
                [
                    name,
                    hex(info.kernel_param.address_of_()),
                    info.type_name,
                    formatted,
                ]
            )
        print_table(table_value)


def print_module_summary(prog: Program) -> None:
    """Print a list of module details and dependencies"""
    # List all loaded modules
    table_value = []
    table_value.append(
        ["MODULE", "NAME", "SIZE", "REF", "DEPENDENDENT MODULES"]
    )
    for mod in KernelModule.all(prog):
        dep_mod = []
        for depuse in for_each_module_use(mod.obj.source_list.address_of_()):
            dep_mod.append(depuse.source.name.string_().decode("utf-8"))
        table_value.append(
            [
                hex(mod.obj.value_()),
                mod.name,
                str(mod.address_region().total_size),
                str(int(mod.obj.refcnt.counter)),
                ",".join(dep_mod),
            ]
        )
    print_table(table_value)


class ListModules(CorelensModule):
    """
    List loaded modules, dependencies and their parameter value.
    """

    name = "lsmod"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_module_summary(prog)
        print_module_parameters(prog)
