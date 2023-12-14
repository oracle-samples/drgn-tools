# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
from typing import Iterable
from typing import List

from _drgn import FaultError
from drgn import cast
from drgn import Object
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.corelens import CorelensModule
from drgn_tools.module import KernelModule
from drgn_tools.table import print_table

_MOD_INTEGER_PARAMS = {
    "byte": "unsigned char *",
    "short": "short *",
    "ushort": "unsigned short *",
    "int": "int *",
    "uint": "unsigned int *",
    "long": "long *",
    "ulong": "unsigned long *",
}


def for_each_module_use(source_list_addr: Object) -> Iterable[Object]:
    """
    Provide the list of ``struct module_use`` as an iterable object

    :param source_list_addr: ``struct module_use.source_list `` Object.
    :returns: A list of ``struct module.source_list`` as an iterable object
    """
    return list_for_each_entry(
        "struct module_use", source_list_addr, "source_list"
    )


def print_module_parameters(prog: Program) -> None:
    """
    Provide the list of ``module parameters`` as an iterable object

    :param prog: drgn program.
    :returns: None
    """

    # Module details
    for mod in KernelModule.all(prog):
        print("\n")
        print("MODULE NAME:".ljust(15), mod.name)
        print("PARAM COUNT:", str(mod.obj.num_kp.value_()))
        print("ADDRESS    :", hex(mod.obj.num_kp.address_of_()))
        table_value = []
        table_value.append(["PARAMETER", "ADDRESS", "TYPE", "VALUE"])
        for i in range(0, mod.obj.num_kp):
            parm_valf = ""
            parm_val = ""
            kp = mod.obj.kp[i]
            try:
                param_type = prog.symbol(kp.ops.get).name
            except LookupError:
                table_value.append(
                    [
                        kp.name.string_().decode("utf-8"),
                        str(hex(kp.address_of_())),
                        "UNKNOWN",
                        "UNKNOWN",
                    ]
                )
                continue

            if param_type.startswith("param_get_"):
                param_type = param_type[len("param_get_") :]
                if param_type in _MOD_INTEGER_PARAMS:
                    parm_valf_address = cast(
                        _MOD_INTEGER_PARAMS[param_type], kp.arg
                    )
                    try:
                        parm_valf = parm_valf_address[0].value_()
                    except FaultError:
                        parm_valf = "(page fault)"
                elif "bool" in param_type:
                    param_type = "bool"
                    parm_valf_address = cast("bool *", kp.arg)
                    parm_val = Object(
                        prog, "bool", address=parm_valf_address.value_()
                    ).value_()
                    if parm_val == 1:
                        parm_valf = "Y"
                    else:
                        parm_valf = "N"
                elif "charp" in param_type:
                    param_type = "charp"
                    value = Object(prog, "char **", value=kp.arg)
                    if value[0]:
                        parm_valf = escape_ascii_string(value[0].string_())
                    else:
                        parm_valf = "(null)"
                elif "string" in param_type:
                    param_type = "string"
                    try:
                        if escape_ascii_string(kp.str.string.string_()):
                            parm_valf = escape_ascii_string(
                                kp.str.string.string_()
                            )
                        else:
                            parm_valf = "(null)"
                    except FaultError:
                        parm_valf = "(page fault)"
            elif "array" in param_type:
                param_type = "array"
                parm_valf = f"array_length: {int(kp.arr.max)}"
            table_value.append(
                [
                    str(kp.name.string_().decode("utf-8")),
                    str(hex(kp.address_of_())),
                    param_type,
                    str(parm_valf),
                ]
            )
        print_table(table_value)


def get_module_summary(prog: Program) -> List[List[str]]:
    """
    Provide the list of ``module details and dependencies`` as an iterable object
    :returns: Nested list of ``module details and dependencies`` as an iterable object
    """
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
    return table_value


def print_module_summary(prog: Program) -> None:
    print_mod = get_module_summary(prog)
    print_table(print_mod)


class ListModules(CorelensModule):
    """
    List loaded modules, dependencies and their parameter value.
    """

    name = "lsmod"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_module_summary(prog)
        print_module_parameters(prog)
