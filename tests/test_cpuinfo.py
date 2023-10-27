# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn import ProgramFlags

from drgn_tools import cpuinfo


def test_cpuinfo(prog):
    cpuinfo.print_cpu_info(prog)

    if not (ProgramFlags.IS_LIVE & prog.flags) or not (
        prog["init_uts_ns"].name.machine.string_().decode("utf-8") == "x86_64"
    ):
        return

    file = open("/proc/cpuinfo", "r")
    lines = file.readlines()
    cpu_data_from_proc = dict()
    for line in lines:
        try:
            title, value = line.split(":")
            title, value = title.strip(), value.strip()
            cpu_data_from_proc[title] = value
        except Exception:
            continue

    cpu_data_from_corelens = cpuinfo.x86_get_cpu_info(prog)

    assert (
        cpu_data_from_corelens["CPU VENDOR"] == cpu_data_from_proc["vendor_id"]
    )
    assert (
        cpu_data_from_corelens["MODEL NAME"]
        == cpu_data_from_proc["model name"]
    )
    assert (
        str(cpu_data_from_corelens["CPU FAMILY"])
        == cpu_data_from_proc["cpu family"]
    )
    if "microcode" in cpu_data_from_proc:
        assert (
            str(cpu_data_from_corelens["MICROCODE"])
            == cpu_data_from_proc["microcode"]
        )
    assert cpu_data_from_corelens["CSTATES"] == prog["max_cstate"]
    assert cpu_data_from_corelens["CPU FLAGS"] == cpu_data_from_proc["flags"]
    assert cpu_data_from_corelens["BUG FLAGS"] == cpu_data_from_proc["bugs"]
