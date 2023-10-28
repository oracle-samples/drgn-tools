# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn import Architecture
from drgn import ProgramFlags

from drgn_tools import cpuinfo


def test_cpuinfo(prog):
    cpuinfo.print_cpu_info(prog)

    if not (ProgramFlags.IS_LIVE & prog.flags):
        return

    if (
        prog.platform.arch == Architecture.X86_64
        or prog.platform.arch == Architecture.AARCH64
    ):
        file = open("/proc/cpuinfo", "r")
        lines = file.readlines()
        file.close()
        cpu_data_from_proc = dict()
        for line in lines:
            try:
                title, value = line.split(":")
                title, value = title.strip(), value.strip()
                cpu_data_from_proc[title] = value
            except Exception:
                continue

    if prog.platform.arch == Architecture.X86_64:
        cpu_data_from_corelens = cpuinfo.x86_get_cpu_info(prog)

        assert (
            cpu_data_from_corelens["CPU VENDOR"]
            == cpu_data_from_proc["vendor_id"]
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
        assert (
            cpu_data_from_corelens["CPU FLAGS"] == cpu_data_from_proc["flags"]
        )
        assert (
            cpu_data_from_corelens["BUG FLAGS"] == cpu_data_from_proc["bugs"]
        )

    if prog.platform.arch == Architecture.AARCH64:
        cpu_data_from_corelens = cpuinfo.aarch64_get_cpu_info(prog)
        assert (
            cpu_data_from_corelens["Features"]
            == cpu_data_from_proc["Features"]
        )
        assert (
            cpu_data_from_corelens["CPU Implementer"]
            == cpu_data_from_proc["CPU implementer"]
        )
        assert (
            str(cpu_data_from_corelens["CPU Architecture"])
            == cpu_data_from_proc["CPU architecture"]
        )
        assert (
            cpu_data_from_corelens["CPU Variant"]
            == cpu_data_from_proc["CPU variant"]
        )
        assert (
            cpu_data_from_corelens["CPU Part"]
            == cpu_data_from_proc["CPU part"]
        )
        assert (
            str(cpu_data_from_corelens["CPU Revision"])
            == cpu_data_from_proc["CPU revision"]
        )
