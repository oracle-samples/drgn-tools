# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper to view sysinfo data
"""
import argparse
import datetime
import time
from typing import Any
from typing import Dict

from drgn import Architecture
from drgn import Program
from drgn import ProgramFlags
from drgn.helpers.linux import for_each_task
from drgn.helpers.linux.sched import loadavg
from drgn.helpers.linux.sched import task_state_to_char

from drgn_tools.corelens import CorelensModule
from drgn_tools.cpuinfo import aarch64_get_cpu_info
from drgn_tools.cpuinfo import x86_get_cpu_info
from drgn_tools.mm import totalram_pages
from drgn_tools.table import print_dictionary
from drgn_tools.util import human_bytes
from drgn_tools.virtutil import show_platform


def loadavg_str(prog: Program) -> str:
    """
    Return system load averaged over 1, 5 and 15 minutes as a string.
    """
    load_avg = loadavg(prog)
    return "{:0.2f}  ,  {:0.2f} ,  {:0.2f}".format(
        load_avg[0],
        load_avg[1],
        load_avg[2],
    )


def get_mem(prog: Program) -> str:
    """
    Returns the total memory of the system, as a human-readable string
    """
    total_pages = totalram_pages(prog)
    pagesize = int(prog["PAGE_SIZE"])
    return human_bytes(total_pages * pagesize)


def task_info(prog: Program) -> str:
    """
    Returns the task info of system as a string
    """
    state_count = {"R": 0, "D": 0, "S": 0}
    tasks_count = 0
    for task in for_each_task(prog):
        tasks_count += 1
        state_code = task_state_to_char(task)
        state_count[state_code] = state_count.get(state_code, 0) + 1
    output = f"{tasks_count}"
    for code in ("R", "D", "S"):
        output += f" {code}:{state_count.get(code, 0)}"
        state_count.pop(code)
    for code, count in state_count.items():
        output += f" {code}:{count}"
    return output


def get_sysinfo(prog: Program) -> Dict[str, Any]:
    """
    Helper to get sysinfo of system

    :returns: a dictionary of the sysinfo data
    """
    if ProgramFlags.IS_LIVE in prog.flags:
        mode = "Live kernel"
    else:
        mode = "VMCORE File"
    if "system_utsname" in prog:
        uts = prog["system_utsname"]
    elif "init_uts_ns" in prog:
        uts = prog["init_uts_ns"]
    else:
        raise Exception("error: could not find utsname information")
    timekeeper = prog["shadow_timekeeper"]
    date = time.ctime(timekeeper.xtime_sec)
    uptime = str(datetime.timedelta(seconds=int(timekeeper.ktime_sec)))
    jiffies = int(prog["jiffies"])
    nodename = uts.name.nodename.string_().decode("utf-8")
    release = uts.name.release.string_().decode("utf-8")
    version = uts.name.version.string_().decode("utf-8")
    machine = uts.name.machine.string_().decode("utf-8")
    load_avg = loadavg_str(prog)
    memory = get_mem(prog)
    tasks = task_info(prog)
    platform = show_platform(prog)

    return {
        "MODE": mode,
        "DATE": date,
        "NODENAME": nodename,
        "RELEASE": release,
        "VERSION": version,
        "MACHINE": machine,
        "UPTIME": uptime,
        "LOAD AVERAGE": load_avg,
        "JIFFIES": jiffies,
        "MEMORY": memory,
        "TASKS": tasks,
        "PLATFORM": platform,
    }


def print_sysinfo(prog: Program) -> None:
    """
    Prints the sysinfo of the system
    """
    data_sysinfo = get_sysinfo(prog)
    print_dictionary(data_sysinfo)
    if prog.platform.arch == Architecture.X86_64:
        cpuinfo_data = x86_get_cpu_info(prog)
        if "CPU FLAGS" in cpuinfo_data:
            del cpuinfo_data["CPU FLAGS"]
        if "BUG FLAGS" in cpuinfo_data:
            del cpuinfo_data["BUG FLAGS"]
        print_dictionary(cpuinfo_data)

    elif prog.platform.arch == Architecture.AARCH64:
        cpuinfo_data = aarch64_get_cpu_info(prog)
        print_dictionary(cpuinfo_data)

    else:
        print(f"Not supported for {prog.platform.arch.name}")


class SysInfo(CorelensModule):
    """
    Corelens Module for sysinfo
    """

    name = "sys"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_sysinfo(prog)
