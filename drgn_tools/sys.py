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

from drgn_tools.corelens import CorelensModule
from drgn_tools.cpuinfo import aarch64_get_cpu_info
from drgn_tools.cpuinfo import x86_get_cpu_info
from drgn_tools.mm import totalram_pages
from drgn_tools.table import print_dictionary
from drgn_tools.util import human_bytes


def load_average(prog: Program) -> str:
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
    task_running = 0
    task_int = 0
    task_unint = 0
    tasks_count = prog["nr_cpu_ids"]
    for task in for_each_task(prog):
        tasks_count += 1
        try:
            if prog.type("struct task_struct").has_member("__state"):
                task_state = task.__state
            else:
                task_state = task.state
        except LookupError:
            task_state = task.__state
        if task_state == 0:
            task_running += 1
        elif task_state == 1:
            task_int += 1
        elif task_state == 2:
            task_unint += 1
    return f"{int(tasks_count)} [R:{task_running} D:{task_unint} S:{task_int}]"


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
    load_avg = load_average(prog)
    memory = get_mem(prog)
    tasks = task_info(prog)
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

