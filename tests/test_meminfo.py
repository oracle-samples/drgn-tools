# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn
from drgn import ProgramFlags

from drgn_tools import meminfo


def test_meminfo(prog):
    meminfo.show_all_meminfo(prog)

    if not (ProgramFlags.IS_LIVE & prog.flags):
        return

    page_shift = prog.constant("PAGE_SHIFT").value_()

    # Get mm statistics from the live vmcore.
    corelens_mm_stats = meminfo.get_all_meminfo(prog)

    # Parse mm statistics from /proc/meminfo.
    proc_mm_stats = {}
    f = open("/proc/meminfo", "r")
    lines = f.readlines()
    for line in lines:
        try:
            key, value = line.split(":")
            key, value = key.strip(), value.strip()
            if "kB" in value:
                value = int(value[:-2].strip())
            proc_mm_stats[key] = value
        except Exception:
            continue

    if prog.platform.arch == drgn.Architecture.X86_64:
        test_exact_match_mm_stats = [
            "MemTotal",
            "SwapTotal",
            "CommitLimit",
            "VmallocTotal",
            "CmaTotal",
        ]
    elif prog.platform.arch == drgn.Architecture.AARCH64:
        test_exact_match_mm_stats = [
            "MemTotal",
            "SwapTotal",
            "CommitLimit",
            "CmaTotal",
        ]
    else:
        raise Exception("Target vmcore's architecture is not supported.")

    # These meminfo statistics in ``corelens_mm_stats`` are in kB
    mm_stats_in_kb = ["KernelStack", "VmallocTotal", "HardwareCorrupted"]

    for item in test_exact_match_mm_stats:
        if item not in proc_mm_stats:
            assert item not in corelens_mm_stats
        else:
            assert item in corelens_mm_stats

            if item in mm_stats_in_kb:
                val_kb = corelens_mm_stats[item]
            else:
                val_kb = corelens_mm_stats[item] << (page_shift - 10)
            assert val_kb == proc_mm_stats[item]
