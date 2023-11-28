# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn import ProgramFlags

from drgn_tools import meminfo
from drgn_tools import numastat


def test_numastat(prog):
    numastat.show_all_nodes_meminfo(prog)


def test_numastat_all_nodes_meminfo(prog):
    if not (ProgramFlags.IS_LIVE & prog.flags):
        return

    page_shift = prog.constant("PAGE_SHIFT").value_()
    numastat_per_node_mm_stats = []
    active_nodes = meminfo.get_active_numa_nodes(prog)
    num_active_nodes = len(active_nodes)

    for node in active_nodes:
        node_mm_stats = numastat.get_per_node_meminfo(prog, node)
        numastat_per_node_mm_stats.append(node_mm_stats)

    sys_fs_per_node_mm_stats = []
    # Parse mm statistics from /sys/devices/system/node/node*/meminfo.
    for node_id in range(num_active_nodes):
        sys_fs_mm_stats = {}

        f = open(f"/sys/devices/system/node/node{node_id}/meminfo", "r")
        lines = f.readlines()
        for line in lines:
            try:
                key, value = line.split(":")
                key, value = key.strip(), value.strip()
                if "Node" in key:
                    key = key.split(" ")[-1].strip()
                if "kB" in value:
                    value = int(value[:-2].strip())
                else:
                    value = int(value)
                sys_fs_mm_stats[key] = value
            except Exception:
                continue

        sys_fs_per_node_mm_stats.append(sys_fs_mm_stats)

    for node_id in range(num_active_nodes):
        sys_fs_mm_stats = sys_fs_per_node_mm_stats[node_id]
        numastat_mm_stats = numastat_per_node_mm_stats[node_id]

        for name, value in sys_fs_mm_stats.items():
            assert name in numastat_mm_stats

            # The result in sys fs is in kB.
            if name == "MemTotal":
                numastat_value_kb = numastat_mm_stats[name] << (
                    page_shift - 10
                )
                assert value == numastat_value_kb

            # The result in sys fs is in number of pages.
            if name == "HugePages_Total":
                assert value == numastat_mm_stats[name]
