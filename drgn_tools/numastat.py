# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for dumping memory usage information for each NUMA node
"""
import argparse
from collections import UserDict
from typing import Dict

from drgn import Object
from drgn import Program

from drgn_tools.corelens import CorelensModule
from drgn_tools.meminfo import for_each_node_zone
from drgn_tools.meminfo import get_active_numa_nodes
from drgn_tools.meminfo import get_mm_constants
from drgn_tools.meminfo import StatDict
from drgn_tools.util import has_member


__all__ = ("show_all_nodes_meminfo", "get_per_node_meminfo")


def get_per_node_mm_stats(prog: Program, node: Object) -> UserDict:
    """
    Read memory statistics counters from ``node.vm_stat`` and each memory
    zone's ``zone.vm_stat`` for the target node. All statistics values are
    stored in a customized dictionary as return.

    :param prog: drgn program
    :param node: ``struct pglist_data *`` of the target NUMA node
    :returns: A dictionary that contains all global statistics items
    """
    stats = StatDict()

    # Add global memory statistics for this node.
    if has_member(node, "vm_stat"):
        arr = node.vm_stat.read_()
        node_stat_enum_obj = prog.type("enum node_stat_item")
        node_stats = StatDict()
        # Skip the last item, which is the length of the array
        for name, value in node_stat_enum_obj.enumerators[:-1]:
            node_stats[name] = max(0, arr[value].counter.value_())
        stats.update(node_stats)

    # Add up all zones' memory statistics for this node.
    all_zones_stats = []
    for zone in for_each_node_zone(prog, node):
        arr = zone.vm_stat.read_()
        zone_stat_enum_obj = prog.type("enum zone_stat_item")
        zone_stats = StatDict()
        # Skip the last item, which is the length of the array
        for name, value in zone_stat_enum_obj.enumerators[:-1]:
            zone_stats[name] = max(0, arr[value].counter.value_())

        try:
            zone_stats[
                "NR_MANAGED_PAGES"
            ] = zone.managed_pages.counter.value_()
        except AttributeError:
            zone_stats["NR_MANAGED_PAGES"] = zone.managed_pages.value_()

        all_zones_stats.append(zone_stats)

    for zone_stats in all_zones_stats:
        for name, value in zone_stats.items():
            if name not in stats:
                stats[name] = value
            else:
                stats[name] += value
    return stats


def get_per_node_meminfo(prog: Program, node: Object) -> Dict[str, int]:
    """
    Collect detailed memory statistics for a NUMA node. Results are expected
    to be similar to outputs produced by node_read_meminfo(...)
    in drivers/base/node.c.

    :param prog: drgn program
    :param node: ``struct pglist_data *`` of the target NUMA node
    :returns: A dictionary that contains all potential memory statistics items.
    """
    mm_stats = {}

    # Read memory statistics and constants.
    mm_consts = get_mm_constants(prog)
    node_zone_stats = get_per_node_mm_stats(prog, node)

    totalram_pages = node_zone_stats["NR_MANAGED_PAGES"]
    freeram_pages = node_zone_stats["NR_FREE_PAGES"]
    # Since 194df9f66db8d ("mm: remove NR_BOUNCE zone stat") in v6.16, NR_BOUNCE
    # is removed from stats and set to zero.
    bounce_pages = node_zone_stats.get("NR_BOUNCE", 0)
    mlocked_pages = node_zone_stats["NR_MLOCK"]

    slab_reclaimable = node_zone_stats["NR_SLAB_RECLAIMABLE"]
    slab_unreclaimable = node_zone_stats["NR_SLAB_UNRECLAIMABLE"]
    lru_active_anon = node_zone_stats["NR_ACTIVE_ANON"]
    lru_inactive_anon = node_zone_stats["NR_INACTIVE_ANON"]
    lru_active_file = node_zone_stats["NR_ACTIVE_FILE"]
    lru_inactive_file = node_zone_stats["NR_INACTIVE_FILE"]
    lru_unevictable = node_zone_stats["NR_UNEVICTABLE"]

    mm_stats["MemTotal"] = totalram_pages
    mm_stats["MemFree"] = freeram_pages
    mm_stats["MemUsed"] = totalram_pages - freeram_pages

    mm_stats["Active"] = lru_active_anon + lru_active_file
    mm_stats["Inactive"] = lru_inactive_anon + lru_inactive_file
    mm_stats["Active(anon)"] = lru_active_anon
    mm_stats["Inactive(anon)"] = lru_inactive_anon
    mm_stats["Active(file)"] = lru_active_file
    mm_stats["Inactive(file)"] = lru_inactive_file
    mm_stats["Unevictable"] = lru_unevictable
    mm_stats["Mlocked"] = mlocked_pages

    # Collect swap meminfo.
    try:
        mm_stats["SwapCached"] = node_zone_stats["NR_SWAPCACHE"]
    except LookupError:
        mm_stats["SwapCached"] = -1
    mm_stats["Dirty"] = node_zone_stats["NR_FILE_DIRTY"]
    mm_stats["Writeback"] = node_zone_stats["NR_WRITEBACK"]
    mm_stats["FilePages"] = node_zone_stats["NR_FILE_PAGES"]
    mm_stats["Mapped"] = node_zone_stats["NR_FILE_MAPPED"]
    mm_stats["AnonPages"] = node_zone_stats["NR_ANON_MAPPED"]
    mm_stats["Shmem"] = node_zone_stats["NR_SHMEM"]

    # Collect slab meminfo.
    try:
        kernel_misc = node_zone_stats["NR_KERNEL_MISC_RECLAIMABLE"]
        mm_stats["KReclaimable"] = slab_reclaimable + kernel_misc
    except LookupError:
        mm_stats["KReclaimable"] = -1
    mm_stats["Slab"] = slab_reclaimable + slab_unreclaimable
    mm_stats["SReclaimable"] = slab_reclaimable
    mm_stats["SUnreclaim"] = slab_unreclaimable

    # Collect other kernel page usage.
    mm_stats["KernelStack"] = node_zone_stats["NR_KERNEL_STACK_KB"] >> (
        mm_consts["PAGE_SHIFT"] - 10
    )
    mm_stats["PageTables"] = node_zone_stats["NR_PAGETABLE"]

    # ebc97a52b5d6c ("mm: add NR_SECONDARY_PAGETABLE to count secondary page
    # table uses.")
    if "NR_SECONDARY_PAGETABLE" in node_zone_stats:
        mm_stats["SecPageTables"] = node_zone_stats["NR_SECONDARY_PAGETABLE"]
    mm_stats["NFS_Unstable"] = 0
    if "NR_UNSTABLE_NFS" in node_zone_stats:
        mm_stats["NFS_Unstable"] = node_zone_stats["NR_UNSTABLE_NFS"]
    mm_stats["Bounce"] = bounce_pages
    # Since commit 8356a5a3b078c ("mm, vmstat: remove the NR_WRITEBACK_TEMP
    # node_stat_item counter") in 6.17, this element is removed and hardcoded
    # zero.
    mm_stats["WritebackTmp"] = node_zone_stats.get("NR_WRITEBACK_TEMP", 0)

    # Collect transparent hugepage meminfo.
    unit = mm_consts["TRANS_HPAGE_UNIT"]
    if "NR_ANON_THPS" in node_zone_stats:
        mm_stats["AnonHugePages"] = node_zone_stats["NR_ANON_THPS"] * unit
        mm_stats["ShmemHugePages"] = node_zone_stats["NR_SHMEM_THPS"] * unit
        mm_stats["ShmemPmdMapped"] = (
            node_zone_stats["NR_SHMEM_PMDMAPPED"] * unit
        )
        try:
            mm_stats["FileHugePages"] = node_zone_stats["NR_FILE_THPS"] * unit
        except LookupError:
            mm_stats["FileHugePages"] = -1
        try:
            mm_stats["FilePmdMapped"] = node_zone_stats["NR_FILE_PMDMAPPED"]
        except LookupError:
            mm_stats["FilePmdMapped"] = -1
    else:
        mm_stats["AnonHugePages"] = (
            node_zone_stats["NR_ANON_TRANSPARENT_HUGEPAGES"] * unit
        )
        mm_stats["ShmemHugePages"] = -1
        mm_stats["ShmemPmdMapped"] = -1
        mm_stats["FileHugePages"] = -1
        mm_stats["FilePmdMapped"] = -1

    # dcdfdd40fa82b ("mm: Add support for unaccepted memory")
    if "NR_UNACCEPTED" in node_zone_stats:
        mm_stats["Unaccepted"] = node_zone_stats["NR_UNACCEPTED"]

    # Collect hugepage info for the default hugepage size in this node.
    node_id = node.node_id.value_()
    hstate = prog["hstates"][prog["default_hstate_idx"]]
    mm_stats["HugePages_Total"] = hstate.nr_huge_pages_node[node_id].value_()
    mm_stats["HugePages_Free"] = hstate.free_huge_pages_node[node_id].value_()
    mm_stats["HugePages_Surp"] = hstate.surplus_huge_pages_node[
        node_id
    ].value_()
    return mm_stats


def show_all_nodes_meminfo(prog: Program) -> None:
    """
    Dump various details about the memory subsystem for each NUMA node.
    This function must parse machine info to determine arch-specific parameters
    before parsing per-node memory statistics.

    :param prog: drgn program
    """
    # A list of all mm statistics items in numastat
    node_meminfo_items = [
        "MemTotal",
        "MemFree",
        "MemUsed",
        "Active",
        "Inactive",
        "Active(anon)",
        "Inactive(anon)",
        "Active(file)",
        "Inactive(file)",
        "Unevictable",
        "Mlocked",
        "Dirty",
        "Writeback",
        "FilePages",
        "Mapped",
        "AnonPages",
        "Shmem",
        "KernelStack",
        "PageTables",
        "NFS_Unstable",
        "Bounce",
        "WritebackTmp",
        "KReclaimable",
        "Slab",
        "SReclaimable",
        "SUnreclaim",
        "AnonHugePages",
        "ShmemHugePages",
        "ShmemPmdMapped",
        "FileHugePages",
        "FilePmdMapped",
        "HugePages_Total",
        "HugePages_Free",
        "HugePages_Surp",
    ]

    # Collect mm statistics from all active NUMA nodes
    per_node_meminfo = []
    active_nodes = get_active_numa_nodes(prog)
    num_active_nodes = len(active_nodes)
    for node in active_nodes:
        node_mm_stats = get_per_node_meminfo(prog, node)
        per_node_meminfo.append(node_mm_stats)

    # Output
    print("Per-node system memory usage (in MBs):")

    node_name_line = "                "
    for i in range(num_active_nodes):
        node_name = f"Node {i}"
        node_name_line += f"{node_name: >16}"
    node_name_line += f"{'Total': >16}"
    print(node_name_line)
    print("                " + " ---------------" * (num_active_nodes + 1))

    page_to_mb = prog.constant("PAGE_SIZE").value_() / (1024 * 1024)
    for mm_item in node_meminfo_items:
        should_skip = any(
            [node_stats[mm_item] < 0 for node_stats in per_node_meminfo]
        )
        if should_skip:
            continue

        curr_line = f"{mm_item: <16}"
        sum_node_stats_mb = 0
        for node_stats in per_node_meminfo:
            num_mb = node_stats[mm_item] * page_to_mb
            sum_node_stats_mb += num_mb
            curr_line += f"{num_mb: >16.2f}"

        # Add a column that sums mm items from all NUMA nodes
        curr_line += f"{sum_node_stats_mb: >16.2f}"
        print(curr_line)


class NumastatModule(CorelensModule):
    """
    Show various details about the memory management subsystem for all
    active NUMA nodes in the system.
    """

    name = "numastat"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        # Dump meminfo-like statistics for each NUMA node
        show_all_nodes_meminfo(prog)
