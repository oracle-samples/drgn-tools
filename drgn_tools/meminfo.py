# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for dumping memory usage information and statistics
"""
import argparse
import math
from collections import UserDict
from typing import Dict
from typing import Iterator
from typing import List

import drgn
from drgn import Object
from drgn import Program
from drgn.helpers.linux import list_for_each_entry
from drgn.helpers.linux.boot import pgtable_l5_enabled
from drgn.helpers.linux.percpu import percpu_counter_sum

from drgn_tools.corelens import CorelensModule
from drgn_tools.mm import totalram_pages
from drgn_tools.util import has_member


__all__ = ("show_all_meminfo", "get_all_meminfo")


class StatDict(UserDict):
    """A dictionary wrapper class to handle renaming of statistics items."""

    renames = {
        "NR_SLAB_RECLAIMABLE": "NR_SLAB_RECLAIMABLE_B",
        "NR_SLAB_UNRECLAIMABLE": "NR_SLAB_UNRECLAIMABLE_B",
        "NR_ANON_MAPPED": "NR_ANON_PAGES",
        "NR_KERNEL_STACK_KB": "NR_KERNEL_STACK",
    }

    def __getitem__(self, key):
        """
        Some global statistics items's names was changed in the past. This
        overwrites the default __getitem__ function to correct name for these.
        """
        if key in self.renames and key not in self.data:
            key = self.renames[key]
        return super().__getitem__(key)


def _read_stats(prog: Program, arr_name: str, enum: str) -> UserDict:
    """
    Read counters from a global statistics array with name ``arr_name``.
    Parse all statistics items that are indexed by ``enum`` and store results
    in a dictionary.

    :param prog: drgn program
    :param arr_name: The global statistics array's variable name
    :param enum: The global statistics array's corresponding enum type
    :returns: A dictionary that contains all statistics items in the array
    """
    arr = prog[arr_name].read_()
    enum_obj = prog.type(enum)
    stats = StatDict()
    # Skip the last item, which is the length of the array
    for name, value in enum_obj.enumerators[:-1]:
        stats[name] = max(0, arr[value].counter.value_())
    return stats


def get_global_mm_stats(prog) -> UserDict:
    """
    Read counters from ``vm_zone_stat``, ``vm_node_stat``, and ``vm_numa_stat``
    for global zone/node page statistics. All statistics values are stored in
    a customized dictionary, as this function's return.

    :param prog: drgn program
    :returns: A dictionary that contains all global statistics items
    """
    try:
        stats = _read_stats(prog, "vm_zone_stat", "enum zone_stat_item")
    except KeyError:
        stats = _read_stats(prog, "vm_stat", "enum zone_stat_item")
    try:
        node_stat = _read_stats(prog, "vm_node_stat", "enum node_stat_item")
        stats.update(node_stat)
    except KeyError:
        pass
    try:
        numa_stat = _read_stats(prog, "vm_numa_stat", "enum numa_stat_item")
        stats.update(numa_stat)
    except KeyError:
        pass
    return stats


def get_mm_constants(prog: Program) -> Dict[str, int]:
    """
    Parse the systemwise and architecture-specific parameters that are relevant
    to the kernel's memory subsystem. Results are cached in a dictionary.

    :param prog: drgn program
    :returns: A dictionary that contains relevant systemwise parameters
    """
    cache = prog.cache.setdefault("drgn_tools.meminfo", {})
    mm_consts = cache.get("mm_constants", {})
    if not mm_consts:
        mm_consts = {}

        # Determine max numbers of NUMA nodes and memory zones in a node.
        # In mm/mempolicy.c, ``preferred_node_policy`` is defined as the following:
        # "static struct mempolicy preferred_node_policy[MAX_NUMNODES];"
        # Also, ``MAX_NUMNODES`` equals to (1 << NODES_SHIFT).
        mm_consts["MAX_NUM_NODES"] = len(prog["preferred_node_policy"])
        mm_consts["NODES_SHIFT"] = int(math.log2(mm_consts["MAX_NUM_NODES"]))
        mm_consts["MAX_NUM_ZONES"] = prog["__MAX_NR_ZONES"].value_()

        # Determine page size
        mm_consts["PAGE_SIZE"] = prog.constant("PAGE_SIZE").value_()
        mm_consts["PAGE_SHIFT"] = prog.constant("PAGE_SHIFT").value_()

        # Determine architecture-specific parameters
        if prog.platform.arch == drgn.Architecture.X86_64:
            # arch/x86/include/asm/pgtable_64_types.h
            _pmd_shift = 21
            if "vmalloc_base" in prog:
                _vmalloc_size_tb = 12800 if pgtable_l5_enabled(prog) else 32
                mm_consts["VMALLOC_START"] = prog["vmalloc_base"].value_()
                mm_consts["VMALLOC_END"] = (
                    mm_consts["VMALLOC_START"] + (_vmalloc_size_tb << 40) - 1
                )
            else:
                mm_consts["VMALLOC_START"] = 0xFFFFC90000000000
                mm_consts["VMALLOC_END"] = 0xFFFFE8FFFFFFFFFF
        elif prog.platform.arch == drgn.Architecture.AARCH64:
            # arch/arm64/include/asm/pgtable-hwdef.h
            n = 2
            _pmd_shift = (mm_consts["PAGE_SHIFT"] - 3) * (4 - (n)) + 3
        else:
            raise Exception("Target vmcore's architecture is not supported.")

        _hpage_pmd_shift = _pmd_shift
        _hpage_pmd_order = _hpage_pmd_shift - mm_consts["PAGE_SHIFT"]
        mm_consts["HPAGE_PMD_NR"] = 1 << _hpage_pmd_order

        # The vm statistics items for transparent hugepages may be counted
        # in hugepages or in pages (since latest kernels). This commit
        # (ID: 69473e5de87389be6c0fa4a5d574a50c8f904fb3) changed the unit from
        # hugepages to pages and updates ``memory_stats`` to reflect it.
        try:
            unit = 1
            for item in prog["memory_stats"]:
                if item.name.string_().decode("utf-8") == "anon_thp":
                    # If ``ratio`` exists and does not equal to PAGE_SIZE, the
                    # unit is in hugepages. After the above commit, ``ratio``
                    # was changed to 1 (page). Later, the ``ratio`` column was
                    # removed because all statistics have the same unit.
                    if (
                        has_member(item, "ratio")
                        and item.ratio.value_() != mm_consts["PAGE_SIZE"]
                    ):
                        unit = mm_consts["HPAGE_PMD_NR"]
                        break
        except KeyError:
            unit = mm_consts["HPAGE_PMD_NR"]
        mm_consts["TRANS_HPAGE_UNIT"] = unit

        # Determine the max number of swap file types.
        # In mm/swap_state.c, ``nr_swapper_spaces`` is defined as:
        # "static unsigned int nr_swapper_spaces[MAX_SWAPFILES] __read_mostly;"
        if "nr_swapper_spaces" in prog:
            mm_consts["MAX_SWAPFILES"] = len(prog["nr_swapper_spaces"])
        else:
            # "nr_swapper_spaces" does not exist in UEK-4.
            mm_consts["MAX_SWAPFILES"] = len(prog["swapper_spaces"])

        # Save ``mm_consts`` to cache.
        cache["mm_constants"] = mm_consts
    return mm_consts


def print_val_kb(prog: Program, text: str, num: int) -> None:
    """
    Produce the formatted output that matches the output in /proc/meminfo.

    :param prog: drgn program
    :param text: The output item's name, e.g, "MemTotal"
    :param num: The output item's value
    """
    if num < 0:
        return

    num_kb = num << (get_mm_constants(prog)["PAGE_SHIFT"] - 10)
    num_kb_str = str(num_kb)
    print(f"{text + ':': <15} {num_kb_str: >8} kB")


def get_active_numa_nodes(prog: Program) -> List[Object]:
    """
    Get a list of all active NUMA nodes.

    :returns: a list of ``struct pglist_data *`` objects.
    """
    active_numa_nodes = []
    node_data = prog["node_data"]
    for i in range(get_mm_constants(prog)["MAX_NUM_NODES"]):
        if node_data[i].value_() != 0x0:
            active_numa_nodes.append(node_data[i])
    return active_numa_nodes


def for_each_node_zone(prog: Program, node: Object) -> Iterator[Object]:
    """
    Iterate over all memory zones in a NUMA node.

    :param prog: drgn program
    :param node: The drgn object of a NUMA node's ``struct pglist_data``.
    :returns: Iterator of ``struct zone`` objects.
    """
    node_zones = node.node_zones
    for j in range(node.nr_zones):
        yield node_zones[j]


def for_each_zone(prog: Program) -> Iterator[Object]:
    """
    Iterate over all zones in a system that contains 1+ NUMA nodes.

    :returns: Iterator of ``struct zone *`` objects.
    """
    for node in get_active_numa_nodes(prog):
        for zone in for_each_node_zone(prog, node):
            yield zone


def for_each_hstate(prog: Program) -> Iterator[Object]:
    """
    Iterate over all hugepage pools in a system.
    Note: each |hstate| represents a pool for a certain unit size hugepages of a NUMA node.

    :returns: Iterator of ``struct hstate`` objects.
    """
    hstates = prog["hstates"].read_()
    for i in range(prog["hugetlb_max_hstate"].value_()):
        yield hstates[i]


def get_total_available_pages(prog: Program) -> int:
    """
    Get an estimation of the amount of memory available for future use.
    This includes the number of free memory pages and the number of pages
    that can be reclaimed from caches.

    :returns: The number of available memory in pages.
    """
    global_stats = get_global_mm_stats(prog)

    total_free_pages = global_stats["NR_FREE_PAGES"]
    total_reserve_pages = prog["totalreserve_pages"].value_()
    available_pages = total_free_pages - total_reserve_pages

    # Calculate the global low watermark.
    low_wmark = 0
    for zone in for_each_zone(prog):
        if has_member(zone, "_watermark"):
            zone_low_wmark = zone._watermark[prog.constant("WMARK_LOW")]
        else:
            zone_low_wmark = zone.watermark[prog.constant("WMARK_LOW")]
        low_wmark += zone_low_wmark.value_()

    # Estimate reclaimable page cache.
    lru_active_file = global_stats["NR_ACTIVE_FILE"]
    lru_inactive_file = global_stats["NR_INACTIVE_FILE"]
    pagecache = lru_active_file + lru_inactive_file
    pagecache -= min(pagecache // 2, low_wmark)
    available_pages += pagecache

    # Determine the number of reclaimable pages.
    reclaimable_pages = 0

    # First, slab cache can be reclaimed.
    slab_reclaimable = global_stats["NR_SLAB_RECLAIMABLE"]
    reclaimable_pages += slab_reclaimable

    # Then, count reclaimable kernel pages.
    if "NR_KERNEL_MISC_RECLAIMABLE" in global_stats:
        misc = global_stats["NR_KERNEL_MISC_RECLAIMABLE"]
        reclaimable_pages += misc

    reclaimable_pages -= min(reclaimable_pages // 2, low_wmark)
    available_pages += reclaimable_pages

    # Finally, add indirectly reclaimable kernel memory.
    if "NR_INDIRECTLY_RECLAIMABLE_BYTES" in global_stats:
        page_shift = prog.constant("PAGE_SHIFT").value_()
        indirect_reclaimable_pages = (
            global_stats["NR_INDIRECTLY_RECLAIMABLE_BYTES"] >> page_shift
        )
        available_pages += indirect_reclaimable_pages

    available_pages = max(0, available_pages)
    return available_pages


def get_total_swap_cache_pages(prog: Program) -> int:
    """
    Get the total number of cached swap pages for all swap types.

    :returns: The number of cached memory back by swap space in pages.
    """
    ret = 0

    global_stats = get_global_mm_stats(prog)
    if "NR_SWAPCACHE" in global_stats:
        # UEK7 and RHCK kernels may maintains a specific per-node
        # statistics item "NR_SWAPCACHE" for tracking the total swap
        # cache pages. In such cases, return the counter directly.
        ret = global_stats.get("NR_SWAPCACHE", 0)
    else:
        max_swapfile_types = get_mm_constants(prog)["MAX_SWAPFILES"]
        swapper_spaces = prog["swapper_spaces"]

        if "nr_swapper_spaces" in prog:
            nr_swapper_spaces = prog["nr_swapper_spaces"]
            for i in range(max_swapfile_types):
                nr = nr_swapper_spaces[i]
                spaces = swapper_spaces[i]
                if nr == 0 or spaces.value_() == 0x0:
                    continue
                for j in range(nr):
                    ret += spaces[j].nrpages.value_()
        else:
            for i in range(max_swapfile_types):
                ret += swapper_spaces[i].nrpages.value_()
    return ret


def get_block_dev_pages(prog: Program) -> int:
    """Get the sum of (4 kB) memory pages used by all block devices."""
    ret = 0
    if "all_bdevs" in prog:
        for bdev in list_for_each_entry(
            "struct block_device", prog["all_bdevs"].address_of_(), "bd_list"
        ):
            inode = bdev.bd_inode
            ret += inode.i_mapping.nrpages.value_()
    else:
        for inode in list_for_each_entry(
            "struct inode",
            prog["blockdev_superblock"].s_inodes.address_of_(),
            "i_sb_list",
        ):
            ret += inode.i_mapping.nrpages.value_()
    return ret


def get_total_hugetlb_pages(prog: Program) -> int:
    """Get sum of (4 kB) memory pages from all hstate hugepage pools."""
    ret = 0
    for h in for_each_hstate(prog):
        pages_per_hugepage = 1 << (h.order.value_())
        ret += h.nr_huge_pages.value_() * pages_per_hugepage
    return ret


def get_vm_commit_limit(prog: Program) -> int:
    """
    Get the total amount of memory (in pages) available to be allocated on the
    system. Linux kernel may overcommit (i.e., allocating more than the amount
    of physical memory). The result should consider |overcommit_kbytes| or
    |overcommit_ratio|.
    """
    allowed = 0
    total_pages = totalram_pages(prog).value_()
    total_swap_pages = prog["total_swap_pages"].value_()
    overcommit_kbytes = prog["sysctl_overcommit_kbytes"].value_()
    overcommit_ratio = prog["sysctl_overcommit_ratio"].value_()

    if overcommit_kbytes:
        allowed = overcommit_kbytes >> (
            get_mm_constants(prog)["PAGE_SHIFT"] - 10
        )
    else:
        hugetlb_pages = get_total_hugetlb_pages(prog)
        allowed = (total_pages - hugetlb_pages) * overcommit_ratio // 100
    allowed += total_swap_pages
    return allowed


def show_hugetlb_meminfo(prog: Program) -> None:
    """Dump memory information for hugepages."""
    # Get statistics for the default hugepage
    hstate = prog["hstates"][prog["default_hstate_idx"]]

    nr_hugepages = hstate.nr_huge_pages.value_()
    free_hugepages = hstate.free_huge_pages.value_()
    resv_hugepages = hstate.resv_huge_pages.value_()
    surplus_hugepages = hstate.surplus_huge_pages.value_()
    default_hugepage_order = hstate.order.value_()
    default_hugepage_size = 1 << (
        default_hugepage_order + get_mm_constants(prog)["PAGE_SHIFT"] - 10
    )

    # Sum the amount of memory (in kB) consumed by hugepages of all sizes.
    total_hugepage_memory = 0
    for h in for_each_hstate(prog):
        count = h.nr_huge_pages.value_()
        order = h.order.value_()
        total_hugepage_memory += count * (
            get_mm_constants(prog)["PAGE_SIZE"] << order
        )

    print("HugePages_Total:   %5d" % (nr_hugepages))
    print("HugePages_Free:    %5d" % (free_hugepages))
    print("HugePages_Rsvd:    %5d" % (resv_hugepages))
    print("HugePages_Surp:    %5d" % (surplus_hugepages))
    print("Hugepagesize:   %8d kB" % (default_hugepage_size))
    print("Hugetlb:        %8d kB" % (total_hugepage_memory / 1024))


def show_arch_meminfo(prog: Program) -> None:
    """Dump numbers of pages mapped for supported page sizes."""
    if prog.platform.arch == drgn.Architecture.AARCH64:
        return

    direct_pages_count = prog["direct_pages_count"].read_()
    direct_4k = direct_pages_count[prog.constant("PG_LEVEL_4K")].value_()
    direct_2m = direct_pages_count[prog.constant("PG_LEVEL_2M")].value_()

    print("DirectMap4k:    %8d kB" % (direct_4k << 2))
    print("DirectMap2M:    %8d kB" % (direct_2m << 11))

    if prog["direct_gbpages"].value_() != 0:
        direct_1g = direct_pages_count[prog.constant("PG_LEVEL_1G")].value_()
        print("DirectMap1G:    %8d kB" % (direct_1g << 20))


def get_all_meminfo(prog: Program) -> Dict[str, int]:
    """
    Collect detailed memory statistics items that match /proc/meminfo.

    :returns: A dictionary that contains relevant memory statistics items.
    """
    # Read global statistics |vm_zone_stat|, |vm_node_stat|, and |vm_numa_stat|.
    mm_consts = get_mm_constants(prog)
    global_stats = get_global_mm_stats(prog)

    stats = {}

    # Collect basic meminfo
    stats["MemTotal"] = totalram_pages(prog).value_()
    stats["MemFree"] = global_stats["NR_FREE_PAGES"]
    stats["MemAvailable"] = get_total_available_pages(prog)

    file_pages = global_stats["NR_FILE_PAGES"]
    swap_cache_pages = get_total_swap_cache_pages(prog)
    buffer_pages = get_block_dev_pages(prog)
    stats["Buffers"] = buffer_pages
    stats["Cached"] = max(0, file_pages - swap_cache_pages - buffer_pages)
    stats["SwapCached"] = swap_cache_pages

    # Collect numbers of pages in all LRU lists
    lru_inactive_anon = global_stats["NR_INACTIVE_ANON"]
    lru_active_anon = global_stats["NR_ACTIVE_ANON"]
    lru_inactive_file = global_stats["NR_INACTIVE_FILE"]
    lru_active_file = global_stats["NR_ACTIVE_FILE"]
    lru_unevictable = global_stats["NR_UNEVICTABLE"]

    stats["Active"] = lru_active_anon + lru_active_file
    stats["Inactive"] = lru_inactive_anon + lru_inactive_file
    stats["Active(anon)"] = lru_active_anon
    stats["Inactive(anon)"] = lru_inactive_anon
    stats["Active(file)"] = lru_active_file
    stats["Inactive(file)"] = lru_inactive_file
    stats["Unevictable"] = lru_unevictable
    stats["Mlocked"] = global_stats["NR_MLOCK"]

    # Collect swap meminfo
    nr_to_be_unused = 0
    nr_swapfiles = prog["nr_swapfiles"].value_()
    for i in range(nr_swapfiles):
        si = prog["swap_info"][i]
        si_swp_used = si.flags.value_() & prog["SWP_USED"].value_()
        si_swp_writeok = si.flags.value_() & prog["SWP_WRITEOK"].value_()
        if si_swp_used and not si_swp_writeok:
            nr_to_be_unused += si.inuse_pages.value_()

    stats["SwapTotal"] = prog["total_swap_pages"].value_() + nr_to_be_unused
    stats["SwapFree"] = (
        prog["nr_swap_pages"].counter.value_() + nr_to_be_unused
    )
    stats["Dirty"] = global_stats["NR_FILE_DIRTY"]
    stats["Writeback"] = global_stats["NR_WRITEBACK"]
    stats["AnonPages"] = global_stats["NR_ANON_MAPPED"]
    stats["Mapped"] = global_stats["NR_FILE_MAPPED"]
    stats["Shmem"] = global_stats["NR_SHMEM"]

    # Collect slab meminfo
    slab_reclaimable_pages = global_stats["NR_SLAB_RECLAIMABLE"]
    slab_unreclaimable_pages = global_stats["NR_SLAB_UNRECLAIMABLE"]
    try:
        kernel_misc = global_stats["NR_KERNEL_MISC_RECLAIMABLE"]
        stats["KReclaimable"] = slab_reclaimable_pages + kernel_misc
    except LookupError:
        stats["KReclaimable"] = -1
    stats["Slab"] = slab_reclaimable_pages + slab_unreclaimable_pages
    stats["SReclaimable"] = slab_reclaimable_pages
    stats["SUnreclaim"] = slab_unreclaimable_pages

    stats["KernelStack"] = global_stats["NR_KERNEL_STACK_KB"]
    stats["PageTables"] = global_stats["NR_PAGETABLE"]
    stats["NFS_Unstable"] = 0
    if "NR_UNSTABLE_NFS" in global_stats:
        stats["NFS_Unstable"] = global_stats["NR_UNSTABLE_NFS"]
    stats["Bounce"] = global_stats["NR_BOUNCE"]
    stats["WritebackTmp"] = global_stats["NR_WRITEBACK_TEMP"]

    stats["CommitLimit"] = get_vm_commit_limit(prog)
    # ``vm_committed_as`` is a percpu counter object. It has percpu
    # counters: each core can update without synchronization. It also has a
    # global counter that gets periodically updated.
    # We prefer the sum of percpu counters to get the most up-to-date result.
    committed_as = percpu_counter_sum(prog["vm_committed_as"])
    stats["Committed_AS"] = max(0, committed_as)

    # Convert the result to be counted in number of pages.
    stats["VmallocTotal"] = -1
    if prog.platform.arch == drgn.Architecture.X86_64:
        stats["VmallocTotal"] = (
            mm_consts["VMALLOC_END"] - mm_consts["VMALLOC_START"]
        ) >> 10

    stats["VmallocUsed"] = 0
    if "nr_vmalloc_pages" in prog:
        stats["VmallocUsed"] = prog["nr_vmalloc_pages"].counter.value_()
    stats["VmallocChunk"] = 0

    try:
        pcpu_nr_populated = prog["pcpu_nr_populated"].value_()
        pcpu_nr_units = prog["pcpu_nr_units"].value_()
        stats["Percpu"] = pcpu_nr_populated * pcpu_nr_units
    except LookupError:
        stats["Percpu"] = -1
    stats["HardwareCorrupted"] = prog[
        "num_poisoned_pages"
    ].counter.value_() << (mm_consts["PAGE_SHIFT"] - 10)

    # Collect transparent hugepage meminfo
    unit = mm_consts["TRANS_HPAGE_UNIT"]
    if "NR_ANON_THPS" in global_stats:
        stats["AnonHugePages"] = global_stats["NR_ANON_THPS"] * unit
        stats["ShmemHugePages"] = global_stats["NR_SHMEM_THPS"] * unit
        stats["ShmemPmdMapped"] = global_stats["NR_SHMEM_PMDMAPPED"] * unit
        try:
            stats["FileHugePages"] = global_stats["NR_FILE_THPS"] * unit
        except LookupError:
            stats["FileHugePages"] = -1
        try:
            stats["FilePmdMapped"] = global_stats["NR_FILE_PMDMAPPED"] * unit
        except LookupError:
            stats["FilePmdMapped"] = -1
    else:
        stats["AnonHugePages"] = (
            global_stats["NR_ANON_TRANSPARENT_HUGEPAGES"] * unit
        )
        stats["ShmemHugePages"] = -1
        stats["ShmemPmdMapped"] = -1
        stats["FileHugePages"] = -1
        stats["FilePmdMapped"] = -1

    stats["CmaTotal"] = prog["totalcma_pages"].value_()
    stats["CmaFree"] = global_stats["NR_FREE_CMA_PAGES"]
    return stats


def show_all_meminfo(prog: Program) -> None:
    """
    Dump various details about the memory subsystem.
    This function must parse machine info to determine arch-specific parameters
    before parsing all memory statistics.
    """
    stats = get_all_meminfo(prog)

    # Ignore highmem stats as the target kernels do not have no highmem zones.
    basic_meminfo_items = [
        "MemTotal",
        "MemFree",
        "MemAvailable",
        "Buffers",
        "Cached",
        "SwapCached",
        "Active",
        "Inactive",
        "Active(anon)",
        "Inactive(anon)",
        "Active(file)",
        "Inactive(file)",
        "Unevictable",
        "Mlocked",
        "SwapTotal",
        "SwapFree",
        "Dirty",
        "Writeback",
        "AnonPages",
        "Mapped",
        "Shmem",
        "KReclaimable",
        "Slab",
        "SReclaimable",
        "SUnreclaim",
        "KernelStack",
        "PageTables",
        "NFS_Unstable",
        "Bounce",
        "WritebackTmp",
        "CommitLimit",
        "Committed_AS",
        "VmallocTotal",
        "VmallocUsed",
        "VmallocChunk",
        "Percpu",
        "HardwareCorrupted",
    ]
    hugepage_meminfo_items = [
        "AnonHugePages",
        "ShmemHugePages",
        "ShmemPmdMapped",
        "FileHugePages",
        "FilePmdMapped",
    ]
    cma_meminfo_items = ["CmaTotal", "CmaFree"]

    # Output
    for item in basic_meminfo_items:
        if stats[item] == -1:
            continue

        if item in ["KernelStack", "VmallocTotal", "HardwareCorrupted"]:
            # These statistics items are counted in kB.
            num_str = str(stats[item])
            if item == "HardwareCorrupted":
                # len("HardwareCorrupted:") is 18, exceeding the target by 3.
                # Reduce the number's width by 3.
                print(f"{item + ':': <15} {num_str: >5} kB")
            else:
                print(f"{item + ':': <15} {num_str: >8} kB")
        else:
            print_val_kb(prog, item, stats[item])

    for item in hugepage_meminfo_items + cma_meminfo_items:
        print_val_kb(prog, item, stats[item])

    # Report hugepage related meminfo
    show_hugetlb_meminfo(prog)

    # Report tlb related meminfo
    show_arch_meminfo(prog)


class MeminfoModule(CorelensModule):
    """Show various details about the memory management subsystem"""

    name = "meminfo"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        show_all_meminfo(prog)
