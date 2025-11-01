# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
    Helper to view memory statistics
"""
import argparse
import time
from collections import defaultdict
from numbers import Number
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple

from drgn import Program
from drgn.helpers.linux.cpumask import for_each_present_cpu
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.slab import for_each_slab_cache
from drgn.helpers.linux.slab import get_slab_cache_aliases
from drgn.helpers.linux.timekeeping import ktime_get_real_seconds

from drgn_tools.buddyinfo import get_per_zone_buddyinfo
from drgn_tools.corelens import CorelensModule
from drgn_tools.meminfo import for_each_zone
from drgn_tools.meminfo import get_active_numa_nodes
from drgn_tools.meminfo import get_all_meminfo
from drgn_tools.meminfo import get_total_hugetlb_pages
from drgn_tools.mm import totalram_pages
from drgn_tools.numastat import get_per_node_meminfo
from drgn_tools.slabinfo import get_kmem_cache_slub_info
from drgn_tools.task import get_command
from drgn_tools.task import get_pid
from drgn_tools.task import get_task_rss


"""
    these are common global constants used by oled-memstate.
    source : https://github.com/oracle/oled-tools/blob/main/tools/memstate/memstate_lib/constants.py
"""

FRAG_LEVEL_LOW_ORDERS = 95
FRAG_THRESHOLD = 95
UNACCOUNTED_THRESHOLD = 0.1
WSF_THRESHOLD = 100
PAGETABLES_USE_PERCENT = 0.02
MFK_RATIO_MIN = 0.8
MFK_RATIO_MAX = 1.5
NUMASTAT_MIN_MEMFREE_PERCENT = 0.1
NUMASTAT_DIFF_PERCENT = 2


def order_to_kb(prog: Program, order: int) -> float:
    return 1 << order + prog["PAGE_SHIFT"].value_()


# print in pretty format
def pages_to_gb(page_size: int, pages: int) -> float:
    """Convert number of memory pages to kilobytes (GB)."""
    gb_val = float(pages * (page_size / (1024 * 1024 * 1024)))
    return gb_val


def pages_to_kb(page_size: int, pages: int) -> float:
    """Convert number of memory pages to kilobytes (KB)."""
    kb_val = float((pages * page_size) / 1024)
    return kb_val


def convert_kb_to_gb(val_in_kb: int) -> float:
    """Return KBs to GBs."""
    val_in_gb = float(val_in_kb) / (1024**2)
    return val_in_gb


def print_pretty_kb(str_msg: str, arg: float) -> None:
    """Print KB value in a pretty format."""
    print(f"{str_msg: <30}{arg: >12}")


def print_pretty_gb(str_msg: str, arg: float) -> None:
    """Print GB value in a pretty format."""
    print(f"{str_msg: <30}{arg: >12.1f}")


def print_pretty_gb_l1(str_msg: str, arg: float) -> None:
    """Pretty-print a GBs value with 1-level indentation."""
    printstr = (" " * 2) + str_msg
    print_pretty_gb(printstr, arg)


def print_pretty_gb_l2(str_msg: str, arg: float) -> None:
    """
    Pretty-print a GBs value with 2-level indentation.
    """
    printstr = (" " * 4) + str_msg
    print_pretty_gb(printstr, arg)


def print_time(sys_time: str) -> None:
    """
    Print time
    """
    print(f"{'TIME: ': >12}{sys_time}")


def print_warn(err_str: str) -> None:
    """Print a warning message."""
    print(f"{'[WARN] ': <8}{err_str}")


def print_info(msg_str: str) -> None:
    """Print an info message."""
    print(f"{'[OK] ': <8}{msg_str}")


def print_numastat_headers(num_numa_nodes: int) -> None:
    print(f"{'NODE 0': >45}", end=" ")
    for i in range(1, num_numa_nodes):
        print(f"{'NODE ' + str(i): >14}", end=" ")
    print("")


def print_pretty_numastat_kb(str_msg: str, numa_arr_kb: List) -> None:
    print(f"{str_msg: <30}", end=" ")
    for _, val in enumerate(numa_arr_kb):
        print(f"{str(val): >14}", end=" ")
    print("")


def get_time(prog: Program) -> str:
    return time.ctime(ktime_get_real_seconds(prog).value_())


def memstate_header(prog: Program, print_header: bool = True) -> None:
    """
    Print memstate header to stdout if it has not been printed yet.
    """
    kernel_version = prog["UTS_RELEASE"].string_().decode("utf-8")
    hostname = prog["init_uts_ns"].name.nodename.string_().decode("utf-8")
    sys_time = get_time(prog)
    if print_header:
        print(f"{'KERNEL: ': >12}{kernel_version}")
        print(f"{'HOSTNAME: ': >12}{hostname}")
        print_time(sys_time)


def display_userspace_mm(
    prog: Program, mm_stats: Dict[str, int]
) -> Dict[str, Any]:
    """
    displaying the userspace memory usage , passing the userspace_mm calculated before as parameter
    """
    page_size = prog["PAGE_SIZE"].value_()
    buffers = pages_to_gb(page_size, mm_stats["Buffers"])
    anonpages = pages_to_gb(page_size, mm_stats["AnonPages"])
    ps_mem = pages_to_gb(page_size, mm_stats["AnonPages"] + mm_stats["Mapped"])
    cached_mm = pages_to_gb(page_size, mm_stats["Cached"])
    sh_mm = pages_to_gb(page_size, mm_stats["Shmem"])
    total = anonpages + cached_mm + buffers

    print_pretty_gb_l1("Userspace", total)
    print_pretty_gb_l2("Processes", ps_mem)
    print_pretty_gb_l2("Page cache", cached_mm)
    print_pretty_gb_l2("Shared mem", sh_mm)

    return {
        "ps_mem": ps_mem,
        "cached_mm": cached_mm,
        "sh_mm": sh_mm,
        "total": total,
    }


def display_kernel_mm(
    prog: Program,
    mm_stats: Dict[str, int],
    mem_total: float,
    mem_free: float,
    user_alloc: float,
) -> Dict[str, float]:
    """
    compute the kernel memory usage statistics and display the kernel memory usage
    """
    page_size = prog["PAGE_SIZE"].value_()
    slab_mm = pages_to_gb(page_size, mm_stats["Slab"])
    vmalloc = pages_to_gb(page_size, mm_stats["VmallocUsed"])
    page_tables = pages_to_gb(page_size, mm_stats["PageTables"])
    kernel_stack = pages_to_gb(page_size, mm_stats["KernelStack"])
    percpu = pages_to_gb(page_size, mm_stats["Percpu"])
    total = slab_mm + vmalloc + page_tables + kernel_stack + percpu
    hugepagessize = get_total_hugetlb_pages(prog)
    ukn = mem_total - (mem_free + total + user_alloc + hugepagessize)
    total = round(total + ukn, 1)

    print_pretty_gb_l1("Kernel", total)
    print_pretty_gb_l2("Slabs", round(slab_mm, 1))
    print_pretty_gb_l2("Percpu", round(percpu, 1))
    print_pretty_gb_l2("Unknown", round(ukn, 1))

    return {
        "slab_mm": slab_mm,
        "vmalloc": vmalloc,
        "page_tables": page_tables,
        "kernel_stack": kernel_stack,
        "percpu": percpu,
        "total": total,
        "ukn": ukn,
    }


def memory_usage(
    prog: Program, hp_stats: Dict[int, List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """ " This is a wrapper API that displays a memory summary"""
    print("")
    pages_size = prog["PAGE_SIZE"].value_()
    print("MEMORY USAGE SUMMARY (in GB):")
    mm_stats = get_all_meminfo(prog)
    total_memory = pages_to_gb(pages_size, totalram_pages(prog).value_())
    free_memory = pages_to_gb(pages_size, mm_stats["MemFree"])
    used_memory = total_memory - free_memory

    print_pretty_gb("Total memory", round(total_memory, 1))
    print_pretty_gb("Free memory", round(free_memory, 1))
    print_pretty_gb("Used memory", round(used_memory, 1))
    user_space_memory = display_userspace_mm(prog, mm_stats)
    kernel_mm_usage = display_kernel_mm(
        prog, mm_stats, total_memory, free_memory, user_space_memory["total"]
    )
    display_hugepages_state(prog, hp_stats)
    used_swap = pages_to_gb(
        pages_size, mm_stats["SwapTotal"] - mm_stats["SwapFree"]
    )
    print_pretty_gb("Swap used", round(used_swap, 1))
    return {
        "total_memory": total_memory,
        "free_memory": free_memory,
        "used_memory": used_memory,
        "kernel_mm_usage": kernel_mm_usage,
        "user_space": user_space_memory,
    }


def get_slab_inof(prog: Program) -> Dict[str, Dict[str, Any]]:
    """
    this api is returning a dictionnary that contain the slab cache , it size and their aliases
    """
    slab_infos: Dict[str, Dict[str, Any]] = defaultdict()
    cache_to_aliases = defaultdict(list)
    for alias, cache in get_slab_cache_aliases(prog).items():
        cache_to_aliases[cache].append(alias)

    for slab in for_each_slab_cache(prog):
        slab_info = get_kmem_cache_slub_info(slab)
        if slab_info.name not in slab_infos:
            slab_infos[slab_info.name] = {}
        slab_infos[slab_info.name]["size"] = (
            slab_info.nr_slabs * slab_info.ssize
        ) / 1024
        slab_infos[slab_info.name]["aliases"] = cache_to_aliases[
            slab_info.name
        ]
    sslab_info = dict(
        sorted(
            slab_infos.items(), key=lambda item: item[1]["size"], reverse=True
        )
    )
    return sslab_info


def display_top_slab_caches(
    sslab_info: Dict[str, Dict[str, Any]], verbose: bool
) -> None:
    print("")
    header = (
        "TOP 10 SLAB CACHES (in KB):"
        if not verbose
        else "TOP SLAB CACHES (in KB):"
    )
    print(header)
    print(f"{'SLAB CACHE':<35}{'SIZE (KB)':>12}    {'ALIASES'}")
    if sslab_info is None:
        print("Slab caches list unavailable!")
        return
    displayed = 0
    total_mem = sum(info["size"] for info in sslab_info.values())
    for slab, infos in sslab_info.items():
        if displayed >= 10 and not verbose:
            break
        else:
            if infos["size"] == 0:
                break
            aliases_lst = infos.get("aliases", [])
            aliases_str = ", ".join(aliases_lst) if aliases_lst else "(null)"
            print(f"{slab:<35}{int(infos['size']):>12}    {aliases_str}")
            displayed = displayed + 1
    print("")
    print(">> Total memory used by all slab caches: " f"{total_mem} KB")


def get_proc_infos(prog: Program) -> Tuple[Dict[Any, Any], int]:
    tasks = list(for_each_task(prog))
    task_infos: Dict = {}
    rss_cache: Dict = {}
    mem_total = 0

    for task in tasks:
        # checkin for the tasks that are at the same group
        gpid = task.tgid.value_()
        pid = get_pid(task)
        if pid != gpid:
            continue
        task_infos[pid] = {}
        task_infos[pid]["cmd"] = get_command(task)
        task_rss = get_task_rss(task, rss_cache)
        task_infos[pid]["rss"] = (
            task_rss.rss_file + task_rss.rss_anon + task_rss.rss_shmem
        ) * (4096 / 1024)
        mem_total += task_infos[pid]["rss"]
        mm = task.mm
        if not mm:
            continue
        swap_pages = task_rss.swapents
        swap_kb = pages_to_kb(prog["PAGE_SIZE"].value_(), swap_pages)
        task_infos[pid]["swap"] = int(swap_kb)
    sorted_task_infos = dict(
        sorted(
            task_infos.items(), key=lambda item: item[1]["rss"], reverse=True
        )
    )
    return sorted_task_infos, mem_total


def display_top_swap_consumers(
    tasks_infos: Tuple[Dict[Any, Any], int], verbose: bool
):
    count = 0
    print("")
    header = "TOP 10 SWAP SPACE CONSUMERS:" if not verbose else "SWAP USERS:"
    print(header)
    filtered = {
        pid: {"cmd": info["cmd"], "swap": info["swap"]}
        for pid, info in tasks_infos[0].items()
        if info.get("swap", 0) > 0
    }
    if not filtered:
        print("No swap usage found.")
        return

    sorted_swap_info = dict(
        sorted(
            filtered.items(), key=lambda item: item[1]["swap"], reverse=True
        )
    )
    for pid, task in sorted_swap_info.items():
        if count >= 10:
            break
        print(
            f"{task['cmd'] + '(' + str((pid)) + ')': <30}"
            f"{int(task['swap']): >16}"
        )


def display_process_infos(
    task_infos: Tuple[Dict[Any, Any], int], verbose: bool
):
    print("")
    header = (
        "TOP 10 MEMORY CONSUMERS (in KB):"
        if not verbose
        else "TOP MEMORY CONSUMERS (in KB):"
    )
    print(header)
    print(f"{'PROCESS(PID)': <30}{'RSS': >16}")
    count = 0
    for pid, task in task_infos[0].items():
        if (count < 10 or verbose) and task["rss"] > 0:
            print(
                f"{task['cmd'] + '(' + str((pid)) + ')': <30}"
                f"{int(task['rss']): >16}"
            )
            count += 1
        else:
            break
    print("")
    print(
        ">> Total memory used by all processes:",
        round(convert_kb_to_gb(task_infos[1]), 1),
        " GB",
    )


def check_pagetables_size(
    prog: Program, kernel_mm_stats, total_mm, hugepages_gb
):
    pagetables_gb = round(kernel_mm_stats["page_tables"], 1)
    if (
        0
        < pagetables_gb
        >= (PAGETABLES_USE_PERCENT * (total_mm - hugepages_gb))
    ):
        print("")
        print_warn(
            "Page tables are larger than expected "
            f"({pagetables_gb} GB); if this is an Exadata system, "
            "check if the DB parameter USE_LARGE_PAGES is set to ONLY."
        )
    else:
        print("")
        print_info(f"Page tables size is: {pagetables_gb} GB.")


def check_committed_as(prog: Program, mm_stats, total_hugepages_gb):
    """
    Check for the committed virtual memory if it's more than physically
    available.
    """
    committed_as_gb = pages_to_gb(
        prog["PAGE_SIZE"].value_(), mm_stats["Committed_AS"]
    )
    mem_total = pages_to_gb(prog["PAGE_SIZE"].value_(), mm_stats["MemTotal"])
    if committed_as_gb >= (mem_total - total_hugepages_gb):
        print("")
        print_warn(
            "Max virtual memory allocated is more than available physical"
            f" memory (Committed_AS = {round(committed_as_gb, 1)} GB)."
        )


def health_check(
    prog: Program,
    mm_stats: Dict[str, int],
    total_mm: float,
    kernel_mm_stats: Dict[str, float],
):
    print("")
    print("HEALTH CHECKS:")
    """
    Check if vm.min_free_kbytes is within recommended limits.
    """
    current_mfk_kb = int(prog["min_free_kbytes"])
    page_size = prog["PAGE_SIZE"].value_()
    total_ram_kb = (totalram_pages(prog).value_() * page_size) // 1024
    current_mfk_percent = round(current_mfk_kb / total_ram_kb * 100, 3)

    # Compute thresholds
    mfk_val1_kb = 0.005 * total_ram_kb  # 0.5% of RAM
    numa_nodes = len(get_active_numa_nodes(prog))
    mfk_val2_kb = (
        (1024 * 1024 * numa_nodes) if numa_nodes > 1 else 0
    )  # 1 GB per NUMA node

    recommended_mfk_kb = int(max(mfk_val1_kb, mfk_val2_kb))

    mfk_warning_str = (
        f"Recommended value for vm.min_free_kbytes is {recommended_mfk_kb} KB "
        f"(max[0.5% of RAM, 1 GB per NUMA node]);\n"
        f"current value is {current_mfk_kb} KB ({current_mfk_percent}%)."
    )

    ratio = round(current_mfk_kb / recommended_mfk_kb, 1)
    if ratio < MFK_RATIO_MIN:
        print_warn(mfk_warning_str)
        print(
            "There is a higher possibility of compaction stalls due to fragmentation."
        )
    elif ratio > MFK_RATIO_MAX:
        print_warn(mfk_warning_str)
        print(
            "There is a higher possibility of the OOM-killer being invoked if memory usage goes up"
        )
    else:
        print_info(f"The value of vm.min_free_kbytes is: {current_mfk_kb} KB.")
        print("")

    """
    Check if vm.watermark_scale_factor is within recommended limits.
    """
    wsf = int(prog["watermark_scale_factor"])

    if wsf > WSF_THRESHOLD:
        print_warn(f"\nvm.watermark_scale_factor has been increased to {wsf}.")
    else:
        print_info(f"The value of vm.watermark_scale_factor is: {wsf}.")

    """
        Page tables health check.
    """
    total_hugepages_gb = get_total_hugetlb_pages(prog)
    check_pagetables_size(prog, kernel_mm_stats, total_mm, total_hugepages_gb)
    """
        Unaccounted kernel memory health check.
    """
    ukn = kernel_mm_stats["ukn"]
    if 0 < ukn >= 0.1 * (total_mm - total_hugepages_gb):
        print("")
        print_warn(
            "Unaccounted kernel memory use is larger than expected: "
            f"{round(ukn, 1)} GB."
        )
    elif ukn >= 0:
        print("")
        print_info(f"Unaccounted kernel memory is: {round(ukn, 1)} GB.")
    """
        check for the commited virtual memory.
    """
    check_committed_as(prog, mm_stats, total_hugepages_gb)


def check_fragmentation_status(prog: Program):
    """Check for memory fragmentation."""

    print("\nBuddyinfo:")
    print("  (Low orders are 0-3, high orders are 4-10).")

    fragmented_nodes = []
    is_fragmented: bool = False

    for zone in for_each_zone(prog):
        zone_name = zone.name.string_().decode("utf-8")
        if zone_name != "Normal":
            continue
        node_id = zone.zone_pgdat.node_id.value_()
        print(f"Node {node_id}, zone {zone_name}", end="  ")
        free_blocks = get_per_zone_buddyinfo(zone)
        free_blocks = free_blocks[:11]

        for count in free_blocks:
            print(f"{count}", end="  ")

        low = (
            sum(free_blocks[i] * order_to_kb(prog, i) for i in range(4))
            // 1024
        )
        high = (
            sum(
                free_blocks[i] * order_to_kb(prog, i)
                for i in range(4, len(free_blocks))
            )
            // 1024
        )
        total = low + high
        low_percent = (low / total) * 100 if total else 0
        high_percent = 100 - low_percent
        print(
            f"\n  Total: {total} KB;\t\tLow: {low} KB ({low_percent:.2f}%);"
            f"\t\tHigh: {high} KB ({high_percent:.2f}%)"
        )

        is_fragmented = low_percent > FRAG_THRESHOLD
        if is_fragmented:
            fragmented_nodes.append(node_id)

    if is_fragmented is True:
        if len(fragmented_nodes) > 1:
            node_str = ", ".join(fragmented_nodes)
            print_warn(
                f"Memory on NUMA node(s) ({node_str}) is fragmented; "
                "system may run into compaction stalls."
            )
        else:
            print_warn(
                "Memory is fragmented - system may run into compaction "
                "stalls."
            )


def get_vm_event_total(prog: Program) -> Dict:
    """
    Return the total value of interesting vm_event_item counters by summing all per-CPU values.
    """
    vm_stats: dict = defaultdict(int)

    interesting = (
        "compact",
        "allocstall_normal",
        "kswapd_low_wmark_hit_quickly",
        "kswapd_high_wmark_hit_quickly",
        "drop_",
        "oom_",
        "zone_reclaim_failed",
    )
    vm_event_enum = prog.type("enum vm_event_item")
    vm_event_map = {n: v for n, v in vm_event_enum.enumerators}
    vm_event_start_index = (
        prog.constant("NR_VM_ZONE_STAT_ITEMS").value_()
        + prog.constant("NR_VM_NODE_STAT_ITEMS").value_()
    )
    try:
        # v5.14: f19298b9516c1 ("mm/vmstat: convert NUMA statistics to basic
        # NUMA counters")
        vm_event_start_index += prog.constant(
            "NR_VM_NUMA_EVENT_ITEMS"
        ).value_()
    except LookupError:
        vm_event_start_index += prog.constant("NR_VM_NUMA_STAT_ITEMS").value_()
    try:
        # v6.11: f4cb78af91e3b ("mm: add system wide stats items category")
        vm_event_start_index += prog.constant("NR_VM_STAT_ITEMS").value_()
    except LookupError:
        vm_event_start_index += prog.constant(
            "NR_VM_WRITEBACK_STAT_ITEMS"
        ).value_()
    vmstat_text = prog["vmstat_text"]
    for event_name, event_index in vm_event_map.items():
        if event_name.startswith("NR_"):
            continue
        text = vmstat_text[vm_event_start_index + event_index].read_()
        label = text.string_().decode()
        if any(label.startswith(prefix) for prefix in interesting):
            total = 0
            for cpu in for_each_present_cpu(prog):
                ves = per_cpu(prog["vm_event_states"], cpu)
                total += ves.event[event_index].value_()
            vm_stats[label] = total
    return dict(vm_stats)


def display_vm_events(prog: Program, vm_events: dict) -> None:
    print("")
    print("Vmstat:")
    for vm_event, counter in vm_events.items():
        print(f"  {vm_event.lower()} {counter}")
    print("")


def is_low_memfree(memfree_kb: list, memtotal_kb: list) -> bool:
    lowest_ratio = min(
        round(float(free) / float(total), 2)
        for total, free in zip(memtotal_kb, memfree_kb)
    )
    if lowest_ratio <= NUMASTAT_MIN_MEMFREE_PERCENT:
        return True
    return False


def check_for_numa_imbalance(numa_row_str: str, numa_val_mb: List) -> None:
    lowest = min(float(val) for val in numa_val_mb)
    highest = max(float(val) for val in numa_val_mb)
    if float(highest) > float(NUMASTAT_DIFF_PERCENT * float(lowest)):
        print_warn(f"{numa_row_str} is imbalanced across NUMA nodes.")


def huge_pages_stats(prog: Program) -> Dict[int, List[Dict[str, Any]]]:
    hp_per_node: Dict[int, List[Dict[str, Number]]] = defaultdict(list)
    hstates = prog["hstates"]

    for nid in range(prog["nr_node_ids"].value_()):
        for i in range(len(hstates)):
            hstate = hstates[i]
            hp_name = hstate.name.string_().decode("utf-8")
            stats = {
                "name": hp_name,
                "hp_size": hp_name[10:-2],
                "nr_huge_pages": hstate.nr_huge_pages_node[nid].value_(),
                "nr_free_huge_pages": hstate.free_huge_pages_node[
                    nid
                ].value_(),
            }
            hp_per_node[nid].append(stats)
    return hp_per_node


def display_hugepages_state(
    prog: Program, hp_per_node: Dict[int, List[Dict[str, Any]]]
) -> None:
    sizes = set()
    for stats in hp_per_node.values():
        for stat in stats:
            sizes.add(stat["hp_size"])

    node_ids = hp_per_node.keys()
    for size in sizes:
        total = []
        for nid in node_ids:
            stat_list = hp_per_node[nid]
            val = next(
                (s["nr_huge_pages"] for s in stat_list if s["hp_size"] == size)
            )
            total.append(val)
        if not all(e == 0 for e in total):
            print_pretty_numastat_kb(f"Total Hugepages ({size} KB)", total)

    for size in sizes:
        free = []
        for nid in node_ids:
            stat_list = hp_per_node[nid]
            val = next(
                (
                    s["nr_free_huge_pages"]
                    for s in stat_list
                    if s["hp_size"] == size
                ),
                0,
            )
            free.append(val)
        if not all(e == 0 for e in free):
            print_pretty_numastat_kb(f"Free Hugepages ({size} KB)", free)


def numa_stats(
    prog: Program, hp_stats: Dict[int, List[Dict[str, Any]]]
) -> None:
    print("")
    print("NUMA STATISTICS:")
    numa_memtotal_kb: List[float] = []
    numa_memfree_kb: List[float] = []
    numa_filepages_kb: List[float] = []
    numa_anonpages_kb: List[float] = []
    numa_slab_kb: List[float] = []
    numa_shmem_kb: List[float] = []
    page_size = prog["PAGE_SIZE"].value_()
    active_nodes = get_active_numa_nodes(prog)
    num_nodes = len(active_nodes)
    if num_nodes > 1:
        print(
            "NUMA is enabled on this system; number of NUMA nodes is "
            f"{num_nodes}."
        )
    else:
        print("NUMA is not enabled on this system.")
        return
    print("Per-node memory usage summary (in KB):")
    print_numastat_headers(num_nodes)
    for node in active_nodes:
        node_mm_stats = get_per_node_meminfo(prog, node)
        numa_memtotal_kb.append(
            pages_to_kb(page_size, int(node_mm_stats["MemTotal"]))
        )
        numa_memfree_kb.append(
            pages_to_kb(page_size, node_mm_stats["MemFree"])
        )
        numa_filepages_kb.append(
            pages_to_kb(page_size, node_mm_stats["FilePages"])
        )
        numa_anonpages_kb.append(
            pages_to_kb(page_size, node_mm_stats["AnonPages"])
        )
        numa_slab_kb.append(pages_to_kb(page_size, node_mm_stats["Slab"]))
        numa_shmem_kb.append(pages_to_kb(page_size, node_mm_stats["Shmem"]))

    print_pretty_numastat_kb("MemTotal", numa_memtotal_kb)
    print_pretty_numastat_kb("MemFree", numa_memfree_kb)
    print_pretty_numastat_kb("FilePages", numa_filepages_kb)
    print_pretty_numastat_kb("AnonPages", numa_anonpages_kb)
    print_pretty_numastat_kb("Slab", numa_slab_kb)
    print_pretty_numastat_kb("Shmem", numa_shmem_kb)
    display_hugepages_state(prog, hp_stats)

    if not is_low_memfree(numa_memfree_kb, numa_memtotal_kb):
        return

    check_for_numa_imbalance("MemFree", numa_memfree_kb)
    check_for_numa_imbalance("FilePages", numa_filepages_kb)
    check_for_numa_imbalance("AnonPages", numa_anonpages_kb)
    check_for_numa_imbalance("Slab", numa_slab_kb)
    check_for_numa_imbalance("Shmem", numa_shmem_kb)


def run_memstate(
    prog: Program,
    per_process: bool = False,
    slab: bool = False,
    numa: bool = False,
    verbose: bool = False,
) -> None:
    run_all = not (per_process or slab or numa)

    memstate_header(prog, True)
    if run_all:
        hp_stats = huge_pages_stats(prog)
        memory_summary = memory_usage(prog, hp_stats)
        mm_stats = get_all_meminfo(prog)
    if run_all or numa:
        if numa:
            hp_stats = huge_pages_stats(prog)
        numa_stats(prog, hp_stats)
    if run_all or slab:
        slab_infos = get_slab_inof(prog)
        display_top_slab_caches(slab_infos, verbose)
    if run_all or per_process:
        proc_infos = get_proc_infos(prog)
        display_process_infos(proc_infos, verbose)
    if run_all:
        display_top_swap_consumers(proc_infos, verbose)
    if run_all:
        health_check(
            prog,
            mm_stats,
            memory_summary["total_memory"],
            memory_summary["kernel_mm_usage"],
        )
        check_fragmentation_status(prog)
        vm_events = get_vm_event_total(prog)
        display_vm_events(prog, vm_events)


class MemState(CorelensModule):
    """
    Corelens Module for memstate
    """

    name = "memstate"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        group = parser.add_argument_group(
            description="analyze memory usage data on this runing system or a passed vmcore."
        )

        group.add_argument(
            "-p", action="store_true", help="display per-process memory usage"
        )
        group.add_argument(
            "-s",
            "--slab",
            action="store_true",
            help="analyze/display slab usage",
        )
        group.add_argument(
            "-n",
            "--numa",
            action="store_true",
            help="analyze/display NUMA stats",
        )
        group.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="verbose data capture; combine with other options",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        run_memstate(
            prog,
            per_process=args.p,
            slab=args.slab,
            numa=args.numa,
            verbose=args.verbose,
        )
