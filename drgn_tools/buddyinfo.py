# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for dumping details about the per-zone buddy page allocator
"""
import argparse
from typing import Any
from typing import List

from drgn import Object
from drgn import Program

from drgn_tools.corelens import CorelensModule
from drgn_tools.meminfo import for_each_node_zone
from drgn_tools.meminfo import get_active_numa_nodes
from drgn_tools.table import print_table


__all__ = ("show_all_zones_buddyinfo", "get_per_zone_buddyinfo")


def get_per_zone_buddyinfo(zone: Object):
    """
    Pages are managed in memory blocks: each memory zone has an array
    ``zone->free_area`` that tracks blocks of all orders. This function parses
    and returns a list that records numbers of free blocks.

    :param zone: ``struct zone *`` of the target zone
    :returns: A list that records numbers of memory blocks of all orders
    """
    free_area = zone.free_area.read_()
    return [x.nr_free.value_() for x in free_area]


def show_all_zones_buddyinfo(prog: Program):
    """Dump numbers of free memory blocks in each zone's buddy allocator."""

    buddyinfo_table: List[List[Any]] = []

    active_nodes = get_active_numa_nodes(prog)
    for node_id in range(len(active_nodes)):
        node_name = f"Node {node_id}"
        for zone in for_each_node_zone(prog, active_nodes[node_id]):
            zone_name = zone.name.string_().decode("utf-8")
            zone_free_blocks = get_per_zone_buddyinfo(zone)

            # For the first iteration, add the table's header
            if len(buddyinfo_table) == 0:
                max_order = len(zone_free_blocks)
                buddyinfo_table.append(
                    ["Node ID", "Zone", "Order 0"]
                    + [f"{x: >7}" for x in range(1, max_order)]
                )

            buddyinfo_table.append(
                [node_name, zone_name] + [f"{x: >7}" for x in zone_free_blocks]
            )

    # Output
    print("Per-zone buddy allocator's information:")
    print_table(buddyinfo_table)


class BuddyInfoModule(CorelensModule):
    """This module shows details about the per-zone buddy page allocator."""

    name = "buddyinfo"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        # Dump buddyinfo-like statistics for all memory zones.
        show_all_zones_buddyinfo(prog)
