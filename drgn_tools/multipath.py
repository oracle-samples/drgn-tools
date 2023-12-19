# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for multipath
"""
import argparse
import enum
from typing import Iterable

from drgn import cast
from drgn import container_of
from drgn import Object
from drgn import Program
from drgn.helpers.common.format import decode_enum_type_flags
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each

from drgn_tools.corelens import CorelensModule
from drgn_tools.util import has_member


NUM_BUCKETS = 64
MASK_BUCKETS = NUM_BUCKETS - 1

device_count = [1]
space = " "


class PathSelectionPolicies(str, enum.Enum):
    SERVICE_TIME = ("service-time",)
    ROUND_ROBIN = ("round-robin",)
    QUEUE_LENGTH = ("queue-length",)
    IO_AFFINITY = ("io-affinity",)
    HISTORICAL_SERVICE_TIME = "historical-service-time"


def rb_tree_uuid_node(prog: Program) -> Iterable[Object]:
    """
    Retrieves nodes of the RBTree in inorder traversal.

    :param prog: drgn program object

    :returns: RBTree nodes in inorder
    """
    return rbtree_inorder_for_each(prog["uuid_rb_tree"].address_of_())


def for_each_uuid_buckets(
    prog: Program, bucket_index: int
) -> Iterable[Object]:
    """
    Iterate through _uuid_buckets list and find struct hash_cell.

    :param prog: drgn program
    :param bucket_index: integer represengint the index

    :returns: Iterable of `struct hash_cell *`
    """
    return list_for_each_entry(
        "struct hash_cell", prog["_uuid_buckets"] + bucket_index, "uuid_list"
    )


def for_each_priority_group(multipath: Object) -> Iterable[Object]:
    """
    Iterates through priority groups of a multipath device.

    Paths are grouped into priority groups.
    A multipath device can have multiple priority groups.

    :param multipath: `struct multipath *`

    :returns: Iterable of `strut priority_group *`
    """
    return list_for_each_entry(
        "struct priority_group",
        multipath.priority_groups.address_of_(),
        "list",
    )


def for_each_pgpath(priority_group: Object) -> Iterable[Object]:
    """
    Iterates through pgpaths for each priority_group.

    struct pgpath contain path properties.

    :param priority_group: `struct priority_group *`

    :returns: Iterable of `struct pgpath *`
    """
    return list_for_each_entry(
        "struct pgpath", priority_group.pgpaths.address_of_(), "list"
    )


def switch_header(ps_type: str) -> None:
    """
    Format the output header as per ps policy.

    :param  ps_type: Path selection policy name.

    :return None.
    """
    header_mapping = {
        "service-time": "      InFlightIO_Size   RThroughput  RCount  Load",
        "round-robin": "      Repeat_Count",
        "queue-length": "      Repeat_Count  Queue_Length",
        "io-affinity": "      Refcount   failed",
        "historical-service-time": "Feature not supported for "
        "historical-service-time.",
    }
    header = header_mapping.get(ps_type)
    if header is not None:
        print(header)
    else:
        """
        We shouldn't reach here.
        """
        print("\n\nPath selection policy %s not supported.\n\n" % ps_type)


def switch_output(ps_type: str, pi: Object) -> None:
    """
    Format the path info output as per ps policy.

    :param  ps_type: Path selection policy name.
    :param pi: `struct path_info *`

    :return None.
    """
    output_mapping = {
        "service-time": "{:<6}{:<12d}{:<5}{:<7d}{:<3}{:<6d}{:<1}{:d}",
        "round-robin": "{:<5}{:d}",
        "queue-length": "{:<5}{:<9d}{:<5}{:d}",
        "io-affinity": "{:<4}{:<7d}{:<3}{:d}",
        "historical-service-time": "",
    }
    output_format = output_mapping.get(ps_type)
    if output_format:
        if ps_type == "service-time":
            load = pi.in_flight_size.counter / pi.relative_throughput
            print(
                output_format.format(
                    space,
                    pi.in_flight_size.counter.value_(),
                    space,
                    pi.relative_throughput.value_(),
                    space,
                    pi.repeat_count.value_(),
                    space,
                    load.value_(),
                )
            )
        elif ps_type == "round-robin":
            print(output_format.format(space, pi.repeat_count.value_()))
        elif ps_type == "queue-length":
            print(
                output_format.format(
                    space,
                    pi.repeat_count.value_(),
                    space,
                    pi.qlen.counter.value_(),
                )
            )
        elif ps_type == "io-affinity":
            print(
                output_format.format(
                    space,
                    pi.refcount.refs.counter.value_(),
                    space,
                    pi.failed.value_(),
                )
            )
        else:
            print(output_format)
    else:
        print("\n\nPath selection policy %s not supported.\n\n" % ps_type)


def show_pgpaths(priority_group: Object) -> None:
    """
    Show pgpath data.

    :param priority_group: `struct priority_group *`

    :returns: None
    """
    path_num = 1
    ps_type = priority_group.ps.type.name.string_().decode()
    format_header = "{:10}{:11}{:12}{:10}"
    print(
        format_header.format("Path_No.", "Disk_Name", "DevName", "State"),
        end="",
    )
    switch_header(ps_type)
    for pgpath in for_each_pgpath(priority_group):
        bdev = pgpath.path.dev.bdev
        disk_name = bdev.bd_disk.disk_name.string_().decode()
        dev_name = pgpath.path.dev.name.string_().decode()
        state = "active" if pgpath.is_active else "not active"
        pi = cast("struct path_info *", pgpath.path.pscontext)
        format_val = "{:<3}{:<7}{:<2}{:<9}{:<2}{:<8}{:<0}{:<17}"
        print(
            format_val.format(
                space,
                path_num,
                space,
                disk_name,
                space,
                dev_name,
                space,
                state,
            ),
            end="",
        )
        switch_output(ps_type, pi)
        path_num += 1


def show_priority_groups(multipath: Object) -> None:
    """
    Show priority group prperties.

    :param multipath: `struct multipath *`

    :returns: None`
    """
    for priority_group in for_each_priority_group(multipath):
        path_selector_type = priority_group.ps.type.name.string_().decode()
        print("PS:Policy %s" % path_selector_type)
        print("No. of paths %d" % priority_group.nr_pgpaths)
        if path_selector_type == "historical-service-time":
            print(
                "\n\nPath selection policy %s not supported.\n\n"
                % path_selector_type
            )
            return
        show_pgpaths(priority_group)


def show_multipath(prog: Program, target: Object) -> None:
    """
    Show multipath properties.

    :param prog: drgn Program
    :param target: `struct dm_target *`

    :returns: None:
    """
    multipath = cast("struct multipath *", target.private)
    if multipath.current_pgpath:
        current_dmpath = multipath.current_pgpath.path
        curr_dev_name = current_dmpath.dev.name.string_().decode()
    else:
        curr_dev_name = "None"
    if multipath.hw_handler_name:
        hw_handler = multipath.hw_handler_name.string_().decode()
    else:
        hw_handler = "0"
    if multipath.next_pg:
        pg_num = multipath.next_pg.pg_num
    elif multipath.current_pg:
        pg_num = multipath.current_pg.pg_num
    else:
        pg_num = 1 if multipath.nr_priority_groups else 0
    queue_mode = decode_enum_type_flags(
        multipath.queue_mode, prog.type("enum dm_queue_mode")
    )
    num_priority_groups = multipath.nr_priority_groups.value_()
    print("struct multipath * (%s)" % hex(multipath.value_()))
    print("nr_priority_groups: %d" % num_priority_groups)
    print("Current path = %s" % curr_dev_name)
    print("hw_handler_name: %s" % hw_handler)
    print("pg_num = %u" % pg_num)
    print("queue_mode = %s" % queue_mode)
    show_priority_groups(multipath)


def iterate_targets(prog: Program, table: Object) -> None:
    """
    Iterate through targets.

    :param prog: drgn Program
    :param table: `struct dm_table *`

    :returns: None
    """
    for index in range(0, table.num_targets):
        target = table.targets[index]
        show_multipath(prog, target)


def dump_hash_cell(prog: Program, hc: Object) -> None:
    """
    Iterate through hash_cells and print info.

    :param prog: drgn Program
    :param hc: `struct hash_cell`

    :returns: None
    """
    table = cast("struct dm_table *", hc.md.map)
    if has_member(table, "targets"):
        target_type = table.targets.type.name.string_().decode()
    else:
        return
    if target_type == "multipath":
        print("--------------- Device [%d] ---------------" % device_count[0])
        print("struct hash_cell * (%s)" % hex(hc.value_()))
        device_name = hc.name.string_().decode()
        device_uuid = hc.uuid.string_().decode()[6:]
        disk_name = hc.md.disk.disk_name.string_().decode()
        print("%s (%s) %s" % (device_name, device_uuid, disk_name))
        print("num_targets = %d" % table.num_targets)
        print("struct dm_target * (%s)" % hex(table.targets.value_()))
        iterate_targets(prog, table)
        device_count[0] += 1


def dump_uek5_6_multipaths(prog: Program) -> None:
    """
    Iterate through uuid_buckets and find hash_cell

    :param prog: drgn Program

    :returns None:
    """
    for index in range(0, NUM_BUCKETS):
        for hash_cell in for_each_uuid_buckets(prog, index):
            dump_hash_cell(prog, hash_cell)


def dump_uek7_multipaths(prog: Program) -> None:
    """
    Iterate through uuid_rb_tree and find hash_cell

    :param prog: drgn Program

    :returns None:
    """
    for rb_node in rb_tree_uuid_node(prog):
        hash_cell = container_of(rb_node, "struct hash_cell", "uuid_node")
        if hash_cell:
            dump_hash_cell(prog, hash_cell)


def show_mp(prog: Program) -> None:
    """
    Dump multipath devices Info.
    Iteratre through uuid rb tree/list
    Iterate through name rb tree.

    :param prog: drgn Program

    :returns None:
    """
    if "uuid_rb_tree" in prog:
        dump_uek7_multipaths(prog)
    elif "_uuid_buckets" in prog:
        dump_uek5_6_multipaths(prog)
    else:
        print(
            "\n\nNo valid multipath symbol found (uuid_rb_tree/_uuid_buckets)!!\n\n"
        )


class Multipath(CorelensModule):
    """Display info about Multipath devices"""

    name = "multipath"
    debuginfo_kmods = [r"^dm[_-].*"]

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        show_mp(prog)
