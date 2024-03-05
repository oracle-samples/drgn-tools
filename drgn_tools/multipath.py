# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for multipath
"""
import argparse
from typing import Iterable

from drgn import cast
from drgn import Object
from drgn import Program
from drgn import Type
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.block import blkdev_name
from drgn_tools.block import blkdev_ro
from drgn_tools.block import blkdev_size
from drgn_tools.corelens import CorelensModule
from drgn_tools.dm import dm_table
from drgn_tools.dm import dm_target_name
from drgn_tools.dm import for_each_dm
from drgn_tools.module import ensure_debuginfo
from drgn_tools.util import BitNumberFlags
from drgn_tools.util import has_member
from drgn_tools.util import type_lookup_conflict


class DmMultipathStateFlags(BitNumberFlags):
    MPATHF_QUEUE_IO = 0
    MPATHF_QUEUE_IF_NO_PATH = 1
    MPATHF_SAVED_QUEUE_IF_NO_PATH = 2
    MPATHF_RETAIN_ATTACHED_HW_HANDLER = 3
    MPATHF_PG_INIT_DISABLED = 4
    MPATHF_PG_INIT_REQUIRED = 5
    MPATHF_PG_INIT_DELAY_RETRY = 6


def for_each_priority_group(multipath: Object) -> Iterable[Object]:
    """
    Iterates through priority groups of a multipath device.

    Paths are grouped into priority groups.
    A multipath device can have multiple priority groups.

    :param multipath: ``struct multipath *``

    :returns: Iterable of ``struct priority_group *``
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

    :param priority_group: ``struct priority_group *``

    :returns: Iterable of ``struct pgpath *``
    """
    return list_for_each_entry(
        "struct pgpath", priority_group.pgpaths.address_of_(), "list"
    )


def switch_header(ps_type: str) -> None:
    """
    Format the output header as per ps policy.

    :param  ps_type: Path selection policy name.

    :returns: None
    """
    header_mapping = {
        "service-time": "   InFlightIO_Size   RThroughput  RCount  Load",
        "round-robin": "   Repeat_Count",
        "queue-length": "   Repeat_Count  Queue_Length",
        "io-affinity": "   Refcount   failed",
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

    :param ps_type: Path selection policy name.
    :param pi: ``void *`` of path_info (must be decoded by the policy)

    :returns: None
    """
    output_mapping = {
        "service-time": "{:<6}{:<12d}{:<5}{:<7d}{:<3}{:<6d}{:<1}{:d}",
        "round-robin": "{:<5}{:d}",
        "queue-length": "{:<5}{:<9d}{:<5}{:d}",
        "io-affinity": "{:<4}{:<7d}{:<3}{:d}",
        "historical-service-time": "",
    }
    output_format = output_mapping.get(ps_type)
    if not output_format:
        print("\n\nPath selection policy %s not supported.\n\n" % ps_type)
        return
    if ps_type == "service-time":
        load = pi.in_flight_size.counter / pi.relative_throughput
        print(
            output_format.format(
                " ",
                pi.in_flight_size.counter.value_(),
                " ",
                pi.relative_throughput.value_(),
                " ",
                pi.repeat_count.value_(),
                " ",
                load.value_(),
            )
        )
    elif ps_type == "round-robin":
        print(output_format.format(" ", pi.repeat_count.value_()))
    elif ps_type == "queue-length":
        print(
            output_format.format(
                " ",
                pi.repeat_count.value_(),
                " ",
                pi.qlen.counter.value_(),
            )
        )
    elif ps_type == "io-affinity":
        print(
            output_format.format(
                " ",
                pi.refcount.refs.counter.value_(),
                " ",
                pi.failed.value_(),
            )
        )
    else:
        print(output_format)


def get_path_info(prog: Program, ps_type: str) -> Type:
    """
    ``struct path_info`` has multiple definitions. Find
    the correct one depending upon ps_type.

    :returns: ``struct path_info *``
    """
    ps_type_us = ps_type.replace("-", "_")
    return type_lookup_conflict(
        prog,
        "struct path_info *",
        f"dm_{ps_type_us}",  # module: e.g. dm_service_time
        # e.g. dm-service-time.c or dm-ps-service-time.c
        [f"dm-{ps_type}.c", f"dm-ps-{ps_type}.c"],
    )


def show_pgpaths(priority_group: Object) -> None:
    """
    Show pgpath data.

    :param priority_group: ``struct priority_group *``

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
    path_info_type = get_path_info(priority_group.prog_, ps_type)
    for pgpath in for_each_pgpath(priority_group):
        bdev = pgpath.path.dev.bdev
        disk_name = blkdev_name(bdev)
        dev_name = pgpath.path.dev.name.string_().decode()
        state = "active" if pgpath.is_active else "not active"
        pi = cast(path_info_type, pgpath.path.pscontext)
        format_val = "{:<3}{:<7}{:<2}{:<9}{:<1}{:<8}{:<3}{:<13}"
        print(
            format_val.format(
                " ",
                path_num,
                " ",
                disk_name,
                " ",
                dev_name,
                " ",
                state,
            ),
            end="",
        )
        switch_output(ps_type, pi)
        path_num += 1


def show_priority_groups(prog: Program, multipath: Object) -> None:
    """
    Show priority group properties.

    :param prog: drgn program
    :param multipath: ``struct multipath *``

    :returns: None
    """
    for priority_group in for_each_priority_group(multipath):
        path_selector_type = priority_group.ps.type.name.string_().decode()
        if path_selector_type == "historical-service-time":
            print(
                "Path selection policy %s not supported.\n"
                % path_selector_type
            )
            continue
        path_selector_type_us = path_selector_type.replace("-", "_")
        ret = ensure_debuginfo(prog, [f"dm_{path_selector_type_us}"])
        if ret:
            print(ret)
            return
        print("Policy = %s" % path_selector_type)
        show_pgpaths(priority_group)


def show_multipath(prog: Program, dm: Object) -> None:
    """
    Show multipath properties.

    :param prog: drgn Program
    :param dm: ``struct mapped_device *``

    :returns: None
    """
    table = dm_table(dm)
    target = table.targets[0]
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
    print("struct multipath * (%s)" % hex(multipath.value_()))

    if has_member(multipath, "flags"):
        print(
            "Flags = %s" % DmMultipathStateFlags.decode(int(multipath.flags))
        )
    print("Current path = %s" % curr_dev_name)
    print("hw_handler_name = %s" % hw_handler)
    if has_member(dm, "bdev"):
        bdev = dm.bdev
    else:
        bdev = dm.disk.part0
    permission = blkdev_ro(bdev)
    if permission == -1:
        gendisk = dm.disk
        print("Permission = %s" % ("ro" if gendisk.part0.policy else "rw"))
    else:
        print("Permission = %s" % ("ro" if permission else "rw"))
    print("Size = %u" % blkdev_size(bdev))
    show_priority_groups(prog, multipath)


def show_mp(prog: Program) -> None:
    """
    Dump multipath devices Info.
    Iteratre through uuid rb tree/list
    Iterate through name rb tree.

    :param prog: drgn Program

    :returns None:
    """

    dm_device_count = 1
    ret = ensure_debuginfo(prog, ["dm_mod", "dm_multipath"])
    if ret:
        print(ret)
        return
    for dm, name, uuid in for_each_dm(prog):
        if dm_target_name(dm) != "multipath":
            continue
        print("%s Device [%d] %s" % ("-" * 15, dm_device_count, "-" * 15))
        disk_name = dm.disk.disk_name.string_().decode()
        print("%s (%s) %s" % (name, uuid.partition("-")[2], disk_name))
        show_multipath(prog, dm)
        dm_device_count += 1


class Multipath(CorelensModule):
    """Display info about Multipath devices"""

    name = "multipath"
    debuginfo_kmods = [
        "dm_mod",
        "dm_multipath",
        "dm_service",
        "dm_queue_length",
        "dm_io_affinity",
        "dm_historical_service_time",
    ]

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        show_mp(prog)
