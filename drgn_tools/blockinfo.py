# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
import re

import drgn
from drgn import Object
from drgn.helpers.linux.block import for_each_disk

from drgn_tools.block import get_inflight_io_nr
from drgn_tools.block import get_max_io_inflight_ns
from drgn_tools.block import queue_freezed_depth
from drgn_tools.block import queue_usage_counter
from drgn_tools.corelens import CorelensModule
from drgn_tools.dm import dm_target_driver
from drgn_tools.md import md_raid_driver
from drgn_tools.nvme import nvme_disk_driver
from drgn_tools.scsi import scsi_disk_driver
from drgn_tools.table import print_table
from drgn_tools.util import timestamp_str


def get_disk_type(disk: Object) -> str:
    diskname = disk.disk_name.string_().decode()
    patterns = {
        "nvme": r"^nvme\d+(n\d+)?$",
        "scsi": r"^sd[a-z]+$",
        "md": r"^md\d+$",
        "dm": r"^dm-\d+$",
        "loop": r"^loop\d+$",
        "pmem": r"^pmem\d+$",
    }
    for dtype, pattern in patterns.items():
        if re.match(pattern, diskname):
            return dtype

    return "unknown"


def get_disk_driver(prog: drgn.Program, disk: Object) -> str:
    dtype = get_disk_type(disk)
    if dtype == "nvme":
        return nvme_disk_driver(prog, disk)
    elif dtype == "scsi":
        return scsi_disk_driver(prog, disk)
    elif dtype == "md":
        return md_raid_driver(prog, disk)
    elif dtype == "dm":
        return dm_target_driver(prog, disk)
    else:
        return dtype


def print_block_devs_info(prog: drgn.Program) -> None:
    """
    Prints the block device information
    """
    output = [
        [
            "MAJOR",
            "GENDISK",
            "NAME",
            "DRIVER",
            "REQUEST_QUEUE",
            "Inflight I/Os",
            "Max Inflight time",
            "Freezed Depth",
            "Usage Counter",
        ]
    ]
    for disk in for_each_disk(prog):
        q = disk.queue
        major = int(disk.major)
        gendisk = hex(disk.value_())
        name = disk.disk_name.string_().decode("utf-8")
        rq = hex(q.value_())
        ios = get_inflight_io_nr(prog, disk)
        output.append(
            [
                str(major),
                gendisk,
                name,
                get_disk_driver(prog, disk),
                rq,
                str(ios),
                timestamp_str(get_max_io_inflight_ns(prog, disk)),
                str(queue_freezed_depth(q)),
                str(queue_usage_counter(q)),
            ]
        )
    print_table(output)


class BlockInfo(CorelensModule):
    """
    Corelens Module for block device info
    """

    name = "blockinfo"

    def run(self, prog: drgn.Program, args: argparse.Namespace) -> None:
        print_block_devs_info(prog)
