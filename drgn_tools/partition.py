# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper to print partition information
"""
import argparse
from typing import NamedTuple

from drgn import Object
from drgn import Program
from drgn.helpers.linux.block import for_each_partition
from drgn.helpers.linux.block import part_devt
from drgn.helpers.linux.block import part_name
from drgn.helpers.linux.device import MAJOR
from drgn.helpers.linux.device import MINOR

from drgn_tools.block import blkdev_ro
from drgn_tools.block import blkdev_size
from drgn_tools.corelens import CorelensModule
from drgn_tools.table import Table


class PartInfo(NamedTuple):
    """
    Partition info, from either ``struct block_device`` or ``struct hd_struct``
    """

    major: int
    minor: int
    name: str
    start_sect: int
    nr_sects: int
    ro: bool
    obj: Object


def get_partinfo_from_blkdev_struct(part: Object) -> PartInfo:
    """
    Collect partition information from ``struct block_device``
    Returns a list with partition information for the given partition.
    """
    devt = part.bd_dev.value_()
    name = part_name(part).decode()
    start_sect = int(part.bd_start_sect)
    nr_sects = int(blkdev_size(part) / 512)
    return PartInfo(
        MAJOR(devt),
        MINOR(devt),
        name,
        start_sect,
        nr_sects,
        # blkdev_ro will never return -1 in case of a struct block_device, so we
        # can convert to bool here.
        blkdev_ro(part) == 1,
        part,
    )


def get_partinfo_from_hd_struct(part: Object) -> PartInfo:
    """
    Collects partition information from ``struct hd_struct``
    Returns a list with partition information for the given partition.
    """
    devt = part_devt(part)
    name = part_name(part).decode()
    start_sect = int(part.start_sect)
    nr_sects = part.nr_sects.value_()
    return PartInfo(
        MAJOR(devt),
        MINOR(devt),
        name,
        start_sect,
        nr_sects,
        bool(part.policy),
        part,
    )


def get_partition_info(part: Object) -> PartInfo:
    """
    Returns partition info from ``struct hd_struct`` or ``struct block_device``
    depending on the kernel version.
    """
    if "block_device" in part.type_.type_name():
        return get_partinfo_from_blkdev_struct(part)
    else:
        return get_partinfo_from_hd_struct(part)


def print_partition_info(prog: Program) -> None:
    """
    Prints partition information
    """
    table = Table(
        [
            "MAJOR",
            "MINOR",
            "NAME",
            "START:>",
            "SECTORS:>",
            "READ-ONLY",
            "OBJECT:016x",  # will be replaced, see below
        ]
    )
    part_is_blkdev = -1
    for part in for_each_partition(prog):
        if part_is_blkdev == -1:
            if "block_device" in part.type_.type_name():
                part_is_blkdev = 1
                table.header[-1] = "BLOCK DEVICE"
            else:
                part_is_blkdev = 0
                table.header[-1] = "HD STRUCT"
        info = get_partition_info(part)
        table.row(*info._replace(obj=info.obj.value_()))

    table.write()


class PartitionInfo(CorelensModule):
    """
    Corelens Module for partition information
    """

    name = "partitioninfo"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_partition_info(prog)
