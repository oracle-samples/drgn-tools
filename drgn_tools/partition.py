# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper to print partition information
"""
import argparse

from drgn import Object
from drgn import Program
from drgn.helpers.linux.block import for_each_partition
from drgn.helpers.linux.block import part_devt
from drgn.helpers.linux.block import part_name
from drgn.helpers.linux.device import MAJOR
from drgn.helpers.linux.device import MINOR

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table


def get_partinfo_from_blkdev_struct(part: Object) -> list:
    """
    Collect partition information from `struct block_device`
    Returns a list with partition information for the given partition.
    """
    devt = part.bd_dev.value_()
    name = part_name(part).decode()
    start_sect = int(part.bd_start_sect)
    nr_sects = int(part.bd_inode.i_size.value_() / 512)
    ro = "Yes" if part.bd_read_only else "No"
    return [
        MAJOR(devt),
        MINOR(devt),
        name,
        start_sect,
        nr_sects,
        ro,
        hex(part.value_()),
    ]


def get_partinfo_from_hd_struct(part: Object) -> list:
    """
    Collects partition information from `struct hd_struct`
    Returns a list with partition information for the given partition.
    """
    devt = part_devt(part)
    name = part_name(part).decode()
    start_sect = int(part.start_sect)
    nr_sects = part.nr_sects.value_()
    ro = "Yes" if int(part.policy) else "No"
    return [
        MAJOR(devt),
        MINOR(devt),
        name,
        start_sect,
        nr_sects,
        ro,
        hex(part.value_()),
    ]


def print_partition_info(prog: Program) -> None:
    """
    Prints partition information
    """
    output = [["MAJOR", "MINOR", "NAME", "START", "SECTORS", "READ-ONLY"]]
    part_is_blkdev = -1
    for part in for_each_partition(prog):
        if part_is_blkdev == -1:
            if "block_device" in part.type_.type_name():
                part_is_blkdev = 1
                output[0].append("BLOCK DEVICE")
            else:
                part_is_blkdev = 0
                output[0].append("HD STRUCT")
        if part_is_blkdev == 1:
            output.append(get_partinfo_from_blkdev_struct(part))
        else:
            output.append(get_partinfo_from_hd_struct(part))

    print_table(output)


class PartitionInfo(CorelensModule):
    """
    Corelens Module for partition information
    """

    name = "partitioninfo"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_partition_info(prog)
