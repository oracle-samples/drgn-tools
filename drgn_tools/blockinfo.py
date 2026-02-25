# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse

import drgn
from drgn.helpers.linux.block import for_each_disk

from drgn_tools.block import get_inflight_io_nr
from drgn_tools.block import get_max_io_inflight_ns
from drgn_tools.block import queue_freezed_depth
from drgn_tools.block import queue_usage_counter
from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table
from drgn_tools.util import timestamp_str


def print_block_devs_info(prog: drgn.Program) -> None:
    """
    Prints the block device information
    """
    output = [
        [
            "MAJOR",
            "GENDISK",
            "NAME",
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
