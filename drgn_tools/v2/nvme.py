# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse

from drgn import Program

from drgn_tools.corelens import CorelensModule
from drgn_tools.nvme import show_ctrl_info
from drgn_tools.nvme import show_firmware_info
from drgn_tools.nvme import show_msi_mask
from drgn_tools.nvme import show_ns_info
from drgn_tools.nvme import show_queue_info
from drgn_tools.nvme import show_queue_map


class NvmeModule(CorelensModule):
    """Show various details about the NVME subsystem"""

    name = "nvme"
    skip_unless_have_kmod = "nvme"

    debuginfo_kmods = ["nvme", "nvme_core"]

    default_args = [
        [
            "--firmware",
            "--ctrl",
            "--queue",
            "--namespace",
            "--queuemap",
            "--msimask",
        ]
    ]

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--firmware", action="store_true", help="Print firmware info"
        )
        parser.add_argument(
            "--ctrl",
            action="store_true",
            help="Print nvme controller information",
        )
        parser.add_argument(
            "--queue", action="store_true", help="Print nvme queue info"
        )
        parser.add_argument(
            "--namespace",
            action="store_true",
            help="Print nvme namespace info",
        )
        parser.add_argument(
            "--queuemap",
            action="store_true",
            help="Print nvme hw->sw ctx info",
        )
        parser.add_argument(
            "--msimask",
            action="store_true",
            help="Print MSI mask for each nvmeq",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if args.firmware:
            show_firmware_info(prog)
            print()
        if args.ctrl:
            show_ctrl_info(prog)
            print()
        if args.queue:
            show_queue_info(prog)
            print()
        if args.namespace:
            show_ns_info(prog)
            print()
        if args.queuemap:
            show_queue_map(prog)
            print()
        if args.msimask:
            show_msi_mask(prog)
            print()
