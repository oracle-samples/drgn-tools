# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse

from drgn import Program

from drgn_tools.corelens import CorelensModule
from drgn_tools.virtio import virtio_show


class Virtio(CorelensModule):
    """Show details of each virtio device, and optionally virtqueues"""

    name = "virtio"
    debuginfo_kmods = ["*virtio*"]
    default_args = [["--show-vq"]]

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--show-vq",
            action="store_true",
            help="show vrings in output",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        virtio_show(prog, show_vq=args.show_vq)
