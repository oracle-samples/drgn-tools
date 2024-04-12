# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse

from drgn import Program

from drgn_tools.corelens import CorelensModule
from drgn_tools.scsi import print_scsi_hosts


class ScsiInfo(CorelensModule):
    """
    Corelens Module for scsi device information
    """

    name = "scsiinfo"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_scsi_hosts(prog)
