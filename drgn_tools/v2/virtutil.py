# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse

from drgn import Program

from drgn_tools.corelens import CorelensModule
from drgn_tools.virtutil import show_platform


class VirtUtil(CorelensModule):
    """
    This module contains helper regarding virtualization.
    Current functionality are :
    cpu hotplug state
    platform type, which includes architecture and hypervisor type
    """

    name = "virt"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        show_platform(prog)
        return
