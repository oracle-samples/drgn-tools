# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse

from drgn import Program

from drgn_tools.corelens import CorelensModule
from drgn_tools.multipath import show_mp


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
