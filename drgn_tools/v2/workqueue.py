# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse

from drgn import Program

from drgn_tools.corelens import CorelensModule
from drgn_tools.workqueue import show_all_workqueues


class WorkqueueModule(CorelensModule):
    """Show details about all workqueues"""

    name = "wq"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        show_all_workqueues(prog)
