# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse

from drgn import Program

from drgn_tools.corelens import CorelensModule
from drgn_tools.irq import print_all_irqs


class IrqModule(CorelensModule):
    """Print basic IRQ information"""

    name = "irq"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_all_irqs(prog)
