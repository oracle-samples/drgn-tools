# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Additional helpers for printk utilities
"""
import argparse
import os
import subprocess
from typing import Optional

from drgn import Program
from drgn.helpers.linux.printk import get_dmesg

from drgn_tools.corelens import CorelensModule


FALLBACK_PAGER = "less"


def dmesg(prog: Program, pager: Optional[str] = None) -> None:
    """
    Display the kernel log in a pager

    The pager is selected in the following manner. First, if the pager argument
    is provided, that is used. Second, if the ``PAGER`` environment variable is
    defined, that is used. Finally, the fallback value of ``less`` is used.

    :param prog: Program to retrieve log for
    :param pager: Override pager selection
    """
    if pager is None:
        real_pager = os.getenv("PAGER", FALLBACK_PAGER)
    else:
        real_pager = pager
    log = get_dmesg(prog)
    subprocess.run([real_pager], check=True, input=log)


class DmesgModule(CorelensModule):
    """Display the kernel log"""

    name = "dmesg"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print(get_dmesg(prog).decode("utf-8"))
