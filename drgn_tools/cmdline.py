# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for command line
"""
import argparse

from drgn import Program

from drgn_tools.corelens import CorelensModule


def get_cmdline(prog: Program) -> str:
    """
    Returns the kernel command line
    """
    str_cmdline = prog["saved_command_line"]
    return str_cmdline.string_().decode("utf-8")


def show_cmdline(prog: Program) -> None:
    str_cmdline = get_cmdline(prog)
    print(str_cmdline)


class CmdLine(CorelensModule):
    """Display the kernel command line"""

    name = "cmdline"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        show_cmdline(prog)
