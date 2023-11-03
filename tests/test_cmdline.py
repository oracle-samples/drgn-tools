# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import cmdline


def test_cmdline(prog):
    cmdline.get_cmdline(prog)
    cmdline.show_cmdline(prog)
