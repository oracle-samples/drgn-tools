# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn_tools.lsmod as lsmod


def test_lsmod(prog):
    lsmod.print_module_summary(prog)
    lsmod.print_module_parameters(prog)
