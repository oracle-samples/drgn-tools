# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn_tools.lsmod as lsmod
from tests import DrgnToolsTestCase


class TestLsmod(DrgnToolsTestCase):
    def test_lsmod(self):
        lsmod.print_module_summary(self.prog)
        lsmod.print_module_parameters(self.prog)
