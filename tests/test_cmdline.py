# Copyright (c) 2023, 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import cmdline
from tests import DrgnToolsTestCase
from tests import skip_unless_live


class TestCmdline(DrgnToolsTestCase):
    @skip_unless_live
    def test_cmdline(self):
        with open("/proc/cmdline", "r") as f:
            found = f.read().rstrip("\n")
        self.assertEqual(cmdline.get_cmdline(self.prog), found)

    def test_cmdline_smoke(self):
        cmdline.get_cmdline(self.prog)
