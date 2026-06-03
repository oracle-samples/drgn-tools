# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn_tools.sysctl as sysctl
from tests import DrgnToolsTestCase


class TestSysctl(DrgnToolsTestCase):
    def test_get_sysctl_table(self):
        # smoke test
        sysctl_table = sysctl.get_sysctl_table(self.prog)
        assert len(sysctl_table) > 10
