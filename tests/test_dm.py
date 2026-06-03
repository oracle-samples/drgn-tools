# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import dm
from tests import DrgnToolsTestCase


class TestDm(DrgnToolsTestCase):
    def test_show_dm(self):
        dm.show_dm(self.prog)
        dm.show_dm_table(self.prog)
