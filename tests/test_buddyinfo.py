# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import buddyinfo
from tests import DrgnToolsTestCase


class TestBuddyinfo(DrgnToolsTestCase):
    def test_buddyinfo(self):
        buddyinfo.show_all_zones_buddyinfo(self.prog)
