# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import lockup
from tests import DrgnToolsTestCase


class TestLockup(DrgnToolsTestCase):
    def test_lockup(self):
        lockup.scan_lockup(self.prog)
