# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import ext4_dirlock
from tests import DrgnToolsTestCase


class TestExt4Dirlock(DrgnToolsTestCase):
    def test_ext4_dirlock_scan(self):
        ext4_dirlock.ext4_dirlock_scan(self.prog)
        ext4_dirlock.ext4_dirlock_scan(self.prog, True)
