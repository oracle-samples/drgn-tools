# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn_tools.nfs_tools
from tests import DrgnToolsTestCase


class TestNfsTools(DrgnToolsTestCase):
    def test_nfs(self):
        try:
            self.prog.module("nfs")
        except LookupError:
            self.skipTest("NFS module not loaded")

        # This is just a smoke test
        drgn_tools.nfs_tools.nfsshow(self.prog)
