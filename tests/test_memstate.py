# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import memstate
from tests import DrgnToolsTestCase
from tests import skip_kernel_versions_below


class TestMemstate(DrgnToolsTestCase):
    @skip_kernel_versions_below("4.14")
    def test_memstate(self):
        memstate.run_memstate(self.prog)
