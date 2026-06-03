# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import virtutil
from tests import DrgnToolsTestCase


class TestVirtutil(DrgnToolsTestCase):
    def test_virtutil(self):
        virtutil.show_cpuhp_state(self.prog)
        virtutil.show_platform(self.prog)
