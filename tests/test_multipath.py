# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import multipath
from tests import DrgnToolsTestCase


class TestMultipath(DrgnToolsTestCase):
    def test_show_mp(self):
        multipath.show_mp(self.prog)
