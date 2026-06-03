# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import blockinfo
from tests import DrgnToolsTestCase


class TestBlockinfo(DrgnToolsTestCase):
    def test_blockinfo(self):
        blockinfo.print_block_devs_info(self.prog)
