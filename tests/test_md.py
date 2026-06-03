# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import md
from tests import DrgnToolsTestCase


class TestMd(DrgnToolsTestCase):
    def test_show_md(self):
        md.show_md(self.prog)
