# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import iscsi
from tests import DrgnToolsTestCase


class TestIscsi(DrgnToolsTestCase):
    def test_iscsi(self):
        iscsi.print_iscsi_sessions(self.prog)
