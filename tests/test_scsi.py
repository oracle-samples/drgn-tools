# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import scsi
from tests import DrgnToolsTestCase


class TestScsi(DrgnToolsTestCase):
    def test_scsi(self):
        scsi.print_scsi_hosts(self.prog)
