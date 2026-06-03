# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import rds
from tests import DrgnToolsTestCase


class TestRds(DrgnToolsTestCase):
    def test_run_rds(self):
        verbose = True
        rds.report(self.prog, verbose)
        rds.rds_ib_conn_ring_info(self.prog, 0xDEADBEEF)
