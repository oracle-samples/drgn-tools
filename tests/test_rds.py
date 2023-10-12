# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import rds


def test_run_rds(prog):
    rds.report(prog)
    rds.rds_ib_conn_ring_info(prog, 0xDEADBEEF)
