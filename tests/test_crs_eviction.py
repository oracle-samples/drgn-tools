# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import crs_eviction


def test_crs_eviction(prog):
    crs_eviction.scan_crs_eviction(prog)
