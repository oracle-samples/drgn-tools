# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import spinlock


# test for qspinlock
def test_scan_bt_for_spinlocks(prog):
    spinlock.scan_bt_for_owners(prog)
