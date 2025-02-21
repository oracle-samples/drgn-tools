# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tool import locking


# test for qspinlock
def test_scan_bt_for_spinlocks(prog):
    locking.scan_bt_for_spinlocks(prog, show_unlocked_only=False)
