# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn_tools.workqueue_lockup as workqueue_lockup


def test_workqueue_lockup(prog):
    workqueue_lockup.scan_workqueue_lockup(prog)
