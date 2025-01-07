# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import iscsi


def test_iscsi(prog):
    iscsi.dump_iscsi_sessions(prog)
