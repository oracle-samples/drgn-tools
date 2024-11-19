# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import targetcli


def test_targetcli(prog):
    targetcli.dump_targetcli(prog)
