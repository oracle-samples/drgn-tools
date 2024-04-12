# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import dm


def test_show_dm(prog):
    dm.show_dm(prog)
    dm.show_dm_table(prog)
