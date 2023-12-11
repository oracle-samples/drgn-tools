# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import buddyinfo


def test_meminfo(prog):
    buddyinfo.show_all_zones_buddyinfo(prog)
