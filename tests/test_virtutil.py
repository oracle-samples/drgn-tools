# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import virtutil


def test_virtutil(prog):
    virtutil.show_cpuhp_state(prog)
    virtutil.show_platform(prog)
