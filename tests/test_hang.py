# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import hang


def test_hang(prog):
    hang.detect_hang(prog, stack=True, time=10)
