# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import pytest

from drgn_tools import memstate


def test_memstate(prog, kver):
    if kver.uek_version is not None and kver.uek_version <= 4:
        pytest.skip("Unsupported kernel version")
    memstate.run_memstate(prog)
