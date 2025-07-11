# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import pytest

import drgn_tools.nfs_tools


def test_nfs(prog):
    try:
        prog.module("nfs")
    except LookupError:
        pytest.skip("NFS module not loaded")

    # This is just a smoke test
    drgn_tools.nfs_tools.nfsshow(prog)
