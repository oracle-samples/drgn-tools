# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import pytest

import drgn_tools.nfs_tools
from drgn_tools.module import KernelModule


def test_nfs(prog):
    nfs = KernelModule.find(prog, "nfs")
    if not nfs:
        pytest.skip("NFS module not loaded")

    # This is just a smoke test
    drgn_tools.nfs_tools.nfsshow(prog)
