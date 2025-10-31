# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import pytest

from drgn_tools import vectorinfo


def test_vectorinfo(prog, kver):
    if kver.arch != "x86_64":
        pytest.skip("Only x86_64 is supported")
    if kver.uek_version is not None and kver.uek_version < 6:
        pytest.skip("UEK6 or later is required")
    vectorinfo.print_vector_matrix(prog)
    vectorinfo.print_vectors(prog, True)
