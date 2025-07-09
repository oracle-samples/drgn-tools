# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import pytest

from drgn_tools.module import module_exports


@pytest.fixture
def common_mod(prog):
    COMMON_MODS = [
        "nf_nat",
        "ib_core",
        "9pnet",
        "libcrc32c",
    ]
    for name in COMMON_MODS:
        try:
            return prog.module(name).object
        except LookupError:
            pass
    pytest.fail("No common kernel module found in program")


def test_module_exports(prog, common_mod):
    # smoke test
    assert module_exports(common_mod)
