# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import pytest

from drgn_tools.module import KernelModule
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
        km = KernelModule.find(prog, name)
        if km is not None:
            return km
    pytest.fail("No common kernel module found in program")


def test_not_exist(prog):
    assert KernelModule.find(prog, "i am not a module") is None


def test_list_modules(prog):
    # smoke test
    mods = list(KernelModule.all(prog))
    assert len(mods) > 1


def test_module_memory(prog, common_mod):
    # smoke test
    common_mod.address_regions()


def test_module_build_id(prog, common_mod):
    # smoke test
    build_id = common_mod.build_id()
    assert isinstance(build_id, str)
    assert len(build_id) == 40


def test_module_exports_and_symbols(prog, common_mod):
    # smoke test
    exports = module_exports(common_mod.obj)
    assert exports
    kallsyms = common_mod.symbols()
    assert kallsyms
    unified = common_mod.unified_symbols()
    assert unified
