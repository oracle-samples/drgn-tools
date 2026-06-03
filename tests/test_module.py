# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools.module import module_exports
from tests import DrgnToolsTestCase


class TestModule(DrgnToolsTestCase):
    COMMON_MODS = [
        "drgntools_test",
        "nf_nat",
        "ib_core",
        "9pnet",
        "libcrc32c",
    ]

    def common_mod(self):
        for name in self.COMMON_MODS:
            try:
                return self.prog.module(name).object
            except LookupError:
                pass
        self.fail("No common kernel module found in program")

    def test_module_exports(self):
        # smoke test
        assert module_exports(self.common_mod())
