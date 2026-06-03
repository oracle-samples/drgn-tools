# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import vectorinfo
from tests import DrgnToolsTestCase
from tests import skip_kernel_versions_below


class TestVectorinfo(DrgnToolsTestCase):
    @skip_kernel_versions_below("5.4")
    def test_vectorinfo(self):
        if self.kver.arch != "x86_64":
            self.skipTest("Only x86_64 is supported")
        vectorinfo.print_vector_matrix(self.prog)
        vectorinfo.print_vectors(self.prog, True)
