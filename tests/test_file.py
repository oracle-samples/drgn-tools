# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn_tools.file as file
from tests import DrgnToolsTestCase
from tests import skip_kernel_versions_below


class TestFile(DrgnToolsTestCase):
    def test_filecache_dump(self):
        # smoke test
        file.filecache_dump(self.prog, 10, 10)

    @skip_kernel_versions_below("4.14")  # skip UEK4
    def test_for_each_file_system_page_in_pagecache(self):
        # smoke test
        for fst in file.for_each_file_system(self.prog):
            for page in file.for_each_file_system_page_in_pagecache(fst):
                break
