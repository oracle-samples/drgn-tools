# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn_tools.file as file


def test_filecache_dump(prog):
    # smoke test
    file.filecache_dump(prog, 10, 10)


def test_for_each_file_system_page_in_pagecache(prog):
    # smoke test
    fst = prog["file_systems"].next
    file.for_each_file_system_page_in_pagecache(fst)
