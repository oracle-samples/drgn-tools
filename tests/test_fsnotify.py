# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools.fsnotify import fsnotify_show
from tests import DrgnToolsTestCase


class TestFsnotify(DrgnToolsTestCase):
    def test_fsnotify(self):
        fsnotify_show(self.prog)
