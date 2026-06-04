# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn_tools.dentry as dentry
from drgn_tools.itertools import take
from tests import DrgnToolsTestCase

LIMIT = 5


class TestDentry(DrgnToolsTestCase):
    def test_for_each_dentry_in_hashtable(self):
        it = dentry.for_each_dentry_in_hashtable(self.prog)
        for d in take(LIMIT, it):
            self.assertEqual(d.type_.type_name(), "struct dentry *")

    def test_list_dentries_in_hashtable(self):
        dentry.list_dentries_in_hashtable(self.prog, LIMIT)

    def test_ls(self):
        dentry.ls(self.prog, "/", None, 0)
