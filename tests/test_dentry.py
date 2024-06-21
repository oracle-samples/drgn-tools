# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn_tools.dentry as dentry
from drgn_tools.itertools import take

LIMIT = 5


def test_for_each_dentry_in_hashtable(prog):
    it = dentry.for_each_dentry_in_hashtable(prog)
    for d in take(LIMIT, it):
        assert d.type_.type_name() == "struct dentry *"


def test_list_dentries_in_hashtable(prog):
    dentry.list_dentries_in_hashtable(prog, LIMIT)


def test_ls(prog):
    dentry.ls(prog, "/")
