# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from operator import itemgetter

import pytest

from drgn_tools import mounts


def test_print_mounts(prog):
    mounts.mountinfo(prog)


def get_proc_mounts():
    fields_0_2_1 = itemgetter(0, 2, 1)
    proc_mount_table = list()
    with open("/proc/mounts", "r") as f:
        for line in f.readlines():
            field_0, field_2, field_1 = fields_0_2_1(line.split())
            proc_mount_table.append([field_0, field_2, field_1])
    return proc_mount_table


@pytest.mark.skip_vmcore("*")
def test_show_mounts(prog):
    prog_table = mounts.get_mountinfo(prog)
    proc_table = get_proc_mounts()

    for row in proc_table:
        assert row in prog_table
