# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from operator import itemgetter

from drgn_tools import mounts
from tests import DrgnToolsTestCase
from tests import skip_unless_live


def get_proc_mounts():
    fields_0_2_1 = itemgetter(0, 2, 1)
    proc_mount_table = list()
    with open("/proc/mounts", "r") as f:
        for line in f.readlines():
            field_0, field_2, field_1 = fields_0_2_1(line.split())
            proc_mount_table.append([field_0, field_2, field_1])
    return proc_mount_table


class TestMounts(DrgnToolsTestCase):
    def test_print_mounts(self):
        mounts.mountinfo(self.prog)

    @skip_unless_live
    def test_show_mounts(self):
        prog_table = mounts.get_mountinfo(self.prog)
        proc_table = get_proc_mounts()

        for row in proc_table:
            self.assertIn(row, prog_table)
