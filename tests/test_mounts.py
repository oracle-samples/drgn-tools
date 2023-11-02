# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from operator import itemgetter

from drgn_tools import mounts
from drgn_tools.table import print_table


def get_proc_mounts():
    fields_0_2_1 = itemgetter(0, 2, 1)
    proc_mount_table = [["DEVNAME", "TYPE", "DIRNAME"]]
    proc_mount_table.append(["-------", "------", "-------"])
    with open("/proc/mounts", "r") as f:
        for line in f.readlines():
            field_0, field_2, field_1 = fields_0_2_1(line.split())
            proc_mount_table.append([field_0, field_2, field_1])
    return proc_mount_table


def test_show_mounts(prog):
    differences = []
    prog_table = mounts.get_mountinfo(prog)
    proc_table = get_proc_mounts()

    for row in prog_table:
        if row not in proc_table:
            differences.append(row)

    difflen = len(differences)
    if difflen > 0:
        print("The /proc/mount is")
        print_table(proc_table)
        print("The mounts from the vmcore are")
        print_table(prog_table)
