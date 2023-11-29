# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
from typing import List

import drgn.helpers.linux.fs

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table


def get_mountinfo(prog: drgn.Program) -> List[List[str]]:
    """
    Get all the mount points from the vmcore

    :param prog: drgn program
    :returns: List of mount points
    """

    mount_table = list()

    mounts = prog["init_task"].nsproxy.mnt_ns
    for mnt in drgn.helpers.linux.fs.for_each_mount(mounts):
        devname = mnt.mnt_devname
        fstype = mnt.mnt.mnt_sb.s_type.name
        mntpt = drgn.helpers.linux.fs.d_path(
            mnt.mnt.address_of_(), mnt.mnt_mountpoint
        )

        mount_stats = [
            devname.string_().decode("utf-8"),
            fstype.string_().decode("utf-8"),
            mntpt.decode("utf-8"),
        ]
        mount_table.append(mount_stats)
    return mount_table


def mountinfo(prog: drgn.Program) -> None:
    """
    Print all the mount points from the vmcore

    :param prog: drgn program
    :returns: None
    """
    mnt_tbl = get_mountinfo(prog)
    mnt_tbl.insert(0, ["-------", "------", "-------"])
    mnt_tbl.insert(0, ["DEVNAME", "TYPE", "DIRNAME"])
    print_table(mnt_tbl)


class Mounts(CorelensModule):
    """Print info about all mount points"""

    name = "mounts"

    def run(self, prog: drgn.Program, args: argparse.Namespace) -> None:
        mountinfo(prog)
