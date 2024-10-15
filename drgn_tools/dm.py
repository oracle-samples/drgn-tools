# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for device mapper devices.
"""
import argparse
from typing import Iterable
from typing import Tuple

from drgn import cast
from drgn import Object
from drgn import Program
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry

from drgn_tools.block import blkdev_name
from drgn_tools.corelens import CorelensModule
from drgn_tools.module import ensure_debuginfo
from drgn_tools.table import print_table
from drgn_tools.util import BitNumberFlags
from drgn_tools.util import kernel_version


def for_each_dm_hash(prog: Program) -> Iterable[Tuple[Object, str, str]]:
    for head in prog["_name_buckets"]:
        for hc in list_for_each_entry(
            "struct hash_cell", head.address_of_(), "name_list"
        ):
            uuid = ""
            if hc.uuid:
                uuid = hc.uuid.string_().decode()

            yield hc.md, hc.name.string_().decode(), uuid


def for_each_dm_rbtree(prog: Program) -> Iterable[Tuple[Object, str, str]]:
    for hc in rbtree_inorder_for_each_entry(
        "struct hash_cell", prog["name_rb_tree"], "name_node"
    ):
        uuid = ""
        if hc.uuid:
            uuid = hc.uuid.string_().decode()

        yield hc.md, hc.name.string_().decode(), uuid


def for_each_dm(prog: Program) -> Iterable[Tuple[Object, str, str]]:
    if "_name_buckets" in prog:
        return for_each_dm_hash(prog)
    elif "name_rb_tree" in prog:
        return for_each_dm_rbtree(prog)
    else:
        raise NotImplementedError("Cannot find dm devices")


class DmFlagsBits(BitNumberFlags):
    """
    Class to convert preprocessor definitions to enum

    drgn can't get the value of preprocessor definitions.
    This is only appliable to the kernel starting 8ae126660fdd
    which was merged by v4.10
    """

    BLOCK_IO_FOR_SUSPEND = 0
    SUSPENDED = 1
    FROZEN = 2
    FREEING = 3
    DELETING = 4
    NOFLUSH_SUSPENDING = 5
    DEFERRED_REMOVE = 6
    SUSPENDED_INTERNALLY = 7
    POST_SUSPENDING = 8
    EMULATE_ZONE_APPEND = 9


class DmFlagsBitsOld(BitNumberFlags):
    """only appliable to kernel older than v4.10"""

    BLOCK_IO_FOR_SUSPEND = 0
    SUSPENDED = 1
    FROZEN = 2
    FREEING = 3
    DELETING = 4
    NOFLUSH_SUSPENDING = 5
    MERGE_IS_OPTIONAL = 6
    DEFERRED_REMOVE = 7
    SUSPENDED_INTERNALLY = 8


def dm_flags(dm: Object) -> str:
    if kernel_version(dm.prog_) < (4, 10, 0):
        return DmFlagsBitsOld.decode(int(dm.flags))
    else:
        return DmFlagsBits.decode(int(dm.flags))


def show_dm(prog: Program) -> None:
    msg = ensure_debuginfo(prog, ["dm_mod"])
    if msg:
        print(msg)
        return

    output = [["NUMBER", "NAME", "MAPPED_DEVICE", "FLAGS"]]
    for dm, name, uuid in for_each_dm(prog):
        output.append(
            [
                dm.disk.disk_name.string_().decode(),
                name,
                hex(dm.value_()),
                dm_flags(dm),
            ]
        )
    print_table(output)


def dm_table(dm: Object) -> Object:
    """
    return the ``struct dm_table *``

    There were two definitions of ``struct dm_table`` before commit
    1d3aa6f683b1("dm: remove dummy definition of 'struct dm_table'")
    which was included in v4.10, specify file for the correct symbol.
    """
    if kernel_version(dm.prog_) < (4, 10, 0):
        table_type = dm.prog_.type(
            "struct dm_table *", "drivers/md/dm-table.c"
        )
        return cast(table_type, dm.map)
    else:
        return cast("struct dm_table *", dm.map)


def dm_target_name(dm: Object) -> str:
    table = dm_table(dm)
    if table.value_() == 0x0:
        return "None"
    return table.targets.type.name.string_().decode()


def show_table_linear(dm: Object, name: str) -> None:
    table = dm_table(dm)
    for tid in range(table.num_targets):
        target = table.targets[tid]
        dev = cast("struct linear_c *", target.private)
        print(
            "%s: %d %d linear %d:%d [%s] %d"
            % (
                name,
                int(target.begin),
                int(target.len),
                dev.dev.bdev.bd_dev >> 20,
                dev.dev.bdev.bd_dev & 0xFFFFF,
                blkdev_name(dev.dev.bdev),
                dev.start,
            )
        )


dmtable_handler = {
    "linear": show_table_linear,
}


def show_dm_table(prog: Program) -> None:
    for dm, name, uuid in for_each_dm(prog):
        target_name = dm_target_name(dm)
        if target_name == "None":
            print("dm %s doesn't have a target" % hex(dm.value_()))
            continue
        elif target_name not in dmtable_handler.keys():
            print(
                "dm %s used non-support target %s"
                % (hex(dm.value_()), target_name)
            )
            continue
        else:
            dmtable_handler[target_name](dm, name)


class Dm(CorelensModule):
    """Display info about device mapper devices"""

    name = "dm"
    skip_unless_have_kmod = "dm_mod"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        show_dm(prog)
        show_dm_table(prog)
