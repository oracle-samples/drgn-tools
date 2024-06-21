# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for dentries.
"""
import argparse
import stat
from typing import Iterable
from typing import Iterator
from typing import Optional

import drgn
from drgn import Object
from drgn import Program
from drgn.helpers.linux.fs import path_lookup
from drgn.helpers.linux.list import hlist_for_each_entry
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.corelens import CorelensModule
from drgn_tools.itertools import count
from drgn_tools.itertools import take
from drgn_tools.table import FixedTable
from drgn_tools.util import kernel_version


MNT_INTERNAL = 0x4000


def dentry_for_each_child(dentry: Object) -> Iterator[Object]:
    """
    Iterate over every child of a dentry
    """
    # Commit da549bdd15c29 ("dentry: switch the lists of children to hlist")
    # changes the list names and types. Try the older names first since all UEK
    # versions have the older names.
    try:
        return list_for_each_entry(
            "struct dentry",
            dentry.d_subdirs.address_of_(),
            "d_child",
        )
    except AttributeError:
        return hlist_for_each_entry(
            "struct dentry",
            dentry.d_children.address_of_(),
            "d_sib",
        )


def sb_first_mount_point(sb: Object) -> Optional[Object]:
    """
    Return the first mountpoint of the superblock

    A single filesystem instance can be mounted at several locations, so the
    super_block has a list of instances. When iterating over the dentry cache,
    we want the full path and don't care too much about _which_ path we get. We
    just want to have a valid filesystem path. So return any arbitrary mount
    point, the first one in the list. If the list is empty (unlikely except
    during an unmount race) or if we are at the root filesystem, return None.

    :param sb: ``struct super_block *``
    :returns: ``struct dentry *`` or None
    """
    for mount in list_for_each_entry(
        "struct mount", sb.s_mounts.address_of_(), "mnt_instance"
    ):
        mnt_parent = mount.mnt_parent.read_()
        if mount.mnt.mnt_flags & MNT_INTERNAL:
            continue
        if mnt_parent == mount:
            return None
        return mount.mnt_mountpoint.read_()
    return None


def dentry_path_any_mount(dentry: Object) -> bytes:
    """
    Like dentry_path(), but don't require a path/mount. Just pick one
    arbitrarily

    :param dentry: ``struct dentry *``
    """
    dentry = dentry.read_()
    d_op = dentry.d_op.read_()
    if d_op and d_op.d_dname:
        return b"[" + dentry.d_inode.i_sb.s_type.name.string_() + b"]"

    components = []
    while True:
        # reading dentry_val allows us to get all the fields of dentry at once
        dentry_val = dentry[0].read_()
        if dentry_val.d_parent == dentry:
            dentry = sb_first_mount_point(dentry_val.d_sb)
            if not dentry:
                break
            else:
                continue
        d_parent = dentry_val.d_parent
        components.append(dentry_val.d_name.name.string_())
        components.append(b"/")
        dentry = d_parent
    if components:
        return b"".join(reversed(components))
    else:
        return b"/"


def for_each_dentry_in_hashtable(prog: Program) -> Iterator[Object]:
    """
    Get all the dentries in dentry hashtable

    :returns: A generator of ``struct dentry *``
    """
    return __dentry_iter(prog)


def for_each_used_dentry_in_hashtable(prog: Program) -> Iterator[Object]:
    """
    Get only the used dentries in dentry hashtable

    :returns: A generator of ``struct dentry *``
    """
    for dentry in __dentry_iter(prog):
        if dentry_is_used(dentry):
            yield dentry


def for_each_unused_dentry_in_hashtable(prog: Program) -> Iterator[Object]:
    """
    Get only the unused dentries in dentry hashtable

    :returns: A generator of ``struct dentry *``
    """
    for dentry in __dentry_iter(prog):
        if dentry_is_unused(dentry):
            yield dentry


def for_each_negative_dentry_in_hashtable(prog: Program) -> Iterator[Object]:
    """
    Get only the negative dentries in dentry hashtable

    :returns: A generator of ``struct dentry *``
    """
    for dentry in __dentry_iter(prog):
        if dentry_is_negative(dentry):
            yield dentry


def count_dentries_in_hashtable(prog: Program) -> int:
    """
    Count the total number of dentries in hashtable

    :returns: An integer representing the total number of dentries in hashtable
    """
    return count(for_each_dentry_in_hashtable(prog))


def count_unused_dentries_in_hashtable(prog: Program) -> int:
    """
    Count the number of unused dentries in hashtable

    :returns: An integer representing the number of unused dentries in hashtable
    """
    return count(for_each_unused_dentry_in_hashtable(prog))


def count_used_dentries_in_hashtable(prog: Program) -> int:
    """
    Count the number of used dentries in hashtable

    :returns: An integer representing the number of used dentries in hashtable
    """
    return count(for_each_used_dentry_in_hashtable(prog))


def count_negative_dentries_in_hashtable(prog: Program) -> int:
    """
    Count the number of negative dentries in hashtable

    :returns: An integer representing the number of negative dentries in hashtable
    """
    return count(for_each_negative_dentry_in_hashtable(prog))


def list_dentries_in_hashtable(prog: Program, limit: Optional[int]) -> None:
    """
    List all dentries in hashtable along with their stats

    :param limit: Number of dentries to list.
    """
    dentries = for_each_dentry_in_hashtable(prog)
    if limit:
        dentries = take(limit, dentries)
    print_dentry_table(dentries)


def list_used_dentries_in_hashtable(
    prog: Program, limit: Optional[int]
) -> None:
    """
    List used dentries in hashtable along with their stats

    :param limit: Number of dentries to list.
    """
    dentries = for_each_used_dentry_in_hashtable(prog)
    if limit:
        dentries = take(limit, dentries)
    print_dentry_table(dentries)


def list_unused_dentries_in_hashtable(
    prog: Program, limit: Optional[int]
) -> None:
    """
    List unused dentries in hashtable along with their stats

    :param limit: Number of dentries to list.
    """
    dentries = for_each_unused_dentry_in_hashtable(prog)
    if limit:
        dentries = take(limit, dentries)
    print_dentry_table(dentries, False)


def list_negative_dentries_in_hashtable(
    prog: Program, limit: Optional[int]
) -> None:
    """
    List negative dentries in hashtable along with their stats

    :param limit: Number of dentries to list.
    """
    dentries = for_each_negative_dentry_in_hashtable(prog)
    if limit:
        dentries = take(limit, dentries)
    print_dentry_table(dentries, False)


def print_dentry_table(
    dentries: Iterable[Object], refcount: bool = True
) -> None:
    """
    Prints a table of dentries

    :param dentries: Any iterable of ``struct dentry *``
    """

    if refcount:
        table = FixedTable(
            [
                "DENTRY:016x",
                "SUPER_BLOCK:016x",
                "INODE:016x",
                "CNT:>",
                "TYPE",
                "PATH",
            ]
        )
    else:
        table = FixedTable(
            ["DENTRY:016x", "SUPER_BLOCK:016x", "INODE:016x", "TYPE", "PATH"]
        )
    for d in dentries:
        file_type = __file_type(int(d.d_inode.i_mode)) if d.d_inode else "NONE"
        if refcount:
            table.row(
                d.value_(),
                d.d_sb.value_(),
                d.d_inode.value_(),
                int(d_count(d)),
                file_type,
                dentry_path_any_mount(d).decode(),
            )
        else:
            table.row(
                d.value_(),
                d.d_sb.value_(),
                d.d_inode.value_(),
                file_type,
                dentry_path_any_mount(d).decode(),
            )


def dentry_is_used(dentry: Object) -> bool:
    """
    Check if a dentry is used

    :param dentry: A ``struct dentry *``
    :returns: True if used
    """
    return dentry.d_inode and d_count(dentry) > 0


def dentry_is_unused(dentry: Object) -> bool:
    """
    Check if a dentry is unused

    :param dentry: A ``struct dentry *``
    :returns: True if unused
    """
    return dentry.d_inode and d_count(dentry) == 0


def dentry_is_negative(dentry: Object) -> bool:
    """
    Check if a dentry is negative

    :param dentry: A ``struct dentry *``
    :returns: True if negative
    """
    return not dentry.d_inode


def d_count(dentry: Object) -> int:
    """
    Count the number of references of a dentry

    :param dentry: A ``struct dentry *``
    :returns: An integer representing the count.
    """
    return dentry.d_lockref.count


def __dentry_iter(prog: Program, chunk_size: int = 2048) -> Iterator[Object]:
    """Iterate through the hashtable"""
    dentry_hashtable = prog["dentry_hashtable"].read_()

    # Commit 854d3e63438d ("dcache: subtract d_hash_shift from 32 in advance")
    # changes the logical meaning of d_hash_shift with absolutely no detectable
    # change to any type or symbol. It was first included in 4.16 and has never
    # been backported to any stable kernel release or UEK. There is simply no
    # other way to know how to interpret d_hash_shift, except by using the
    # kernel version. Thankfully, it's just a simply comparison against 4.16.
    if kernel_version(prog) < (4, 16, 0):
        dentry_hashtable_size = 2 ** (int(prog["d_hash_shift"]))
    else:
        dentry_hashtable_size = 2 ** (32 - int(prog["d_hash_shift"]))

    if dentry_hashtable_size % chunk_size != 0:
        raise ValueError("chunk size is too big")

    # iterate though the hashtable chunk by chunk
    chunk_type = prog.array_type(dentry_hashtable[0].type_, chunk_size)
    for chunk_start in range(0, dentry_hashtable_size, chunk_size):
        array_chunk = drgn.Object(
            prog, chunk_type, address=dentry_hashtable + chunk_start
        ).read_()
        for i in range(chunk_size):
            bucket = array_chunk[i]
            d_hash = bucket.first
            while d_hash:
                dentry = drgn.container_of(d_hash, "struct dentry", "d_hash")
                yield dentry
                d_hash = d_hash.next.read_()


def __file_type(mode: Object) -> str:
    """Get the file type"""
    if stat.S_ISREG(mode):
        return "REG"
    elif stat.S_ISDIR(mode):
        return "DIR"
    elif stat.S_ISLNK(mode):
        return "LNK"
    elif stat.S_ISCHR(mode):
        return "CHR"
    elif stat.S_ISBLK(mode):
        return "BLK"
    elif stat.S_ISFIFO(mode):
        return "FIFO"
    elif stat.S_ISSOCK(mode):
        return "SOCK"
    elif stat.S_ISDOOR(mode):
        return "DOOR"
    elif stat.S_ISPORT(mode):
        return "PORT"
    elif stat.S_ISWHT(mode):
        return "WHT"

    return "UNKN"


def ls(prog: Program, directory: str, count: bool = False) -> None:
    """
    Print dentry children, like the ls command
    :param directory: directory to print children of
    :param count: when true, only print counts (not the full contents)
    """
    dentries = dentry_for_each_child(path_lookup(prog, directory).dentry)

    pos = neg = 0
    for i, dentry in enumerate(dentries):
        path = dentry_path_any_mount(dentry).decode()
        if dentry_is_negative(dentry):
            neg += 1
        else:
            pos += 1
        if not count:
            print(f"{i:05d} {path}")
    print(f"{pos} positive, {neg} negative dentries")


class Ls(CorelensModule):
    """List or count child dentries given a file path"""

    name = "ls"

    # This module shouldn't run for corelens reports, because it has a required
    # argument. It's quite useful to run it interactively though.
    run_when = "never"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "directory",
            type=str,
            help="directory to list",
        )
        parser.add_argument(
            "--count",
            "-c",
            action="store_true",
            help="only print counts, rather than every element",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        ls(prog, args.directory, count=args.count)


class DentryCache(CorelensModule):
    """List dentries from the dentry hash table"""

    name = "dentrycache"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--limit",
            "-l",
            type=int,
            default=50,
            help="list at most <number> dentries, 50 by default",
        )
        parser.add_argument(
            "--negative",
            "-n",
            action="store_true",
            help="list negative dentries only, disabled by default",
        )
        parser.add_argument(
            "--detailed",
            "-d",
            action="store_true",
            help="include inode, super, file type, refcount",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if args.negative:
            dentries = for_each_negative_dentry_in_hashtable(prog)
        else:
            dentries = for_each_dentry_in_hashtable(prog)

        if args.limit:
            dentries = take(args.limit, dentries)

        if args.detailed:
            print_dentry_table(dentries)
        else:
            # Emulate oled dentrycache
            for i, dentry in enumerate(dentries):
                path = dentry_path_any_mount(dentry).decode()
                print(f"{i:05d} {path}")
