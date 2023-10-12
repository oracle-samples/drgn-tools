# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for dentries.
"""
import stat
from typing import Iterable
from typing import Iterator
from typing import Optional

import drgn
from drgn import Object
from drgn import Program
from drgn.helpers.linux.fs import dentry_path

from drgn_tools.itertools import count
from drgn_tools.itertools import take
from drgn_tools.table import print_table


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
        dentry_table = [
            ["DENTRY", "SUPER_BLOCK", "INODE", "REFCOUNT", "TYPE", "PATH"]
        ]
    else:
        dentry_table = [["DENTRY", "SUPER_BLOCK", "INODE", "TYPE", "PATH"]]
    for d in dentries:
        file_type = __file_type(int(d.d_inode.i_mode)) if d.d_inode else "NONE"
        if refcount:
            dentry_stats = [
                hex(d.value_()),
                hex(d.d_sb.value_()),
                hex(d.d_inode.value_()),
                int(d_count(d)),
                file_type,
                dentry_path(d).decode(),
            ]
        else:
            dentry_stats = [
                hex(d.value_()),
                hex(d.d_sb.value_()),
                hex(d.d_inode.value_()),
                file_type,
                dentry_path(d).decode(),
            ]
        dentry_table.append(dentry_stats)
    print_table(dentry_table)


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


def __dentry_iter(prog: Program) -> Iterator[Object]:
    """Iterate through the hashtable"""
    dentry_hashtable = prog["dentry_hashtable"]
    # for uek5 and newer
    dentry_hashtable_size = 2 ** (32 - int(prog["d_hash_shift"].read_()))
    # for uek4
    if not prog.symbols("in_lookup_hashtable"):
        dentry_hashtable_size = 2 ** (int(prog["d_hash_shift"].read_()))

    # iterate though the hashtable bucket by bucket
    for i in range(dentry_hashtable_size):
        bucket = dentry_hashtable[i]
        d_hash = bucket.first
        while d_hash:
            dentry = drgn.container_of(d_hash, "struct dentry", "d_hash")
            yield dentry
            d_hash = d_hash.next


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
