# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for file cache.
"""
import argparse
from typing import Iterator
from typing import List
from typing import Tuple
from typing import Union

import drgn
from drgn import cast
from drgn import container_of
from drgn import Object
from drgn import Program
from drgn.helpers.linux import d_path
from drgn.helpers.linux.list import hlist_empty
from drgn.helpers.linux.list import hlist_for_each_entry
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.radixtree import radix_tree_for_each
from drgn.helpers.linux.xarray import xa_for_each

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table
from drgn_tools.util import human_bytes


def for_each_inode_page_in_pagecache(
    inode: Object,
) -> Iterator[Object]:
    """
    Walk through pages of page cache in an inode

    :param inode: ``struct inode *``
    :returns: A generator of ``struct page *``
    """
    return inode_page_dump(inode)


def for_each_superblock_page_in_pagecache(sb: Object) -> Iterator[Object]:
    """
    Walk through pages of page cache in a superblock

    :param sb: ``struct super_block *``
    :returns: A generator of ``struct page *``
    """
    for inode in list_for_each_entry(
        "struct inode", sb.s_inodes.address_of_(), "i_sb_list"
    ):
        yield from for_each_inode_page_in_pagecache(inode)


def for_each_file_system_page_in_pagecache(fst: Object) -> Iterator[Object]:
    """
    Walk through pages of page cache in a file system

    :param fst: ``struct file_system_type *``
    """
    for sb in hlist_for_each_entry(
        "struct super_block", fst.fs_supers.address_of_(), "s_instances"
    ):
        yield from for_each_superblock_page_in_pagecache(sb)


def filecache_dump(
    prog: Program,
    top_n: int,
    page_limit: int,
    fs_types: Union[List[str], None] = None,
    skip_fs_types: Union[List[str], None] = None,
) -> None:
    """
    Dump the filecache stats including the pages, size, filesystem type and
    filepath. Dump NUMA stats as well if numa set to True.

    :param top_n: The largest <top_n> files to be dumped
    :param page_limit: Only files with the number of pages greater than
      <page_limit> are dumped
    :param fs_types: File system types to dump. None to dump all
    :param skip_fs_types: File system types to skip. None to skip nothing
    """
    inode_entries: List[Tuple[int, Object]] = []
    output_table = [["PAGES", "SIZE", "FS_TYPE", "FILE"]]
    fst = prog["file_systems"]
    while fst:
        if __check_fs_types(fst, fs_types, skip_fs_types):
            __add_filesystem(inode_entries, fst, page_limit)
        fst = fst.next

    # iterate through all but the system volume
    inode_entries.sort(reverse=True)

    page_size = prog["PAGE_SIZE"]
    for f in inode_entries[1 : top_n + 1]:
        nrpages = f[0]
        nrpages_size = human_bytes(int(nrpages * page_size))

        fs_type = __fst_name_by_inode(f[1])
        file_path = ""
        file_path = __path_by_inode(f[1])
        output_table.append([str(nrpages), nrpages_size, fs_type, file_path])

    print_table(output_table)


class Filecache(CorelensModule):
    """Prints files from page cache, sorted by the amount of cached pages"""

    name = "filecache"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--limit",
            "-l",
            default=1000,
            metavar="N",
            type=int,
            help="Limit output to the top N files",
        )
        parser.add_argument(
            "--min-pages",
            "-m",
            default=1,
            metavar="M",
            type=int,
            help="Only show files with more than M pages cached",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        filecache_dump(prog, args.limit, args.min_pages, None, None)


def file_page_dump(file: Object) -> Iterator[Object]:
    """
    Get page pointers associated with a file object

    :param file: ``struct file *``
    :returns: A generator of ``struct page *``
    """
    address_space = file.f_mapping
    # check whether address_space exists,i.e. the file is mapped into memory or not
    if not address_space:
        return iter([])

    else:
        return __walk_tree(address_space)


def inode_page_dump(inode: Object) -> Iterator[Object]:
    """
    Get page pointers associated with an inode object

    :param inode: ``struct inode *``
    :returns: A generator of ``struct page *``
    """
    address_space = inode.i_mapping
    # check whether address_space exists,i.e. the file is mapped into memory or not
    if not address_space:
        return iter([])

    else:
        return __walk_tree(address_space)


def __add_inode(
    inode_entries: List[Tuple[int, Object]], inode: Object, page_limit: int
) -> None:
    """Add inode to inode_entries"""
    address_space = inode.i_mapping
    # check whether address_space exists,i.e. the file is mapped into memory or not
    if not address_space:
        return

    nrpages = 0
    try:
        nrpages = int(address_space.nrpages)
    except drgn.FaultError:
        # Handles the potential page I/O address: Page Directory Pointer Table (PDPT) not present
        return

    # only inodes with number of pages greater than <page_limit> are added
    if nrpages < page_limit:
        return

    inode_entries.append((nrpages, inode))


def __add_superblock(
    inode_entries: List[Tuple[int, Object]], sb: Object, page_limit: int
) -> None:
    """Add the superblocks by iterating through its inodes"""
    for inode in list_for_each_entry(
        "struct inode", sb.s_inodes.address_of_(), "i_sb_list"
    ):
        __add_inode(inode_entries, inode, page_limit)


def __add_filesystem(
    inode_entries: List[Tuple[int, Object]], fst: Object, page_limit: int
) -> None:
    """Add the filesystems by iterating through its superblocks"""
    for sb in hlist_for_each_entry(
        "struct super_block", fst.fs_supers.address_of_(), "s_instances"
    ):
        __add_superblock(inode_entries, sb, page_limit)


def __check_fs_types(
    fst: Object,
    fs_types: Union[List[str], None],
    skip_fs_types: Union[List[str], None],
) -> bool:
    """Only keep the desired filesystem types"""
    fs_type = fst.name.string_().decode()
    if skip_fs_types and fs_type in skip_fs_types:
        return False
    if fs_types and fs_type not in fs_types:
        return False
    return True


def __fst_name_by_inode(inode: Object) -> str:
    """Get the filesystem name"""
    sb = inode.i_sb
    # in case inode is not associated with any mounted filesystem
    # or inode is part of an unlinked file (kept in mem until all processes close their references to the file)
    if not sb:
        return "SUPER BLOCK NOT FOUND"
    try:
        fst_name = sb.s_type.name.string_().decode()
    except drgn.FaultError:
        return "NONE"

    return fst_name


def __path_by_inode(inode: Object) -> str:
    """Get the filepath"""
    hlist_head = inode.i_dentry
    if hlist_empty(hlist_head.address_of_()):
        return "[NO DENTRY]"
    try:
        hlist_node = hlist_head.first
        dentry = container_of(hlist_node, "struct dentry", "d_u")
        return d_path(dentry).decode()
    except drgn.FaultError:
        return "[ERROR]"


def __walk_tree(address_space: Object) -> Iterator[Object]:
    # works for different UEK versions
    try:
        return __walk_xarray(address_space.i_pages)
    except AttributeError:
        pass
    try:
        return __walk_radix(address_space.page_tree)
    except AttributeError:
        raise ValueError(
            "Unrecognized struct address_space; tried xarray and radix tree"
        ) from None


def __walk_xarray(xarray: Object) -> Iterator[Object]:
    """Step through the xarray"""
    for _, entry in xa_for_each(xarray.address_of_()):
        page_ptr = cast("struct page *", entry)
        if not page_ptr.value_():
            continue
        yield page_ptr


def __walk_radix(radix: Object) -> Iterator[Object]:
    """Step through the radix tree"""
    for _, entry in radix_tree_for_each(radix.address_of_()):
        page_ptr = cast("struct page *", entry)
        if not page_ptr.value_():
            continue
        yield page_ptr
