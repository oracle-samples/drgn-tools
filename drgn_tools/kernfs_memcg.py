# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Kernfs_memcg
--------------

The ``drgn.helpers.linux.kernfs_memcg`` module provides helpers for working with the
Linux memcg subsystem.
"""
import argparse
from typing import Iterator

from drgn import cast
from drgn import container_of
from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn.helpers.common.format import decode_enum_type_flags
from drgn.helpers.linux import cgroup_path
from drgn.helpers.linux import css_for_each_descendant_pre
from drgn.helpers.linux import find_slab_cache
from drgn.helpers.linux import for_each_page
from drgn.helpers.linux import inode_path
from drgn.helpers.linux import kernfs_path
from drgn.helpers.linux import PageSlab
from drgn.helpers.linux import slab_cache_for_each_allocated_object

from drgn_tools.corelens import CorelensModule
from drgn_tools.dentry import dentry_path_any_mount


_KERNFS_TYPE_MASK = 0xF
# cgroup subsystem id for memory cgroup, from kernel/cgroup/cgroup.c
_MEMORY_CGRP_ID = 4


def decode_css_flags(css: Object) -> str:
    """
    Get a human-readable representation of cgroup_subsys_state.flags

    :param css: ``struct cgroup_subsys_state *``
    """
    # We only need the type of the enum containing the cgroup subsystem state
    # constants. Unfortunately the enum is anonymous so we need to access the
    # type via one of the enum members. CSS_ONLINE is present since
    # a31f2d3ff7fe2 ("cgroup: introduce CSS_ONLINE flag and on/offline_css()
    # helpers") in Linux 3.8, which is sufficient for our needs.
    CSS_ONLINE = css.prog_.constant("CSS_ONLINE")
    flags = css.flags.value_()
    if not flags:
        # There is no dedicated flag value to indicate a zombie cgroup.
        # A css.flags value of 0 indicates that cgroup destruction is
        # complete but cgroup object has not been fully freed because
        # of being pinned by some other object
        return "ZOMBIE"

    return decode_enum_type_flags(flags, CSS_ONLINE.type_, False)


def for_each_kernfs_node(prog: Program) -> Iterator[Object]:
    """
    Iterate over all kernfs_node objects in the system.
    This ignores the fact that ``kernfs_node_cache`` may be merged with
    other slab caches and returns all objects of ``kernfs_node_cache``
    or of the merged slab-cache.
    Usually we iterate through kernfs_node(s) of specific usage, for
    example, kernfs_node(s) corresponding to cgroups. So user can
    do additional checks to ensure that validity of obtained kernfs_node
    object.
    For example for cgroups, kernfs_node.priv is a pointer to ``struct
    cgroup`` object. This is better than giving up straight away
    for merged slab caches.


    :returns: Iterator of ``struct kernfs_node *`` objects.
    """
    kernfs_node_cache = find_slab_cache(prog, "kernfs_node_cache")
    for kn in slab_cache_for_each_allocated_object(
        kernfs_node_cache, "struct kernfs_node"
    ):
        yield kn


def dump_memcgroup_hierarchy(prog: Program) -> None:
    """
    Dump hierarchy of active mem cgroups.
    """
    cgroup_subsys = prog["cgroup_subsys"][_MEMORY_CGRP_ID]
    css = cgroup_subsys.root.cgrp.self.address_of_()
    print(f"dumping: {cgroup_subsys.name.string_().decode()} hierarchy")
    for pos in css_for_each_descendant_pre(css):
        cgroup_state = decode_css_flags(pos)
        print(
            f"path: {cgroup_path(pos.cgroup).decode()} state: {cgroup_state}"
        )


def kernfs_node_of_cgroup(kn: Object) -> bool:
    """
    Check if a kernfs_node object represents a cgroup object.

    :param kn: ``struct kernfs_node *``
    :returns: True if kernfs_node object represents a cgroup object,
              False otherwise.
    """
    if (kn.flags.value_() & _KERNFS_TYPE_MASK) == kn.prog_.constant(
        "KERNFS_DIR"
    ).value_():
        try:
            cgrp = cast("struct cgroup *", kn.priv)
            return cgrp.kn == kn
        except FaultError:
            return False
    else:
        return False


def kernfs_node_of_memcgroup(kn: Object) -> bool:
    """
    Check if a kernfs_node object represents a mem cgroup object.

    :param kn: ``struct kernfs_node *``
    :returns: True if kernfs_node object represents a mem cgroup object,
              False otherwise.
    """
    if kernfs_node_of_cgroup(kn):
        prog = kn.prog_
        cgrp = cast("struct cgroup *", kn.priv)
        return prog["cgroup_subsys"][_MEMORY_CGRP_ID].root == cgrp.root
    else:
        return False


def dump_memcg_kernfs_nodes(prog: Program) -> None:
    """
    List all kernfs_node objects that represent a mem cgroup.
    """
    count = 0
    for kn in for_each_kernfs_node(prog):
        if kernfs_node_of_memcgroup(kn):
            count = count + 1
            path = kernfs_path(kn).decode()
            print("kernfs_node: ", hex(kn.value_()), "  ", path)

    print("Total number of memcg kernfs_node objects: ", count)


def get_num_active_mem_cgroups(prog: Program) -> int:
    """
    Get number of active mem cgroups.
    """
    mem_cgroup_subsys = prog["cgroup_subsys"][_MEMORY_CGRP_ID]
    # add 1 to number of active memcgroups to account for root memcgroup
    try:
        return mem_cgroup_subsys.root.cgrp.nr_descendants.value_() + 1
    except AttributeError:
        print("Number of active descendants not available.")
        return -1


def get_num_dying_mem_cgroups(prog: Program) -> int:
    """
    Get number of inactive or dying mem cgroups.
    """
    mem_cgroup_subsys = prog["cgroup_subsys"][_MEMORY_CGRP_ID]
    try:
        return mem_cgroup_subsys.root.cgrp.nr_dying_descendants.value_()
    except AttributeError:
        print("Number of dying descendants not available.")
        return -1


def get_num_mem_cgroups(prog: Program) -> None:
    active_mem_cgroups = get_num_active_mem_cgroups(prog)
    dying_mem_cgroups = get_num_dying_mem_cgroups(prog)
    if active_mem_cgroups >= 0 and dying_mem_cgroups >= 0:
        print(
            f"There are {active_mem_cgroups} active and {dying_mem_cgroups} dying memcgroups \n"
        )
    # UEK4 does not maintain dedicated counter for active and dying
    # descendants.
    else:
        total_mem_cgroups = prog["cgroup_subsys"][
            _MEMORY_CGRP_ID
        ].root.nr_cgrps.value_()
        print(f"There are a total of {total_mem_cgroups} memcgroups \n")


# By default (max_pages == 0) we scan all pages,
# that have memcg ref but if max_pages is specified
# then we bail out after getting those many pages
# or after scanning all pages , whichever happens first.
def dump_page_cache_pages_pinning_cgroups(
    prog: Program, max_pages: int = 0, max_scan: int = 0
):
    """
    Dump page-cache pages that have reference to a mem-cgroup.

    The ouput also contains information such as the cgroup that is pinned, its
    flags (to indicate current state of cgroup) and file cached by this page.

    :param max_pages: specify how many pages to find. Use 0 (the default) to
      list all such pages.
    :param max_scan: how many pages to scan, regardless of whether any such
      pages are found. Use 0 (the default) to scan all pages.
    """
    mem_cgroup_root = prog["cgroup_subsys"][_MEMORY_CGRP_ID].root
    total_count = 0
    found_count = 0
    fault_count = 0
    for page in for_each_page(prog):
        total_count = total_count + 1
        if max_scan and total_count > max_scan:
            break
        try:
            # Ignore slab pages
            if PageSlab(page):
                continue
            # Ignore non page-cache pages
            if not page.mapping:
                continue
            try:
                mem_cgroup = page.mem_cgroup
            except AttributeError:
                mem_cgroup = page.memcg_data

            if not mem_cgroup.value_() or mem_cgroup.value_() & 3:
                continue
            cgroup_subsys_state = cast(
                "struct cgroup_subsys_state *", mem_cgroup
            )
            if cgroup_subsys_state.cgroup.root == mem_cgroup_root:
                found_count = found_count + 1
                cgrp = cgroup_subsys_state.cgroup
                address_space = page.mapping
                inode = address_space.host
                if inode_path(inode) is None:
                    continue
                dentry = container_of(
                    inode.i_dentry.first, "struct dentry", "d_u.d_alias"
                )
                path = dentry_path_any_mount(dentry).decode()
                cgroup_state = decode_css_flags(cgrp.self.address_of_())
                print(
                    f"page: 0x{page.value_():x} cgroup: {cgroup_path(cgrp).decode()} state: {cgroup_state} path: {path}\n"
                )
                if max_pages and found_count == max_pages:
                    break
        except FaultError:
            fault_count = fault_count + 1
            continue

    print(
        f"Scanned {total_count} pages, found {found_count} pages with memory cgroup refs, found {fault_count} faults."
    )


class NumMemCgroups(CorelensModule):
    """Print number of active and dying memcgroups"""

    name = "num-memcgroups"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        get_num_mem_cgroups(prog)


class PagesPinningMemcgroups(CorelensModule):
    """Print information related to pages, that are pinning memcgroup(s)"""

    name = "pages-pinning-memcg"
    run_when = "never"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--max",
            "-m",
            type=int,
            default=0,
            help="Maximum number of pages to show. By default(0) all such pages are shown.",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        dump_page_cache_pages_pinning_cgroups(prog, max_pages=args.max)
