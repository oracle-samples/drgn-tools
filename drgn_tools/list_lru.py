# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
LRU Lists
------------

Helper to work with LRU lists. LRU can be created to be memcg aware and
ordered by NUMA node.

The routines iterate through the specified LRU and on NUMA machines, the
output keeps the entries ordered by NUMA node.

The list_lru_for_each_list() function iterates all of the list_lru_one
list. The list_lru_for_each_entry() function iterates through all the
specified entries on a list_lru and returns the NUMA nodeid, memcg
and Object of the specified type.

The list_lru_from_memcg_node_for_each_list() and
list_lru_from_memcg_node_for_each_entry() functions allows the user to
restrict the iteration of the list_lru_one and entries by the memcg
index when the list_lru is memcg_aware and the NUMA node identifier.

list_lru_kmem_to_memcgidx() is a helper to find the mem_cgroup index
from a list_lru kvm address. This helper will find the memcg of a list_lru
address. This routine is only interested in slab allocated entries and does
not check nor handle the MEMCG_DATA_KMEM case.
"""
from typing import Iterator
from typing import Tuple
from typing import Union

from drgn import cast
from drgn import IntegerLike
from drgn import NULL
from drgn import Object
from drgn import Program
from drgn import Type
from drgn.helpers.linux.list import list_empty
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.mm import compound_head
from drgn.helpers.linux.mm import page_to_pfn
from drgn.helpers.linux.mm import page_to_virt
from drgn.helpers.linux.mm import PageSlab
from drgn.helpers.linux.mm import virt_to_page
from drgn.helpers.linux.nodemask import for_each_online_node
from drgn.helpers.linux.nodemask import node_state
from drgn.helpers.linux.xarray import xa_for_each
from drgn.helpers.linux.xarray import xa_load

from drgn_tools.meminfo import get_active_numa_nodes
from drgn_tools.util import has_member

MEMCG_DATA_OBJCGS = 1
MEMCG_DATA_KMEM = 2

__all__ = (
    "list_lru_for_each_list",
    "list_lru_for_each_entry",
    "list_lru_from_memcg_node_for_each_list",
    "list_lru_from_memcg_node_for_each_entry",
    "list_lru_kmem_to_memcgidx",
    "list_lru_kmem_to_nodeid",
)


def list_lru_for_each_list(
    lru: Object
) -> Iterator[Tuple[int, int, Object]]:
    """
    Iterate over a list_lru and return each NUMA nodeid, memcgid and
    list_lru_one object.

    :param lru: ``struct list_lru *``
    :return: Iterator of the Tuple (node_id, memcg_idx, ``list_lru_one *``)
    """
    prog = lru.prog_
    memcg_aware = 0
    if has_member(lru, "memcg_aware") and lru.memcg_aware:
        memcg_aware = 1

    if has_member(lru, "node"):
        # no lru.node in uek7 but covered in above test
        if has_member(lru.node, "memcg_lrus") and lru.node[0].memcg_lrus:
            memcg_aware = 1

    if memcg_aware:
        if has_member(lru, "ext") or has_member(lru, "xa"):
            # v5.13 (uek7) or newer
            if has_member(lru, "ext"):
                # uek7 has a UEK_KABI_REPLACE of node to ext
                xa = lru.ext.xa
            else:
                # uek8
                xa = lru.xa
            # Keep the entries grouped by the NUMA node.
            for nid in for_each_online_node(prog):
                for memcgid, memcg in xa_for_each(xa.address_of_()):
                    # convert from the void ptr
                    memcg = Object(prog, "struct list_lru_memcg *", memcg)
                    yield (nid, memcgid, memcg.node[nid])
        else:
            # Before v5.13, memcg entries are in an array
            # Keep the entries grouped by the NUMA node.
            for nid in for_each_online_node(prog):
                for i in range(prog["memcg_nr_cache_ids"]):
                    llru1 = lru.node[nid].memcg_lrus.lru[i]
                    if not list_empty(llru1.list.address_of_()):
                        yield (nid, i, llru1)
    else:
        # not lru.memcg_aware
        for nid in for_each_online_node(prog):
            # not lru.memcg_aware
            if has_member(lru, "ext"):
                yield (nid, 0, lru.ext.node[nid].lru)
            else:
                yield (nid, 0, lru.node[nid].lru)


def list_lru_for_each_entry(
    type: Union[str, Type],
    lru: Object, member: str
) -> Iterator[Tuple[int, int, Object]]:
    """
    Iterate over all of the entries in a list_lru.
    This function calls list_lru_for_each_list() and then iterates over
    each list_lru_one.

    :param type: Entry type.
    :param lru: ``struct list_lru *``
    :param member: Name of list node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
    for nid, memcgid, llru1 in list_lru_for_each_list(lru):
        for entry in list_for_each_entry(
            type, llru1.list.address_of_(), member
        ):
            yield (nid, memcgid, entry)


def list_lru_from_memcg_node_for_each_list(
    mindx: IntegerLike,
    nid: IntegerLike,
    lru: Object,
) -> Iterator[Object]:
    """
    Iterate over each list_lru_one entries for the provided memcg and NUMA node.

    :param mindx: memcg index.
    :param nid: NUMA node ID.
    :param lru: ``struct list_lru *``
    :return: Iterator of ``struct list_lru_one`` objects.
    """
    prog = lru.prog_
    if node_state(nid, prog["N_ONLINE"]):
        memcg_aware = 0
        if has_member(lru, "memcg_aware") and lru.memcg_aware:
            memcg_aware = 1
        if has_member(lru, "node"):
            # no lru.node in uek7 but covered in above test
            if has_member(lru.node, "memcg_lrus") and lru.node[0].memcg_lrus:
                memcg_aware = 1
        if memcg_aware:
            if has_member(lru, "ext") or has_member(lru, "xa"):
                # v5.13 (uek7) or newer
                if has_member(lru, "ext"):
                    # uek7 has a UEK_KABI_REPLACE of node to ext
                    xa = lru.ext.xa
                else:
                    # uek8
                    xa = lru.xa
                # Keep the entries grouped by the NUMA node.
                memcg = xa_load(xa.address_of_(), mindx)
                # convert from the void ptr unless it is a NULL
                if memcg != NULL(prog, "void *"):
                    memcg = Object(prog, "struct list_lru_memcg *", memcg)
                    yield memcg.node[nid]
            else:
                # Before v5.13
                # make sure the memcg index is within the legal limits
                if mindx >= 0 and mindx < prog["memcg_nr_cache_ids"]:
                    llru1 = lru.node[nid].memcg_lrus.lru[mindx]
                    if not list_empty(llru1.list.address_of_()):
                        yield llru1
        else:
            # not lru.memcg_aware
            if has_member(lru, "ext"):
                yield lru.ext.node[nid].lru
            else:
                yield lru.node[nid].lru


def list_lru_from_memcg_node_for_each_entry(
    mindx: IntegerLike,
    nid: IntegerLike,
    type: Union[str, Type],
    lru: Object,
    member: str,
) -> Iterator[Object]:
    """
    Iterate over the entries in a list_lru by the provided memcg and NUMA node.
    This function calls list_lru_from_memcg_node_for_each_list() and
    then iterates over each list_lru_one.

    :param mindx: memcg index.
    :param nid: NUMA node ID.
    :param type: Entry type.
    :param lru: ``struct list_lru *``
    :param member: Name of list node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
    for llru1 in list_lru_from_memcg_node_for_each_list(mindx, nid, lru):
        yield from list_for_each_entry(
            type, llru1.list.address_of_(), member)


def list_lru_kmem_to_memcgidx(
    prog: Program,
    kvm: IntegerLike
) -> IntegerLike:
    """
    Return the memcg index of the list_lru entry.
    Return -1 if the list_lru is not memcg enabled or value could not be found.
    Memory cgroups for slab allocation are per object. This code expects a slab
    allocated kvm and the MEMCG_DATA_KMEM case is NOT covered in this routine.

    :param prog: Kernel being debugged
    :param kvm: address of a list_lru
    :return: memcg index, -1 means not found
    """
    page = virt_to_page(prog, kvm)
    cpage = compound_head(page)
    # page_objcgs_check() MEMCG_DATA_OBJCGS memcg are managed per object
    if has_member(cpage, "memcg_data") or has_member(cpage, "obj_cgroups"):
        if has_member(cpage, "memcg_data"):
            memcg_data = cpage.memcg_data
        else:
            # cast to an integer for the MEMCG_DATA_KMEM test.
            memcg_data = cast("unsigned long", cpage.obj_cgroups)
        if memcg_data & MEMCG_DATA_OBJCGS:
            objcgrp = Object(
                prog, "struct obj_cgroup **", memcg_data - MEMCG_DATA_OBJCGS
            )
            # offset of object calculation
            pvm = page_to_virt(cpage)
            kvm = Object(prog, "void *", kvm)
            if has_member(cpage, "slab_cache"):
                slab_cache = cpage.slab_cache
            else:
                # v5.17 (uek8) moved the kmem_cache to a new slab structure.
                # and since v6.10 the slab pages are identified by a page type
                if PageSlab(cpage):
                    slab = Object(prog, "struct slab *", cpage)
                    slab_cache = slab.slab_cache
                else:
                    return -1
            objoffset = (kvm - pvm) / slab_cache.size
            memcgrp = objcgrp[objoffset].memcg
            if memcgrp == NULL(prog, "struct mem_cgroup *"):
                return -1
            else:
                return memcgrp.kmemcg_id
        else:
            return -1
    else:
        # Before v5.13
        scache = cpage.slab_cache
        if scache == NULL(prog, "struct kmem_cache *"):
            return -1
        else:
            return cpage.slab_cache.memcg_params.memcg.kmemcg_id


def list_lru_kmem_to_nodeid(
    prog: Program,
    kvm: IntegerLike
) -> IntegerLike:
    """
    Return the NUMA node id of the list_lru entry.

    :param prog: Kernel being debugged
    :param kvm: address of a list_lru entry
    :return: NUMA node id
    """
    page = virt_to_page(prog, kvm)
    cpage = compound_head(page)
    #
    pfn = page_to_pfn(cpage)
    nodes = get_active_numa_nodes(cpage.prog_)
    for i in range(1, len(nodes)):
        if nodes[i - 1].node_start_pfn <= pfn < nodes[i].node_start_pfn:
            return nodes[i - 1].node_id
    return nodes[-1].node_id
