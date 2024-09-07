# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
LRU Lists
------------

Helper to work with LRU lists. LRU can be created to be memcg aware and
ordered by NUMA node.

The routines iterate through the specified LRU and on NUMA machines, the
output keeps the entries ordered by NUMA node.

The list_lru_from_memcg_node_for_each_entry() function allows the user to
restrict the iteration by the memcg index when the list_lru is memcg_aware
and the NUMA node identifier.

list_lru_kmem_to_memcgidx() is a helper to find the mem_cgroup index
from a list_lru kvm address. This helper will find the memcg of a list_lru
address. This routine is only interested in slab allocated entries and does
not check nor handle the MEMCG_DATA_KMEM case.
"""
from typing import Iterator
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
from drgn.helpers.linux.mm import page_to_virt
from drgn.helpers.linux.mm import virt_to_page
from drgn.helpers.linux.nodemask import for_each_online_node
from drgn.helpers.linux.nodemask import node_state
from drgn.helpers.linux.xarray import xa_for_each
from drgn.helpers.linux.xarray import xa_load

from drgn_tools.util import has_member

MEMCG_DATA_OBJCGS = 1
MEMCG_DATA_KMEM = 2

__all__ = (
    "list_lru_for_each_entry",
    "list_lru_from_memcg_node_for_each_entry",
    "list_lru_kmem_to_memcgidx",
)


def list_lru_for_each_entry(
    prog: Program, type: Union[str, Type], lru: Object, member: str
) -> Iterator[Object]:
    """
    Iterate over all of the entries in a list_lru.

    :param prog: Kernel being debugged
    :param type: Entry type.
    :param lru: ``struct list_lru *``
    :param member: Name of list node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
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
                for _, memcg in xa_for_each(xa.address_of_()):
                    # convert from the void ptr
                    memcg = Object(prog, "struct list_lru_memcg *", memcg)
                    lru_one = memcg.node[nid]
                    if lru_one.nr_items > 0:
                        for entry in list_for_each_entry(
                            type, lru_one.list.address_of_(), member
                        ):
                            yield entry
        else:
            # Before v5.13, memcg entries are in an array
            # Keep the entries grouped by the NUMA node.
            for nid in for_each_online_node(prog):
                i = 0
                while i < prog["memcg_nr_cache_ids"]:
                    li = lru.node[nid].memcg_lrus.lru[i].list
                    i = i + 1
                    if not list_empty(li.address_of_()):
                        for entry in list_for_each_entry(
                            type, li.address_of_(), member
                        ):
                            yield entry
    else:
        # not lru.memcg_aware
        for nid in for_each_online_node(prog):
            # not lru.memcg_aware
            if has_member(lru, "ext"):
                li = lru.ext.node[nid].lru.list
            else:
                li = lru.node[nid].lru.list
            for entry in list_for_each_entry(type, li.address_of_(), member):
                yield entry


def list_lru_from_memcg_node_for_each_entry(
    prog: Program,
    mindx: IntegerLike,
    nid: IntegerLike,
    type: Union[str, Type],
    lru: Object,
    member: str,
) -> Iterator[Object]:
    """
    Iterate over the entries in a list_lru by the provided memcg and NUMA node.

    :param prog: Kernel being debugged
    :param mindx: memcg index.
    :param nid: NUMA node ID.
    :param type: Entry type.
    :param lru: ``struct list_lru *``
    :param member: Name of list node member in entry type.
    :return: Iterator of ``type *`` objects.
    """
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
                    lru_one = memcg.node[nid]
                    if lru_one.nr_items > 0:
                        for entry in list_for_each_entry(
                            type, lru_one.list.address_of_(), member
                        ):
                            yield entry
            else:
                # Before v5.13
                # make sure the memcg index is within the legal limits
                if mindx >= 0 and mindx < prog["memcg_nr_cache_ids"]:
                    li = lru.node[nid].memcg_lrus.lru[mindx].list
                    if not list_empty(li.address_of_()):
                        for entry in list_for_each_entry(
                            type, li.address_of_(), member
                        ):
                            yield entry
        else:
            # not lru.memcg_aware
            if has_member(lru, "ext"):
                li = lru.ext.node[nid].lru.list
            else:
                li = lru.node[nid].lru.list
            for entry in list_for_each_entry(type, li.address_of_(), member):
                yield entry


def list_lru_kmem_to_memcgidx(prog: Program, kvm: IntegerLike) -> IntegerLike:
    """
    Convert the kvm of an embedded list_lru and return the memcg index.
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
                if cpage.flags & (1 << prog.constant("PG_slab")):
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
