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

slab_object_to_memcgidx() is a helper to find the mem_cgroup index
from a list_lru entry. This routine is only interested in slab
allocated entries and does not check nor handle the MEMCG_DATA_KMEM case.
slab_object_to_nodeid() is a helper to find the NUMA node id from a
list_lru entry.
"""
from typing import Iterator
from typing import Tuple
from typing import Union

from drgn import cast
from drgn import IntegerLike
from drgn import NULL
from drgn import Object
from drgn import Type
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.mm import compound_head
from drgn.helpers.linux.mm import page_to_pfn
from drgn.helpers.linux.mm import page_to_virt
from drgn.helpers.linux.mm import virt_to_page
from drgn.helpers.linux.nodemask import for_each_online_node
from drgn.helpers.linux.nodemask import node_state
from drgn.helpers.linux.slab import slab_object_info
from drgn.helpers.linux.xarray import xa_for_each
from drgn.helpers.linux.xarray import xa_load

from drgn_tools.meminfo import get_active_numa_nodes
from drgn_tools.util import has_member

__all__ = (
    "list_lru_for_each_list",
    "list_lru_for_each_entry",
    "list_lru_from_memcg_node_for_each_list",
    "list_lru_from_memcg_node_for_each_entry",
    "slab_object_to_memcgidx",
    "slab_object_to_nodeid",
)


def list_lru_for_each_list(lru: Object) -> Iterator[Tuple[int, int, Object]]:
    """
    Iterate over a list_lru and return each NUMA nodeid, memcgid and
    list_lru_one object.

    :param lru: ``struct list_lru *``
    :return: Iterator of the Tuple (node_id, memcg_idx, ``list_lru_one *``)
    """
    prog = lru.prog_
    memcg_aware = 0
    # v5.2-rc2-303-g3e8589963773 (memcg: make it work on sparse non-0-node
    # systems) adds memcg_aware boolean
    if has_member(lru, "memcg_aware") and lru.memcg_aware:
        memcg_aware = 1

    # Before v5.15.0-9.96.3-944-gd337fa4c0eb2 (Oracle) and
    # v5.17-47-g6a6b7b77cc0f (community) (mm: list_lru: transpose the array
    # of per-node per-memcg lru lists), the list_lru_memcg entry was in the
    # list_lru_node that was in the list_lru.
    if has_member(lru, "node"):
        if has_member(lru.node, "memcg_lrus") and lru.node[0].memcg_lrus:
            memcg_aware = 1

    if memcg_aware:
        if has_member(lru, "ext") or has_member(lru, "xa"):
            if has_member(lru, "ext"):
                # (uek7) Oracle port UEK_KABI_REPLACE of node to ext
                # v5.15.0-9.96.3-944-gd337fa4c0eb2 of commity patch
                # v5.17-47-g6a6b7b77cc0f
                xa = lru.ext.xa
            else:
                # uek 8 v5.17-57-gbbca91cca9a9 replace array with xarray
                # doesn't have uek7 KABI changes.
                xa = lru.xa
            # Keep the entries grouped by the NUMA node.
            for nid in for_each_online_node(prog):
                for memcgid, memcg in xa_for_each(xa.address_of_()):
                    # convert from the void ptr
                    memcg = Object(prog, "struct list_lru_memcg *", memcg)
                    yield (nid, memcgid, memcg.node[nid])
        else:
            for nid in for_each_online_node(prog):
                # Keep the entries grouped by the NUMA node.
                for i in range(prog["memcg_nr_cache_ids"]):
                    yield (nid, i, lru.node[nid].memcg_lrus.lru[i])
    else:
        # not lru.memcg_aware
        for nid in for_each_online_node(prog):
            if has_member(lru, "ext"):
                yield (nid, 0, lru.ext.node[nid].lru)
            else:
                yield (nid, 0, lru.node[nid].lru)


def list_lru_for_each_entry(
    type: Union[str, Type], lru: Object, member: str
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
) -> Object:
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
        # v5.2-rc2-303-g3e8589963773 (memcg: make it work on sparse non-0-node
        # systems) adds memcg_aware boolean
        if has_member(lru, "memcg_aware") and lru.memcg_aware:
            memcg_aware = 1
        # Before v5.15.0-9.96.3-944-gd337fa4c0eb2 (Oracle) and
        # v5.17-47-g6a6b7b77cc0f (community) (mm: list_lru: transpose the array
        # of per-node per-memcg lru lists), the list_lru_memcg entry was in the
        # list_lru_node that was in the list_lru.
        if has_member(lru, "node"):
            if has_member(lru.node, "memcg_lrus") and lru.node[0].memcg_lrus:
                memcg_aware = 1
        if memcg_aware:
            if has_member(lru, "ext") or has_member(lru, "xa"):
                if has_member(lru, "ext"):
                    # (uek7) Oracle port UEK_KABI_REPLACE of node to ext
                    # v5.15.0-9.96.3-944-gd337fa4c0eb2 of commity patch
                    # v5.17-47-g6a6b7b77cc0f
                    xa = lru.ext.xa
                else:
                    # uek 8 v5.17-57-gbbca91cca9a9 replace array with xarray
                    # doesn't have uek7 KABI changes.
                    xa = lru.xa
                # Keep the entries grouped by the NUMA node.
                memcg = xa_load(xa.address_of_(), mindx)
                # convert from the void ptr unless it is a NULL
                if memcg != NULL(prog, "void *"):
                    memcg = Object(prog, "struct list_lru_memcg *", memcg)
                    yield memcg.node[nid]
            else:
                # make sure the memcg index is within the legal limits
                if mindx >= 0 and mindx < prog["memcg_nr_cache_ids"]:
                    yield lru.node[nid].memcg_lrus.lru[mindx]
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
        yield from list_for_each_entry(type, llru1.list.address_of_(), member)


def slab_object_to_memcgidx(obj: Object) -> IntegerLike:
    """
    Return the memcg index of the list_lru object.
    Return -1 if the list_lru is not memcg enabled. Raise an error if the
    value could not be found. Memory cgroups for slab allocation are per
    object. This code expects a slab allocated object and the MEMCG_DATA_KMEM
    case is NOT covered in this routine.
    """
    prog = obj.prog_
    info = slab_object_info(obj)
    if not info:
        raise ValueError("not a slab object")

    if hasattr(info.slab_cache, "memcg_params"):
        # Prior to v5.9, there were separate slab caches per memcg, so the memcg
        # could be determined from the slab cache itself.
        # uek6 added commit v5.4.17-2050-33-g3aac91dc16a4 (community commit
        # 10befea91b61c ("mm: memcg/slab: use a single set of kmem_caches
        # for all allocations") and retained a unused memcg_params.
        params = info.slab_cache.memcg_params
        if params.memcg:
            return params.memcg.kmemcg_id.value_()

    slab_object_index = (
        obj.value_() - page_to_virt(info.slab).value_()
    ) // info.slab_cache.size.value_()

    if hasattr(info.slab, "obj_cgroups"):
        # Starting with v5.9 in commit 10befea91b61c ("mm: memcg/slab: use a
        # single set of kmem_caches for all allocations"), until v5.11, object
        # cgroup information was stored in a "obj_cgroups" array, which was
        # shared in a union as "mem_cgroup". The lowest bit is set to indicate
        # that it is an array of object cgroup information.
        obj_cgroups = info.slab.obj_cgroups
        if not obj_cgroups.value_() & 1:
            return -1
        memcg_data = Object(prog, obj_cgroups.type_, obj_cgroups.value_() - 1)
        memcg = memcg_data[slab_object_index].memcg
    elif hasattr(info.slab, "memcg_data"):
        # Starting with v5.11 commit 87944e2992bd2 ("mm: Introduce page memcg
        # flags"), until v6.10 , the "mem_cgroup" and "obj_cgroups" are placed
        # into the unsigned long field "memcg_data", with constant flags to
        # formalize the access to them.
        flag = prog.constant("MEMCG_DATA_OBJCGS")
        mask = cast(
            "unsigned long", prog.constant("__NR_MEMCG_DATA_FLAGS") - 1
        )
        if not info.slab.memcg_data & flag:
            return -1
        memcg_data = cast("struct obj_cgroup **", info.slab.memcg_data & ~mask)
        memcg = memcg_data[slab_object_index].memcg
    elif hasattr(info.slab, "obj_exts"):
        # Since v6.10 commit 21c690a349baa ("mm: introduce slabobj_ext to
        # support slab object extensions"), struct slab now supports more type
        # of object metadata, in addition to memcg info. There are new constants
        # to check and a new type, slabobj_ext, to use for accessing the
        # metadata.
        flag = prog.constant("MEMCG_DATA_OBJEXTS")
        mask = cast("unsigned long", prog.constant("__NR_OBJEXTS_FLAGS") - 1)
        if not info.slab.obj_exts & flag:
            return -1
        exts = cast("struct slabobj_ext *", info.slab.obj_exts & ~mask)
        memcg = exts[slab_object_index].objcg.memcg
    else:
        raise RuntimeError(
            "Cannot find object memcg info for this kernel version"
        )

    if memcg:
        return memcg.kmemcg_id.value_()
    else:
        return -1


def slab_object_to_nodeid(obj: Object) -> IntegerLike:
    """
    Return the NUMA node id of the list_lru entry.

    :param obj: address of a list_lru entry
    :return: NUMA node id
    """
    prog = obj.prog_
    page = virt_to_page(prog, obj)
    cpage = compound_head(page)
    #
    pfn = page_to_pfn(cpage)
    nodes = get_active_numa_nodes(prog)
    for i in range(1, len(nodes)):
        if nodes[i - 1].node_start_pfn <= pfn < nodes[i].node_start_pfn:
            return nodes[i - 1].node_id
    return nodes[-1].node_id
