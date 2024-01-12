# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper to view slabinfo data
"""
import argparse
from typing import NamedTuple
from typing import Set

from drgn import cast
from drgn import NULL
from drgn import Object
from drgn import Program
from drgn.helpers.linux.cpumask import for_each_present_cpu
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.nodemask import for_each_online_node
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.slab import _get_slab_cache_helper
from drgn.helpers.linux.slab import for_each_slab_cache

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table


class SlabCacheInfo(NamedTuple):
    """Describes summary information about a slab cache"""

    cache: Object
    """The ``struct kmem_cache *`` object"""
    objsize: int
    """Size of each individual object"""
    allocated: int
    """Number of allocated objects"""
    total: int
    """Total count of objects"""
    nr_slabs: int
    """Number of slabs"""
    ssize: int
    """Slab size"""
    name: str
    """Name of the slab cache"""


def kmem_cache_pernode(cache: Object, nodeid: int) -> tuple:
    """
    Get number of slabs, objects and partial object per node
    traverse though the partial list of node
    and count the number of partial objects

    :param cache: `struct kmem_cache` drgn object
    :param nodeid: node index
    "returns: a tuple with node information
    """
    nr_slabs = 0
    nr_total_objs = 0
    nr_free = 0
    nr_partial = 0
    node_total_use = 0

    kmem_cache_node = cache.node[nodeid]
    x = 0

    prog = cache.prog_

    nr_slabs = kmem_cache_node.nr_slabs.counter.value_()
    nr_total_objs = kmem_cache_node.total_objects.counter.value_()
    nr_partial = kmem_cache_node.nr_partial.value_()

    page = Object(prog, "struct page", address=0x0)
    partial_slab_list = "slab_list" if hasattr(page, "slab_list") else "lru"

    for page in list_for_each_entry(
        "struct page", kmem_cache_node.partial.address_of_(), partial_slab_list
    ):
        nrobj = page.objects.value_()
        nrinuse = page.inuse.value_()
        x = nrobj - nrinuse
        node_total_use += nrinuse
        nr_free += x

    return nr_slabs, nr_total_objs, nr_partial, node_total_use, nr_free


def kmem_cache_percpu(cache: Object) -> int:
    """
    Count the number of cpu_slab pages for all nodes.

    :param: `struct kmem_cache` drgn object
    """

    cpu_per_node = 0
    prog = cache.prog_
    cpu_slab_ptr = NULL

    for cpuid in for_each_present_cpu(prog):
        per_cpu_slab = per_cpu_ptr(cache.cpu_slab, cpuid)
        cpu_slab_ptr = per_cpu_slab.page

        if not cpu_slab_ptr:
            continue
        cpu_per_node += 1

    return cpu_per_node


def collect_node_info(cache: Object) -> tuple:
    """
    Parse through each node to collect per-node slab data

    :param: `struct kmem_cache` drgn object
    :returns: a tuple containing per-node slab data
    """
    nr_slabs = 0
    nr_total_objs = 0
    nr_free = 0
    nr_partial = 0
    node_total_use = 0

    prog = cache.prog_

    for node in for_each_online_node(prog):
        slabs, total_objs, partial, total_use, free = kmem_cache_pernode(
            cache, node
        )
        nr_slabs += slabs
        nr_total_objs += total_objs
        nr_partial += partial
        node_total_use += total_use
        nr_free += free

    return nr_slabs, nr_total_objs, nr_partial, node_total_use, nr_free


def slub_get_cpu_freelist_cnt(
    cpu_freelist: Object, slub_helper: Object
) -> int:
    """
    Get number of elements in percpu freelist

    :param slab_cache: `struct kmem_cache` drgn object
    :param cpu_freelist: `void**` pointer to next available object
    :param slub_helper: slab cache helper object
    :returns: the count of per cpu free objects
    """
    cpu_free_set: Set[int] = set()
    slub_helper._slub_get_freelist(cpu_freelist, cpu_free_set)

    return len(cpu_free_set)


def slub_per_cpu_partial_free(cpu_partial: Object) -> int:
    """
    Get the partial free from percpu partial list

    :param cpu_partial: `struct page` drgn object
        of kmem_cache->cpu_slab->partial list
    :returns: free objects from partial list
    """

    partial_free = partial_objects = partial_inuse = 0

    while cpu_partial:
        page = cast("struct page *", cpu_partial)

        partial_objects = page.objects.value_()
        partial_inuse = page.inuse.value_()
        partial_free += partial_objects - partial_inuse
        cpu_partial = page.next

    return partial_free


def kmem_cache_slub_info(cache: Object) -> tuple:
    """
    For given kmem_cache object, parse through each cpu
    and get number of total slabs and  free objects

    :param: `struct kmem_cache` drgn object
    :returns: total slabs, free objects
    """
    prog = cache.prog_

    total_slabs = objects = free_objects = 0
    slub_helper = _get_slab_cache_helper(cache)

    for cpuid in for_each_present_cpu(prog):
        per_cpu_slab = per_cpu_ptr(cache.cpu_slab, cpuid)
        cpu_freelist = per_cpu_slab.freelist
        cpu_slab_ptr = per_cpu_slab.page
        cpu_partial = per_cpu_slab.partial

        if not cpu_slab_ptr:
            continue

        page_inuse = cpu_slab_ptr.inuse.value_()
        objects = cpu_slab_ptr.objects.value_()

        if objects < 0:
            objects = 0

        free_objects += objects - page_inuse
        cpu_free_objects = slub_get_cpu_freelist_cnt(cpu_freelist, slub_helper)
        free_objects += cpu_free_objects

        partial_frees = slub_per_cpu_partial_free(cpu_partial)
        free_objects += partial_frees

        total_slabs += 1

    return total_slabs, free_objects


def get_kmem_cache_slub_info(cache: Object) -> SlabCacheInfo:
    """
    Get slab information for given slab cache

    :param cache: `struct kmem_cache` drgn object
    :returns: a namedtuple SlabCacheInfo that describes
        summary info about a slab cache
    """
    total_slabs, free_objects = kmem_cache_slub_info(cache)
    (
        nr_slabs,
        nr_total_objs,
        nr_partial,
        node_total_use,
        nr_free,
    ) = collect_node_info(cache)
    cpu_per_node = kmem_cache_percpu(cache)

    full_slabs = nr_slabs - cpu_per_node - nr_partial
    free_objects += nr_free
    total_slabs += nr_partial
    total_slabs += full_slabs
    inuse = nr_total_objs - free_objects
    ssize = int((int(cache.prog_["PAGE_SIZE"]) << int(cache.oo.x >> 16)))

    return SlabCacheInfo(
        cache,
        int(cache.object_size),
        inuse,
        nr_total_objs,
        total_slabs,
        ssize,
        cache.name.string_().decode("utf-8"),
    )


def print_slab_info(prog: Program) -> None:
    """
    Helper to print slab information
    """
    output = [
        ["CACHE", "OBJSIZE", "ALLOCATED", "TOTAL", "SLABS", "SSIZE", "NAME"]
    ]
    for cache in for_each_slab_cache(prog):
        slabinfo = get_kmem_cache_slub_info(cache)
        output.append(
            [
                hex(slabinfo.cache.value_()),
                str(slabinfo.objsize),
                str(slabinfo.allocated),
                str(slabinfo.total),
                str(slabinfo.nr_slabs),
                f"{int(slabinfo.ssize / 1024)}k",
                slabinfo.name,
            ]
        )
    print_table(output)


class SlabInfo(CorelensModule):
    """
    Corelens Module for slabinfo
    """

    name = "slabinfo"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_slab_info(prog)
