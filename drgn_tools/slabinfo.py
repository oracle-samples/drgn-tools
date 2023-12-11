# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper to view slabinfo data
"""
import argparse
from typing import Set

import drgn
from drgn import cast
from drgn import FaultError
from drgn import sizeof
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.slab import for_each_slab_cache

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table

PAGE_MAPPING_ANON = 1
output = []


def collect_node_info(
    prog: drgn.Program,
    s: drgn.Object,
    nrnodeid: int,
    total_slabs: int,
    free_objects: int,
    total_inuse: int,
) -> None:
    """
    collect per node slab data and
    print the collective output
    """
    nr_slabs = 0
    nr_total_objs = 0
    nr_free = 0
    nr_partial = 0
    node_total_use = 0
    full_slabs = 0
    cpu_per_node = 0
    ad = hex(s.value_())
    ssize = int((int(prog["PAGE_SIZE"]) << int(s.oo.x >> 16)) / 1024)

    for nodeid in range(nrnodeid):
        kmem_cache_node = s.node[nodeid]
        x = 0
        nr_slabs = nr_slabs + kmem_cache_node.nr_slabs.counter.value_()
        nr_total_objs = (
            nr_total_objs + kmem_cache_node.total_objects.counter.value_()
        )
        nr_partial = nr_partial + kmem_cache_node.nr_partial.value_()
        cpu_per_node = 0
        try:
            for page in list_for_each_entry(
                "struct page",
                kmem_cache_node.partial.address_of_(),
                "slab_list",
            ):
                nrobj = page.objects.value_()
                nrinuse = page.inuse.value_()
                x = nrobj - nrinuse
                node_total_use += nrinuse
                nr_free += x
        except LookupError:
            for page in list_for_each_entry(
                "struct page", kmem_cache_node.partial.address_of_(), "lru"
            ):
                nrobj = page.objects.value_()
                nrinuse = page.inuse.value_()
                x = nrobj - nrinuse
                node_total_use += nrinuse
                nr_free += x

        for cpuid in for_each_online_cpu(prog):
            try:
                per_cpu_slab = per_cpu_ptr(s.cpu_slab, cpuid)
            except FaultError:
                per_cpu_slab = 0
            else:
                cpu_slab_ptr = per_cpu_slab.page
                if not cpu_slab_ptr:
                    continue
                cpu_per_node += 1

        full_slabs = nr_slabs - cpu_per_node - nr_partial

    total_inuse += nr_total_objs
    free_objects += nr_free
    total_slabs += nr_partial
    total_slabs += full_slabs
    inuse = total_inuse - free_objects
    output.append(
        [
            ad,
            int(s.object_size),
            inuse,
            total_inuse,
            total_slabs,
            f"{ssize}k",
            s.name.string_().decode("utf-8"),
        ]
    )


def freelist_dereference_swab(
    prog: drgn.Program, slab_cache: drgn.Object, ptr_addr: int
) -> int:
    """
    Freelist traversal with swab
    """
    freelist_random = slab_cache.random.value_()
    ulong_size = sizeof(prog.type("unsigned long"))
    return (
        prog.read_word(ptr_addr)
        ^ freelist_random
        ^ int.from_bytes(ptr_addr.to_bytes(ulong_size, "little"), "big")
    )


def freelist_dereference_noswab(
    prog: drgn.Program, slab_cache: drgn.Object, ptr_addr: int
) -> int:
    """
    Freelist traversal with no swab
    """
    freelist_random = slab_cache.random.value_()
    return prog.read_word(ptr_addr) ^ freelist_random ^ ptr_addr


def try_hardened_freelist_dereference(
    prog: drgn.Program, slab_cache: drgn.Object, ptr_addr: int
) -> int:
    """
    Segregate the free list traverse based on CONFIG_SLAB_FREELIST_HARDENED
    """
    try:
        slab_cache.random.value_()

    except AttributeError:
        slab_freelist_hardened = 0
        needswab = 0

    else:
        slab_freelist_hardened = 1
        needswab = 1

    if slab_freelist_hardened and needswab:
        result = freelist_dereference_swab(prog, slab_cache, ptr_addr)
    if not slab_freelist_hardened and not needswab:
        try:
            result = prog.read_word(ptr_addr)
        except FaultError:
            result = 0

    return result


def slub_get_freelist(
    prog: drgn.Program,
    slab_cache: drgn.Object,
    freelist: drgn.Object,
    freelist_set: Set[int],
) -> None:
    """
    Main function to traverse through the freelist data of kmem_cache_cpu
    """
    ptr = freelist.value_()
    while ptr:
        if ptr & PAGE_MAPPING_ANON:
            break
        freelist_set.add(ptr)
        ptr = try_hardened_freelist_dereference(
            prog, slab_cache, (ptr + slab_cache.offset.value_())
        )


def slub_get_cpu_freelist(
    prog: drgn.Program, slab_cache: drgn.Object, cpu_freelist: drgn.Object
) -> set:
    """
    Collect freelist data from kmem_cache_cpu and
    return the set of free objects
    """
    cpu_free_set: Set[int] = set()
    slub_get_freelist(prog, slab_cache, cpu_freelist, cpu_free_set)
    return cpu_free_set


def slub_get_cpu_freelist_cnt(
    prog: drgn.Program, slab_cache: drgn.Object, cpu_freelist: drgn.Object
) -> int:
    """
    Collect freelist data from kmem_cache_cpu and
    return the count of free objects
    """
    cpu_free_set_rc = slub_get_cpu_freelist(prog, slab_cache, cpu_freelist)
    return len(cpu_free_set_rc)


def slub_partial_free(
    prog: drgn.Program, slab_cache: drgn.Object, slab: drgn.Object
) -> int:
    """
    Collect partial list from kmem_cache_cpu
    """
    cpu_partial = slab
    pss_cnt = 0
    partial_free = partial_objects = partial_inuse = 0

    while cpu_partial:
        page = cast("struct page *", cpu_partial)

        try:
            partial_objects = page.objects.value_()
        except AttributeError:
            partial_objects = 0
            return 0

        try:
            partial_inuse = page.inuse.value_()
        except AttributeError:
            partial_inuse = 0
            return 0

        partial_free += partial_objects - partial_inuse

        try:
            cpu_partial = page.next
        except AttributeError:
            cpu_partial = 0
        pss_cnt += 1

    return partial_free


def kmem_cache_slub_info(
    prog: drgn.Program, slab: drgn.Object, nrnodeid: int
) -> None:
    """
    Collect the per-slab data.
    Traverse though all the CPUs to collect the slab data.
    """
    total_slabs = objects = free_objects = total_inuse = 0

    for cpuid in for_each_online_cpu(prog):
        try:
            per_cpu_slab = per_cpu_ptr(slab.cpu_slab, cpuid)
        except FaultError:
            continue
        else:
            cpu_freelist = per_cpu_slab.freelist
            cpu_slab_ptr = per_cpu_slab.page
            cpu_partial = per_cpu_slab.partial

            if not cpu_slab_ptr:
                continue

        try:
            page_inuse = cpu_slab_ptr.inuse.value_()
        except AttributeError:
            page_inuse = 0

        try:
            objects = cpu_slab_ptr.objects.value_()
        except AttributeError:
            objects = 0
            continue
        if objects < 0:
            objects = 0

        free_objects += objects - page_inuse
        cpu_free_objects = slub_get_cpu_freelist_cnt(prog, slab, cpu_freelist)
        free_objects += cpu_free_objects
        objects = 0
        page_inuse = 0
        partial_frees = slub_partial_free(prog, slab, cpu_partial)
        free_objects += partial_frees
        total_slabs += 1

    collect_node_info(
        prog, slab, nrnodeid, total_slabs, free_objects, total_inuse
    )


def get_slab_info(prog: drgn.Program) -> None:
    """
    Print the slab headers and initiate the slab collection
    process for all slabs
    """
    output.append(
        ["CACHE", "OBJSIZE", "ALLOCATED", "TOTAL", "SLABS", "SSIZE", "NAME"]
    )
    nrnodeid = prog["nr_node_ids"].value_()
    for slab in for_each_slab_cache(prog):
        kmem_cache_slub_info(prog, slab, nrnodeid)

    print_table(output)


class SlabInfo(CorelensModule):
    """
    Corelens Module for slabinfo
    """

    name = "slabinfo"

    def run(self, prog: drgn.Program, args: argparse.Namespace) -> None:
        get_slab_info(prog)
