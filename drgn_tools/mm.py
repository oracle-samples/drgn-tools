# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for examining the memory management subsystem.
"""
import enum
from typing import List
from typing import Tuple

import drgn
from drgn import FaultError
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.boot import pgtable_l5_enabled
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.slab import for_each_slab_cache


class AddrKind(enum.Enum):
    """
    An enumeration of possible virtual memory address kinds.

    The kernel can have a huge variety of kinds of memory: percpu data,
    memory for device I/O, read-only data, and more. Understanding what kind of
    memory address you're dealing with can help with a variety of debugging
    tasks.
    """

    USER = "user"
    """Userspace memory."""

    DIRECT_MAP = "direct map"
    """
    An address from the direct mapping of virtual addresses to physical.

    A lot of kernel addresses (such as memory allocated via the slab allocator)
    fall under this category.
    """

    TEXT = "text"
    """
    An address from the vmlinux / core kernel's text segment.

    Most code falls under this category. However, some __init code is discarded
    after boot, and is part of INITTEXT.
    """
    INITTEXT = "inittext"
    """
    An address from the vmlinux / core kernel's __init text segment.

    These are functions decorated with the "__init" macro. Their memory is
    freed after initializing the kernel. However, their symbols remain, and the
    virtual addresses used to refer to them don't get reused. Thus, you could
    see these addresses in a booted system, though it would be quite unlikely.
    """

    DATA = "data"
    """
    An address from the vmlinux / core kernel's RW data segment.

    These are static data structures which are initialized to some non-zero
    value, and not declared const.
    """
    RODATA = "rodata"
    """
    An address from the vmlinux / core kernel's RO data segment.

    These are static data structures which are declared const.
    """
    BSS = "bss"
    """
    An address from the vmlinux / core kernel's BSS data segment.

    These are static data structures which aren't initialized to a non-zero
    value. As such, they are placed into a separate section and their memory is
    zero'd at initialization.
    """
    PERCPU = "percpu"
    """
    An address from the vmlinux / core kernel which refers to percpu data.

    Please note that as of now, we can only detect static percpu variables from
    the core kernel. Modules and dynamically allocated percpu variables are
    harder to detect, and are in the works.
    """

    VMEMMAP = "vmemmap"
    """
    An address from virtual memory map section.

    The memory map is an array of "struct page" that describes all physical
    memory. When CONFIG_SPARSEMEM_VMEMMAP is enabled, the memory mapping is in
    a separate virtual address range, which allows "holes" in the memory
    mapping to be unmapped, saving a significant portion of memory when there
    are lots of holes in the physical address space.

    What this means is that, when CONFIG_SPARSEMEM_VMEMMAP is enabled, all
    ``struct page *`` addresses are within the vmemmap region. If you see a
    struct page, you know it should be in the vmemmap, and if you see a
    vmemmap address, you know it must be a struct page. On UEK, VMEMMAP is
    always enabled, however in general, it is configuration specific.
    """
    VMALLOC = "vmalloc"
    """
    An address from vmalloc.

    The vmalloc subsystem serves a variety of purposes (vmalloc allocator,
    vmap, ioremap). It allows the kernel to allocate large ranges of virtually
    contiguous, but physically discontiguous memory, as well as map physical
    I/O memory addresses into the kernel range. It also allows the kernel to
    allocate memory with "guard pages" that protect against over/under flow.

    These addresses may be returned by vmalloc(), or setup by vmap() or
    ioremap(). A common example of this category of memory is kernel stacks,
    and another quite common example is memory-mapped I/O ranges.
    """
    MODULE = "module"
    """
    An address from the kernel module range.

    Modules have a reserved range of memory into which their code and data
    pages are mapped.
    """

    UNKNOWN = "unknown"
    """
    An address which we could not categorize.
    """

    @classmethod
    def _ranges(cls, prog: drgn.Program) -> List[Tuple["AddrKind", int, int]]:
        ranges = prog.cache.get("drgn_tools_AddrKind_ranges")
        if ranges:
            return ranges

        # See include/asm-generic/vmlinux-lds.h
        # and also Documentation/x86/x86_64/mm.{rst,txt}
        # Convenient link:
        # https://www.kernel.org/doc/html/latest/x86/x86_64/mm.html
        try:
            page_offset_base = prog["page_offset_base"].value_()
        except KeyError:
            # Prior to 021182e52fe0 ("x86/mm: Enable KASLR for physical mapping
            # memory regions"), page_offset_base did not exist and there was
            # just a constant for the beginning of the memory map.
            page_offset_base = 0xFFFF880000000000
        max_pfn = int(prog["max_pfn"])
        page_size = int(prog["PAGE_SIZE"])
        top_of_map = page_offset_base + max_pfn * page_size

        try:
            vmalloc_base = prog["vmalloc_base"].value_()
        except KeyError:
            # Prior to a95ae27c2ee1 ("x86/mm: Enable KASLR for vmalloc memory
            # regions"), vmalloc_base did not exist and there was this
            # constant.
            vmalloc_base = 0xFFFFC90000000000
        if pgtable_l5_enabled(prog):
            vmalloc_end = vmalloc_base + (12800 << 40)
        else:
            vmalloc_end = vmalloc_base + (32 << 40)

        try:
            vmemmap_base = prog["vmemmap_base"].value_()
        except KeyError:
            # Prior to 25dfe4785332 ("x86/mm/64: Enable KASLR for vmemmap
            # memory region"), vmemmap_base did not exist and there was this
            # constant.
            vmemmap_base = 0xFFFFEA0000000000
        vmemmap_end = vmemmap_base + max_pfn * drgn.sizeof(
            prog.type("struct page")
        )

        pcpu_end = prog.symbol("__per_cpu_end").address

        ranges = [
            (
                cls.PERCPU,
                prog.symbol("__per_cpu_start").address,
                pcpu_end,
            ),
            (
                cls.USER,
                pcpu_end,
                # This value is based on the 5-level paging support. There's no
                # real harm in using it when only 4-level paging is enabled,
                # since the addresses between the 4 and 5 level userspace
                # boundaries are a hole anyway.
                0x00FFFFFFFFFFFFFF,
            ),
            (
                cls.DIRECT_MAP,
                page_offset_base,
                top_of_map,
            ),
            (
                cls.VMALLOC,
                vmalloc_base,
                vmalloc_end,
            ),
            (
                cls.VMEMMAP,
                vmemmap_base,
                vmemmap_end,
            ),
            (
                cls.INITTEXT,
                prog.symbol("_sinittext").address,
                prog.symbol("_einittext").address,
            ),
            (
                cls.TEXT,
                prog.symbol("_stext").address,
                prog.symbol("_etext").address,
            ),
            (
                cls.RODATA,
                prog.symbol("__start_rodata").address,
                prog.symbol("__end_rodata").address,
            ),
            (
                cls.BSS,
                prog.symbol("__bss_start").address,
                prog.symbol("__bss_stop").address,
            ),
            (
                cls.DATA,
                prog.symbol("_sdata").address,
                prog.symbol("_edata").address,
            ),
            (
                cls.MODULE,
                # Hard coded, but no difference b/w 4 and 5 level paging
                0xFFFFFFFFA0000000,
                0xFFFFFFFFFEFFFFFF,
            ),
        ]
        prog.cache["drgn_tools_AddrKind_ranges"] = ranges
        return ranges

    @classmethod
    def categorize(
        cls, prog: drgn.Program, addr: drgn.IntegerLike
    ) -> "AddrKind":
        """
        Given a memory address, tell what kind of memory it refers to.

        Please note that right now, this is x86_64-specific and restricted to
        the configurations used by UEK.

        :param prog: program we're debugging
        :param addr: address to categorize
        """
        if prog.platform.arch != drgn.Architecture.X86_64:
            raise NotImplementedError("Only implemented for x86_64")
        addr = int(addr)

        for kind, start, end in cls._ranges(prog):
            if addr >= start and addr < end:
                return kind

        return cls.UNKNOWN


def totalram_pages(prog: drgn.Program) -> drgn.Object:
    """
    The value of totalram_pages is used to show MemTotal in /proc/meminfo.

    It was defined as ``unsigned long totalram_pages``, and then changed to
    ``atomic_long_t _totalram_pages`` in commit `ca79b0c211af`__ ("mm: convert
    totalram_pages and totalhigh_pages variables to atomic")

    __ http://git.kernel.org/torvalds/c/ca79b0c211af

    Return this value as a drgn unsigned long.

    :param prog: program to read from
    :returns: The total RAM pages as a drgn ``unsigned long``
    """
    if "_totalram_pages" in prog:
        return prog["_totalram_pages"].counter
    return prog["totalram_pages"]


def check_freelists_at_crashing_cpu(prog: drgn.Program) -> None:
    crashing_cpu = prog["crashing_cpu"].value_()
    for slab_cache in for_each_slab_cache(prog):
        cpu_slab = per_cpu_ptr(slab_cache.cpu_slab.read_(), crashing_cpu)
        if cpu_slab.freelist.value_():
            try:
                _ = prog.read(cpu_slab.freelist.value_(), 1)
            except FaultError:
                slab_cache_name = escape_ascii_string(
                    slab_cache.name.string_(), escape_backslash=True
                )
                print(
                    f"found freelist corruption in lockless freelist of slab-cache: {slab_cache_name} at crash cpu: {crashing_cpu}"
                )
                return

    print(
        "No freelist corruption detected at crashing CPU. Run full slab validator for comprehensive check"
    )
