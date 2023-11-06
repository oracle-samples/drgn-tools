# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for examining the memory management subsystem.
"""
import enum
import math
from typing import List
from typing import Tuple

import drgn
from drgn import FaultError
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.boot import pgtable_l5_enabled
from drgn.helpers.linux.list import list_for_each_entry
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
    def _ranges_x86_64(
        cls, prog: drgn.Program
    ) -> List[Tuple["AddrKind", int, int]]:
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
        return ranges

    @classmethod
    def _ranges_aarch64(
        cls, prog: drgn.Program
    ) -> List[Tuple["AddrKind", int, int]]:
        # For canonical information on this, see documentation:
        # https://www.kernel.org/doc/html/latest/arch/arm64/memory.html
        # And more importantly, code:
        # arch/arm64/include/asm/memory.h
        # The docs neglect to describe how KASLR impacts things.

        MB = 1024 * 1024
        GB = 1024 * MB

        vmcoreinfo = dict(
            line.split("=", 1)
            for line in prog["VMCOREINFO"]
            .string_()
            .decode("utf-8")
            .strip()
            .split("\n")
        )
        va_bits = int(vmcoreinfo["NUMBER(VA_BITS)"])
        if va_bits != 48:
            raise NotImplementedError(
                "Drgn-tools does not (yet) support arm64 with {va_bit} bit VAs"
            )

        page_offset = (1 << 64) - (1 << va_bits)
        modules_vaddr = (1 << 64) - (1 << (va_bits - 1))
        try:
            # 3e35d303ab7d ("arm64: module: rework module VA range selection")
            # changes the module virtual region to 2GiB. It also introduces the
            # variable "module_direct_base", which we can use to detect it
            prog.symbol("module_direct_base")
            modules_vsize = 2 * GB
        except LookupError:
            modules_vsize = 128 * MB
        modules_end = modules_vaddr + modules_vsize

        # vmemmap is at the end of the address space, except for a guard hole
        # (whose size depends on the kernel version). Thankfully, Drgn already
        # knows how to find it, so all we need to do is calculate the length.
        # The length doesn't seem to vary based on kernel version.
        # The computation is seen in arch/arm64/include/asm/memory.h,
        # essentially we take the max length of the direct map, convert to
        # pages, and multiply by the aligned #bytes per struct page. Direct map
        # spans page_offset to modules_vaddr
        vmemmap_start = prog["vmemmap"].value_()
        page_order = int(math.log2(prog.type("struct page").size - 1)) + 1
        vmemmap_size = (modules_vaddr - page_offset) >> (
            prog["PAGE_SHIFT"].value_() - page_order
        )

        # For arm64, the kernel image mapping is actually within VMALLOC_START
        # .. VMALLOC_END. In fact, VMALLOC_START = MODULES_END. So we need to be
        # careful to split up the vmalloc region into a section before, and a
        # section after the kernel image.
        #
        # What's worse, in 9ad7c6d5e75b ("arm64: mm: tidy up top of kernel VA
        # space"), the top of the vmalloc space became VMEMMAP_START - 256MiB.
        # Prior to that, it was defined as: (- PUD_SIZE - VMEMMAP_SIZE - 64
        # KiB)... Unfortunately, the commit that does this, makes no change in
        # terms of symbols or variables!
        #
        # We can use two tricks to help resolve this problem.
        # 1. The /proc/kcore implementation contains a handy list of memory
        #    ranges and their types. We can find the range which begins with
        #    VMALLOC_START, and read the size out of it to get the end.
        #    This is a nice, easy way to handle it, but it depends on having
        #    CONFIG_PROC_KCORE enabled, and the kernel must have finished
        #    initialization. Debugging partially initialized kernels should be
        #    possible, so we'd like a backup, even a less-than-perfect one.
        # 2. If that doesn't work, we can fall back on using the vmemmap_start
        #    as the top of vmalloc. This is not strictly correct: there's a
        #    "fixmap" region in between as well as an IO range. However... it's
        #    the best we can do for this case.
        vmalloc_end = vmemmap_start
        try:
            KCORE_VMALLOC = prog.constant("KCORE_VMALLOC")
            for kcl in list_for_each_entry(
                "struct kcore_list", prog["kclist_head"].address_of_(), "list"
            ):
                # In the code, VMALLOC_START is defined to MODULES_END
                if kcl.type == KCORE_VMALLOC and kcl.addr == modules_end:
                    vmalloc_end = (kcl.addr + kcl.size).value_()
        except LookupError:
            pass

        return [
            (cls.USER, 0, (1 << va_bits) - 1),
            (cls.DIRECT_MAP, page_offset, modules_vaddr),
            (cls.MODULE, modules_vaddr, modules_end),
            # In between the modules_end and _text, there's the KASLR
            # offset. This is more vmalloc!
            (cls.VMALLOC, modules_end, prog.symbol("_text").address),
            (
                cls.TEXT,
                prog.symbol("_text").address,
                prog.symbol("_etext").address,
            ),
            (
                cls.RODATA,
                prog.symbol("__start_rodata").address,
                prog.symbol("__end_rodata").address,
            ),
            (
                cls.INITTEXT,
                prog.symbol("__inittext_begin").address,
                prog.symbol("__inittext_end").address,
            ),
            (
                # TODO: should we have INITDATA too?
                # NOTE: initdata begin .. end includes percpu, as well as some
                # hypervisor percpu things, and relocation information. We're
                # splitting initdata here to ensure we get it right.
                cls.DATA,
                prog.symbol("__initdata_begin").address,
                prog.symbol("__per_cpu_start").address,
            ),
            (
                cls.PERCPU,
                prog.symbol("__per_cpu_start").address,
                prog.symbol("__per_cpu_end").address,
            ),
            (
                cls.DATA,
                prog.symbol("__per_cpu_end").address,
                prog.symbol("__initdata_end").address,
            ),
            (
                cls.DATA,
                prog.symbol("_sdata").address,
                prog.symbol("_edata").address,
            ),
            (
                cls.BSS,
                prog.symbol("__bss_start").address,
                prog.symbol("__bss_stop").address,
            ),
            (
                cls.VMALLOC,
                prog.symbol("_end").address,
                vmalloc_end,
            ),
            # There's some arch-specific junk between _text and _end which isn't
            # fully covered by the ranges above for the kernel image. For the
            # most part this shouldn't matter.
            (cls.VMEMMAP, vmemmap_start, vmemmap_start + vmemmap_size),
        ]

    @classmethod
    def _ranges(cls, prog: drgn.Program) -> List[Tuple["AddrKind", int, int]]:
        ranges = prog.cache.get("drgn_tools_AddrKind_ranges")
        if ranges:
            return ranges

        if prog.platform.arch == drgn.Architecture.X86_64:
            ranges = cls._ranges_x86_64(prog)
        elif prog.platform.arch == drgn.Architecture.AARCH64:
            ranges = cls._ranges_aarch64(prog)
        else:
            raise NotImplementedError(
                f"AddrKind is not implemented for {prog.platform.arch}"
            )
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
