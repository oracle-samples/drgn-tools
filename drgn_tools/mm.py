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

from drgn_tools.debuginfo import vmcoreinfo_data


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
        # ARM64 address space is rather variable. These ranges are only written
        # with consideration to UEK6 and later.
        MB = 1024 * 1024
        GB = 1024 * MB
        vmcoreinfo = vmcoreinfo_data(prog)

        # We can rely the following being in vmcoreinfo:
        # NUMBER(VA_BITS), NUMBER(kimage_voffset), NUMBER(PHYS_OFFSET):
        #   v4.12 commit 20a166243328c ("arm64: kdump: add VMCOREINFO's for
        #   user-space tools")
        # KERNELOFFSET: v4.19 commit: e401b7c2c6900 ("arm64, kaslr: export
        #   offset in VMCOREINFO ELF notes")
        va_bits = int(vmcoreinfo["NUMBER(VA_BITS)"])
        if va_bits != 48:
            raise NotImplementedError(
                "Drgn-tools does not (yet) support arm64 with {va_bit} bit VAs"
            )

        # These values are the direct map, for determining vmemmap ranges as
        # well.
        page_offset = (1 << 64) - (1 << va_bits)
        page_end = (1 << 64) - (1 << va_bits - 1)

        # At some point betwen 5.15 and 6.12, __bss_stop stopped being relocated.
        # Detect this and fix it up.
        bss_start = prog.symbol("__bss_start").address
        bss_stop = prog.symbol("__bss_stop").address
        if bss_stop < bss_start:
            bss_stop += int(vmcoreinfo["KERNELOFFSET"], 16)

        # User memory, direct map, and most of the kernel image address kinds
        # are quite easy to determine via symbols or constants, or based on the
        # VA Size.
        basic_ranges = [
            # 0x0000000000000000 - 0x0000ffffffffffff
            (cls.USER, 0, (1 << va_bits) - 1),
            # 0xffff000000000000 - 0xffff800000000000
            (cls.DIRECT_MAP, page_offset, page_end),
            # These are just relocated based on kaslr offset so we don't need to
            # do anything.
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
            # We're relying on ordering here. per_cpu lies within initdata,
            # so put it earlier in the list so that it is identified first.
            (
                cls.PERCPU,
                prog.symbol("__per_cpu_start").address,
                prog.symbol("__per_cpu_end").address,
            ),
            (
                cls.DATA,  # TODO: should we have initdata?
                prog.symbol("__initdata_begin").address,
                prog.symbol("__initdata_end").address,
            ),
            (
                cls.DATA,
                prog.symbol("_sdata").address,
                prog.symbol("_edata").address,
            ),
            (
                cls.BSS,
                bss_start,
                bss_stop,
            ),
        ]

        # Now for the tricky part: determining modules and vmalloc regions.
        # We're really relying on UEK configuration and versions here. This is
        # only valid for UEK6 and later, with CONFIG_RANDOMIZE_BASE enabled.
        # It works with or without KASLR being enabled at runtime, but
        # CONFIG_RANDOMIZE_BASE is required to be enabled.

        # These constants are in vmcoreinfo since v5.18 commit 2369f171d5c55
        # ("arm64: crash_core: Export MODULES, VMALLOC, and VMEMMAP ranges").
        # They should be taken with a grain of salt because they are
        # preprocessor constants. MODULES_VADDR is subject to KASLR, so the
        # preprocessor constant is summarily ignored in that case.
        if "NUMBER(MODULES_VADDR)" in vmcoreinfo:
            modules_end = int(vmcoreinfo["NUMBER(MODULES_END)"], 16)
            vmalloc_start = modules_end
            vmalloc_end = int(vmcoreinfo["NUMBER(VMALLOC_END)"], 16)
            vmemmap_start = int(vmcoreinfo["NUMBER(VMEMMAP_START)"], 16)
            vmemmap_end = int(vmcoreinfo["NUMBER(VMEMMAP_END)"], 16)
        else:
            # Otherwise, we need to fudge things a bit. Vmalloc starts at the
            # end of the statically configured module region, and continues
            # until basically the vmemmap. (There is technically some PCI I/O
            # and fixmap stuff in there... but we're fudging things at this
            # point)
            vmalloc_start = page_end + 128 * MB
            vmemmap_start = prog["vmemmap"].value_()
            vmalloc_end = vmemmap_start
            # Size of the vmemmap is defined in terms of the direct map size and
            # struct page.
            vmemmap_size = (
                (page_end - page_offset) // prog["PAGE_SIZE"].value_()
            ) * prog.type("struct page").size
            vmemmap_end = vmemmap_start + vmemmap_size

        vmemmap_vmalloc_regions = [
            (cls.VMEMMAP, vmemmap_start, vmemmap_end),
            (cls.VMALLOC, vmalloc_start, vmalloc_end),
        ]

        # Ok, now handle the module base address(es)
        module_regions = []
        try:
            # v6.5 commit 3e35d303ab7d ("arm64: module: rework module VA
            # range selection") changes the module virtual region to 2GiB.
            # It also introduces the variables module_direct_base and
            # module_plt_base. These are each
            module_direct = prog["module_direct_base"].value_()
            if module_direct:
                module_regions.append(
                    (cls.MODULE, module_direct, module_direct + 128 * MB)
                )
            module_plt = prog["module_plt_base"].value_()
            if module_plt:
                module_regions.append(
                    (cls.MODULE, module_plt, module_plt + 2 * GB)
                )
        except LookupError:
            # Prior to that commit, we just had module_alloc_base.
            # Interestingly, module allocations were actually allowed to spill
            # out over 2 GiB if allocation within the first 128 MiB was
            # impossible, and KASAN was disabled and CONFIG_ARM64_MODULE_PLTS
            # was enabled. It seems totally feasible to believe that this
            # happens on real systems. We're ignoring that here, because it's
            # uncertain how to distinguish between real vmalloc allocations and
            # module allocations that spilled out.
            module_alloc = prog["module_alloc_base"].value_()
            module_regions.append(
                (cls.MODULE, module_alloc, module_alloc + 128 * MB)
            )

        return basic_ranges + module_regions + vmemmap_vmalloc_regions

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


def check_freelists_at_cpu(prog: drgn.Program, cpu: int) -> None:
    for slab_cache in for_each_slab_cache(prog):
        cpu_slab = per_cpu_ptr(slab_cache.cpu_slab.read_(), cpu)
        if cpu_slab.freelist.value_():
            try:
                _ = prog.read(cpu_slab.freelist.value_(), 1)
            except FaultError:
                slab_cache_name = escape_ascii_string(
                    slab_cache.name.string_(), escape_backslash=True
                )
                print(
                    f"found freelist corruption in lockless freelist of slab-cache: {slab_cache_name} at cpu: {cpu}"
                )
                return

    print(
        "No freelist corruption detected at crashing CPU. Run full slab validator for comprehensive check"
    )
