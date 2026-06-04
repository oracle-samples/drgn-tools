# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from resource import getpagesize

import drgn
from drgn.helpers.linux import module_address_regions
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.mm import virt_to_page

from drgn_tools import mm
from tests import DrgnToolsTestCase
from tests import skip_live
from tests import xfail


class TestMm(DrgnToolsTestCase):
    def test_totalram_pages(self):
        reported_pages = mm.totalram_pages(self.prog).value_()

        if self.prog.flags & drgn.ProgramFlags.IS_LIVE:
            # We're running live! Let's test it against
            # the value reported in /proc/meminfo.
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        mem_kb = int(line.split()[1])
                        break
                else:
                    self.fail("No memory size found")
            mem_bytes = mem_kb * 1024
            mem_pages = mem_bytes / getpagesize()

            self.assertEqual(mem_pages, reported_pages)
        else:
            # We cannot directly confirm the memory value.
            # We've already verified that we can lookup the
            # value without error, now apply a few "smoke
            # tests" to verify it's not completely wonky.

            # At least 512 MiB of memory:
            self.assertGreater(
                reported_pages, (512 * 1024 * 1024) / getpagesize()
            )
            # Less than 4 TiB of memory:
            self.assertLess(
                reported_pages,
                (4 * 1024 * 1024 * 1024 * 1024) / getpagesize(),
            )

    def test_AddrKind_categorize_text(self):
        # A pretty standard, common function.
        dput = self.prog.symbol("dput").address
        self.assertEqual(
            mm.AddrKind.categorize(self.prog, dput), mm.AddrKind.TEXT
        )

        # An init function.
        start_kernel = self.prog.symbol("start_kernel").address
        self.assertEqual(
            mm.AddrKind.categorize(self.prog, start_kernel),
            mm.AddrKind.INITTEXT,
        )

    def test_AddrKind_categorize_data(self):
        # kernel/panic.c: initialized to -1 (invalid cpu)
        data = self.prog.symbol("panic_cpu").address
        self.assertEqual(
            mm.AddrKind.categorize(self.prog, data), mm.AddrKind.DATA
        )

        # init/main.c: strings in argv_init are declared const
        rodata = self.prog["envp_init"][0].value_()
        self.assertEqual(
            mm.AddrKind.categorize(self.prog, rodata), mm.AddrKind.RODATA
        )

        # kernel/panic.c: uninitialized
        try:
            bss = self.prog.symbol("panic_on_taint").address
        except LookupError:
            # panic_on_taint was added in 5.8, 77cb8f12fc6e9 ("kernel: add
            # panic_on_taint"), which was backported to stable kernels. Don't fail
            # the test if it's not found. However, some vmcores in our test suite
            # are incredibly old UEK versions from before these stable backports.
            # Don't fail the tests just because this variable is not found.
            pass
        else:
            self.assertEqual(
                mm.AddrKind.categorize(self.prog, bss), mm.AddrKind.BSS
            )

        # percpu
        pcpu = self.prog.symbol("runqueues").address
        self.assertEqual(
            mm.AddrKind.categorize(self.prog, pcpu), mm.AddrKind.PERCPU
        )

    def test_AddrKind_categorize_mapped(self):
        # Pretty much any allocated kernel object is a DIRECT_MAP because it came
        # from a slab allocator. And of course, slab allocators are themselves
        # allocated via slab (except the first one) so here's a somewhat meta test:
        dm = self.prog["mm_cachep"]  # mm_struct cache
        self.assertEqual(
            mm.AddrKind.categorize(self.prog, dm.value_()),
            mm.AddrKind.DIRECT_MAP,
        )

        # Get the struct page for it, which should be vmemmap
        page = virt_to_page(dm)
        self.assertEqual(
            mm.AddrKind.categorize(self.prog, page.value_()),
            mm.AddrKind.VMEMMAP,
        )

        # Find a module and get a pointer into its data
        mods = list_for_each_entry(
            "struct module",
            self.prog["modules"].address_of_(),
            "list",
        )
        for mod in mods:
            for region in module_address_regions(mod):
                module_base = region[0]
                break
            else:
                continue  # try the next module

            # Test we can categorize modules
            self.assertEqual(
                mm.AddrKind.categorize(self.prog, module_base),
                mm.AddrKind.MODULE,
            )
            break
        else:
            self.fail(
                "Cannot AddrKind.categorize() (no kmod or missing addr)!"
            )

    # TODO: get a better accounting of the exact percpu offset start and end,
    # and make this work!
    @xfail
    def test_AddrKind_categorize_module_percpu(self):
        # Find a module and get a pointer into its data
        mods = list_for_each_entry(
            "struct module",
            self.prog["modules"].address_of_(),
            "list",
        )
        for mod in mods:
            if mod.percpu_size.value_() > 0:
                pcpu_ptr = mod.percpu.value_()
                break
        else:
            self.fail("No modules with percpu loaded, cannot test.")
        print(hex(pcpu_ptr))
        self.assertEqual(
            mm.AddrKind.categorize(self.prog, pcpu_ptr), mm.AddrKind.PERCPU
        )

    @skip_live
    def test_check_freelists_at_cpu(self):
        if "crashing_cpu" in self.prog:
            cpu = self.prog["crashing_cpu"].value_()
        else:
            cpu = self.prog["panic_cpu"].counter.value_()
        mm.check_freelists_at_cpu(self.prog, cpu)
