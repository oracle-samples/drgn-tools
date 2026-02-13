# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn.helpers.linux.slab import find_slab_cache

from drgn_tools import slabinfo


def test_slabinfo(prog):
    slabinfo.print_slab_info(prog)


def test_slabdump(prog):
    cache = find_slab_cache(prog, "kmalloc-256")
    slabinfo.dump_slab_objects(cache, limit=10)
