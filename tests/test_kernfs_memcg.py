# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import kernfs_memcg as kernfs_memcg
from tests import DrgnToolsTestCase


class TestKernfsMemcg(DrgnToolsTestCase):
    def test_dump_page_cache_pages_pinning_cgroups(self):
        kernfs_memcg.dump_page_cache_pages_pinning_cgroups(
            self.prog, 10, 1000000
        )

    def test_dump_memcgroup_hierarchy(self):
        kernfs_memcg.dump_memcgroup_hierarchy(self.prog)

    def test_kernfs_node_of_memcgroup(self):
        count = 0
        for kn in kernfs_memcg.for_each_kernfs_node(self.prog):
            if kernfs_memcg.kernfs_node_of_memcgroup(kn):
                count = count + 1
            if count >= 5:
                print("Found 5 memcgroup, kernfs_node objects.")
                break

    def test_get_num_active_mem_cgroups(self):
        count = kernfs_memcg.get_num_active_mem_cgroups(self.prog)
        print(f"number of active memcgroups: {count}\n")

    def test_get_num_dying_mem_cgroups(self):
        count = kernfs_memcg.get_num_dying_mem_cgroups(self.prog)
        print(f"number of dying memcgroups: {count}\n")
