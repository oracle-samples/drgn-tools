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
        cgroup_subsys = self.prog["cgroup_subsys"]

        # Test against the memcg root kn:
        memory_cgrp_id = self.prog.constant("memory_cgrp_id")
        memory_subsys = cgroup_subsys[memory_cgrp_id]
        memcg_kn = memory_subsys.root.cgrp.kn
        self.assertTrue(kernfs_memcg.kernfs_node_of_cgroup(memcg_kn))
        self.assertTrue(kernfs_memcg.kernfs_node_of_memcgroup(memcg_kn))

        # Test against a kn associated with another cgroup. There may not be a
        # non-memory cgroup on the system, for example on cgroup v1. So it's ok
        # that we only assert this if we manage to find one.
        for i in range(self.prog.constant("CGROUP_SUBSYS_COUNT")):
            subsys = cgroup_subsys[i]
            if subsys and subsys.root != memory_subsys.root:
                other_cg_kn = subsys.root.cgrp.kn
                self.assertTrue(
                    kernfs_memcg.kernfs_node_of_cgroup(other_cg_kn)
                )
                self.assertFalse(
                    kernfs_memcg.kernfs_node_of_memcgroup(other_cg_kn)
                )

        # Finally, there's plenty of other kernfs nodes on the system, e.g. the
        # one associated with the sysfs root. Use that as an example which is
        # neither cgroup, nor memcg.
        other_kn = self.prog["sysfs_root"].kn
        self.assertFalse(kernfs_memcg.kernfs_node_of_cgroup(other_kn))
        self.assertFalse(kernfs_memcg.kernfs_node_of_memcgroup(other_kn))

    def test_get_num_active_mem_cgroups(self):
        count = kernfs_memcg.get_num_active_mem_cgroups(self.prog)
        print(f"number of active memcgroups: {count}\n")

    def test_get_num_dying_mem_cgroups(self):
        count = kernfs_memcg.get_num_dying_mem_cgroups(self.prog)
        print(f"number of dying memcgroups: {count}\n")
