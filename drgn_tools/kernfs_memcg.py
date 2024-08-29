from drgn import Object
from drgn.helpers.linux import find_slab_cache
from drgn.helpers.linux import slab_cache_for_each_allocated_object
from drgn.helpers.linux import kernfs_path
from drgn.helpers.linux import css_for_each_descendant_pre
from drgn.helpers.linux import cgroup_path

def dump_kernfs_nodes(prog):
    with open("kernfs_nodes_addr.txt", "w") as f:
        kernfs_node_cache = find_slab_cache(prog, "kernfs_node_cache")
        for kn in slab_cache_for_each_allocated_object(kernfs_node_cache, "struct kernfs_node"):
            try:
                if kn.flags.value_() & 0xf == 0x1:
                    path = kernfs_path(kn).decode()
                    #if "cgroup" in path:
                    f.write("kernfs_node: "+hex(kn.value_())+"  "+path+"\n")
            except:
                pass


def dump_memcgroup_hierarchy(prog):
    cgroup_subsys = prog["cgroup_subsys"][4]
    css = cgroup_subsys.root.cgrp.self.address_of_()
    print(f"dumping: {cgroup_subsys.name.string_().decode()} hierarchy")
    for pos in css_for_each_descendant_pre(css):
        print(f"path: {cgroup_path(pos.cgroup).decode()} flags: 0x{pos.flags.value_():x}")


def kernfs_node_of_cgroup(kn: Object):
    if (kn.flags.value_() & 0xf) == 0x1:
        cgrp = Object(prog, "struct cgroup", address=kn.priv.value_())
        return cgrp.kn == kn.address_of_()
    else:
        return False


def kernfs_node_of_memcgroup(kn: Object):
    if (kn.flags.value_() & 0xf) == 0x1:
        cgrp = Object(prog, "struct cgroup", address=kn.priv.value_())
        return (cgrp.kn == kn) and (prog["cgroup_subsys"][4].root == cgrp.root)
    else:
        return False


def dump_memcg_kernfs_nodes(prog):
    with open("memcg_kernfs_nodes_addr.txt", "w") as f:
        kernfs_node_cache = find_slab_cache(prog, "kernfs_node_cache")
        for kn in slab_cache_for_each_allocated_object(kernfs_node_cache, "struct kernfs_node"):
            try:
                if kernfs_node_of_memcgroup(kn):
                    path = kernfs_path(kn).decode()
                    #if "cgroup" in path:
                    f.write("kernfs_node: "+hex(kn.value_())+"  "+path+"\n")
            except:
                pass

def dump_memcg_kernfs_nodes_check(prog):
    with open("memcg_kernfs_nodes_addr.txt", "w") as f:
        count = 0
        kernfs_node_cache = find_slab_cache(prog, "kernfs_node_cache")
        for kn in slab_cache_for_each_allocated_object(kernfs_node_cache, "struct kernfs_node"):
            if (kn.flags.value_() & 0xf) == 0x1:
                print("Got dir")
                try:
                    cgrp = Object(prog, "struct cgroup", address=kn.priv.value_())
                    #cond1 = cgrp.kn == kn
                    #cond2 = prog["cgroup_subsys"][4].root == cgrp.root
                    #cond3 = cgrp.kn == kn and prog["cgroup_subsys"][4].root == cgrp.root
                    #print("cond1# ", cond1, " cond2# ", cond2, " cond3# ", cond3)
                    #if cond3:
                    if cgrp.kn == kn and prog["cgroup_subsys"][4].root == cgrp.root:
                        count = count + 1
                        path = kernfs_path(kn).decode()
                        #print("Got there")
                        #print("kernfs_node: ", hex(kn.value_()), "  ", path)
                        f.write("kernfs_node: "+hex(kn.value_())+"  "+path+"\n")
                except:
                    pass

        print("count: ", count)

