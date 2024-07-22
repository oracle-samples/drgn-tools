# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from typing import Optional
from typing import Union

from drgn import cast
from drgn import IntegerLike
from drgn import Object
from drgn import Path
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.fs import for_each_mount
from drgn.helpers.linux.fs import mount_dst
from drgn.helpers.linux.fs import mount_fstype
from drgn.helpers.linux.nodemask import for_each_online_node

from drgn_tools.list_lru import list_lru_for_each_entry
from drgn_tools.list_lru import list_lru_from_memcg_node_for_each_entry
from drgn_tools.list_lru import list_lru_kmem_to_memcgidx


def test_list_lru(
    prog: Program,
    *,
    dst: Optional[Path] = None,
    fstype: Optional[Union[str, bytes]] = None,
    verbose: Optional[IntegerLike] = None,
) -> None:
    """
    Tests memcg aware and unaware lru by walking the entire lru and use the
    kvm to look up the memcg index and then walk lru by memcg for a NUMA nodes.
    The memcg unaware lru should not find a memcg index.
    """
    for mnt in for_each_mount(
        prog,
        src=None,
        dst=dst,
        fstype=fstype,
    ):
        mnt_dst = escape_ascii_string(mount_dst(mnt), escape_backslash=True)
        mnt_fstype = escape_ascii_string(
            mount_fstype(mnt), escape_backslash=True
        )
        sb = mnt.mnt.mnt_sb
        lru = sb.s_dentry_lru
        d_cnt = 0
        errors = 0
        # iterate through the dentry lru, find the memcg index and verify entry can
        # be found by memcg
        print(
            f"memcg aware test on {mnt_dst} dentry lru at {hex(lru.address_of_())}"
        )
        for dentry in list_lru_for_each_entry(
            prog, "struct dentry", lru.address_of_(), "d_lru"
        ):
            d_cnt = d_cnt + 1
            dlru = cast("unsigned long", dentry.d_lru.address_of_())
            memcg = list_lru_kmem_to_memcgidx(prog, dlru)
            if memcg == -1:
                if verbose is not None:
                    print(f"lru for dentry {hex(dentry)} not found")
                errors = errors + 1
            else:
                found = 0
                for n in for_each_online_node(prog):
                    # look for the entry if not found in an earlier NUMA node
                    if found == 0:
                        if verbose is not None:
                            print(
                                f"looking for dentry {hex(dentry)} in memcg {memcg} node {n}"
                            )
                        for dentry2 in list_lru_from_memcg_node_for_each_entry(
                            prog,
                            memcg,
                            n,
                            "struct dentry",
                            lru.address_of_(),
                            "d_lru",
                        ):
                            if hex(dentry) == hex(dentry2):
                                found = 1
                                break
                if found == 0:
                    if verbose is not None:
                        print(
                            f"lru for dentry {hex(dentry)} NOT found at mencg idx {memcg}"
                        )
                    errors = errors + 1
                else:
                    if verbose is not None:
                        print(
                            f"lru for dentry {hex(dentry)} FOUND at mencg idx {memcg}"
                        )
        print(f"errors {errors} in {d_cnt} dentrys")
        if mnt_fstype == "xfs":
            print(
                f"memcg unaware test on {mnt_dst} xfs_buf lru at {hex(lru.address_of_())}"
            )
            # memcg unaware lru
            mp = Object(prog, "struct xfs_mount *", sb.s_fs_info)
            lru = mp.m_ddev_targp.bt_lru
            d_cnt = 0
            errors = 0
            # iterate through the xfs_buf lru, memcg index will be -1
            for bp in list_lru_for_each_entry(
                prog, "struct xfs_buf", lru.address_of_(), "b_lru"
            ):
                d_cnt = d_cnt + 1
                bplru = cast("unsigned long", bp.b_lru.address_of_())
                memcg = list_lru_kmem_to_memcgidx(prog, bplru)
                if memcg == -1:
                    if verbose is not None:
                        print(f"lru for bp {hex(bp)} not found")
                    memcg = 0
                found = 0
                for n in for_each_online_node(prog):
                    if verbose is not None:
                        print(
                            f"looking for bmap {hex(bp)} in memcg {memcg} node {n}"
                        )
                    for bp2 in list_lru_from_memcg_node_for_each_entry(
                        prog,
                        memcg,
                        n,
                        "struct xfs_buf",
                        lru.address_of_(),
                        "b_lru",
                    ):
                        if hex(bp) == hex(bp):
                            found = 1
                            break
                if found == 0:
                    if verbose is not None:
                        print(
                            f"lru for bp {hex(bp)} NOT found at mencg idx {memcg}"
                        )
                    errors = errors + 1
                else:
                    if verbose is not None:
                        print(
                            f"lru for bp {hex(bp)} FOUND at mencg idx {memcg}"
                        )
            print(f"errors {errors} in {d_cnt} bps")
