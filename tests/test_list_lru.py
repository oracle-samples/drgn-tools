# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from typing import Optional
from typing import Union

from drgn import IntegerLike
from drgn import Object
from drgn import Path
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.fs import for_each_mount
from drgn.helpers.linux.fs import mount_dst
from drgn.helpers.linux.fs import mount_fstype

from drgn_tools.list_lru import list_lru_for_each_entry
from drgn_tools.list_lru import list_lru_from_memcg_node_for_each_entry
from drgn_tools.list_lru import slab_object_to_memcgidx
from drgn_tools.list_lru import slab_object_to_nodeid


def test_list_lru(
    prog: Program,
    *,
    dst: Optional[Path] = None,
    fstype: Optional[Union[str, bytes]] = None,
    verbose: Optional[IntegerLike] = None,
    verify: Optional[IntegerLike] = None,
    maxitems: Optional[IntegerLike] = None,
) -> None:
    """
    Tests memcg aware and unaware lru by walking the lru and for every
    entry found, look up the memcg index (may be -1) and NUMA node ID.
    Compare the memcg and NUMA node id with the one returned by list_lru
    iterator. When "verify" is provided, walk the specific portion of the
    list_lru to verify this entry is found by memcg index and NUMA node ID.
    The default is to stop after the first 10,000 entries. The optional
    argument, maxitems, with a value of zero, will find all entries, else
    maxitems specifies the number of items found per filesystem.
    """
    if maxitems is None:
        items = 10000
    else:
        items = maxitems
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
        # iterate through the dentry lru, find and verify the memcg index and
        # NUMA nodeid. If verify is specified the lookup the entry.
        print(
            f"memcg aware test on {mnt_dst} dentry lru at {hex(lru.address_of_())}"
        )
        for nid, mcgid, dentry in list_lru_for_each_entry(
            "struct dentry", lru.address_of_(), "d_lru"
        ):
            d_cnt = d_cnt + 1
            if (items != 0) and (d_cnt >= items):
                # limit the items searched unless maxitems was 0
                break
            memcg = slab_object_to_memcgidx(dentry)
            n = slab_object_to_nodeid(dentry)
            if (memcg == -1) or (mcgid != memcg) or (n != nid):
                raise RuntimeError("memcg/nodeid differ for dentry")
            else:
                if verify is not None:
                    # look for the entry in the calculated NUMA node and memcg
                    found = 0
                    if verbose is not None:
                        print(
                            f"looking for dentry {hex(dentry)} in memcg {memcg.value_()} node {n.value_()}"
                        )

                    for dentry2 in list_lru_from_memcg_node_for_each_entry(
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
                        raise RuntimeError("dentry not found")
                    else:
                        if verbose is not None:
                            print(
                                f"lru for dentry {hex(dentry)} FOUND at memcg idx {memcg.value_()} nodeid {n.value_()}"
                            )
        print(f"{d_cnt} dentrys found successfully")
        if mnt_fstype == "xfs":
            print(
                f"memcg unaware test on {mnt_dst} xfs_buf lru at {hex(lru.address_of_())}"
            )
            # xfs_buf items have a memcg unaware lru
            mp = Object(prog, "struct xfs_mount *", sb.s_fs_info)
            lru = mp.m_ddev_targp.bt_lru
            d_cnt = 0
            # iterate through the xfs_buf lru, memcg index will be -1
            for nid, mcgid, bp in list_lru_for_each_entry(
                "struct xfs_buf", lru.address_of_(), "b_lru"
            ):
                d_cnt = d_cnt + 1
                if (items != 0) and (d_cnt >= items):
                    # limit the items searched unless maxitems was 0
                    break
                memcg = slab_object_to_memcgidx(bp)
                if memcg == -1:
                    memcg = 0
                n = slab_object_to_nodeid(bp)
                if (memcg == -1) or (mcgid != memcg) or (n != nid):
                    if verbose is not None:
                        raise RuntimeError("memcg/nodeid mismatch on xfs_buf")
                else:
                    if verify is not None:
                        # look for the entry in the calculated NUMA node and memcg
                        found = 0
                        if verbose is not None:
                            print(
                                f"looking for xfs_buf {hex(bp)} in memcg {memcg} node {n.value_()}"
                            )
                        for bp2 in list_lru_from_memcg_node_for_each_entry(
                            memcg,
                            n,
                            "struct xfs_buf",
                            lru.address_of_(),
                            "b_lru",
                        ):
                            if hex(bp) == hex(bp2):
                                found = 1
                                break

                        if found == 0:
                            raise RuntimeError("xfs_buf not found")
                        else:
                            if verbose is not None:
                                print(
                                    f"lru for xfs_buf {hex(bp)} FOUND at memcg idx {memcg} nodeid {n.value_()}"
                                )
            print(f"{d_cnt} xfs_bufs found")
