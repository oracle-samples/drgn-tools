# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for sysctl.
"""
from stat import S_ISDIR
from stat import S_ISLNK
from types import MappingProxyType
from typing import Any
from typing import Dict
from typing import Iterator
from typing import Tuple
from typing import Union

from drgn import container_of
from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each


def get_sysctl_table(prog: Program) -> MappingProxyType:
    """
    Get the sysctl table.

    :returns: sysctl table as a read-only dictionary, where keys are
      procnames and values are their data
    """

    cache = prog.cache.get("drgn_tools", {})
    if "sysctl_table" not in cache:
        sysctl_table: Dict[str, str] = {}
        root_dir = prog["sysctl_table_root"].default_set.dir
        __process_dir(prog, root_dir, sysctl_table)
        for key, value in sysctl_table.items():
            sysctl_table[key] = get_data_entry(prog, value)
        cache["sysctl_table"] = MappingProxyType(sysctl_table)

    return cache["sysctl_table"]


def print_sysctl_table(prog: Program) -> None:
    """
    Print the sysctl table.

    :param sysctl_table: a cached dictionary
    """

    sysctl_table = get_sysctl_table(prog)
    for key, value in sysctl_table.items():
        print("{} = {}".format(key, value))


def look_up_sysctl_entry(prog: Program, procname: str) -> Any:
    """
    look up sysctl entry of given procname

    :param procname: procname to look up
    :returns: The data associated with the procname
    """

    sysctl_table = get_sysctl_table(prog)
    return sysctl_table[procname]


def __process_dir(
    prog: Program,
    dir: Object,
    sysctl_table: Dict[str, Object],
    prefix: str = "",
) -> None:
    """Process and retrieve the ctl_dir"""

    for ct, header in __for_all_sysdir_entries(dir):
        if S_ISLNK(int(ct.mode)):
            newdir = __process_symlink(prog, header, ct)
            if newdir:
                __process_dir(prog, newdir, sysctl_table, "net.")
        f_name = prefix + ct.procname.string_().decode()
        if S_ISDIR(int(ct.mode)):
            newdir = container_of(header, "struct ctl_dir", "header")
            __process_dir(prog, newdir, sysctl_table, f_name + ".")

        else:
            sysctl_table[f_name] = ct


def __for_all_sysdir_entries(dir: Object) -> Iterator[Tuple[Object, Object]]:
    """Traverse ctl_node tree"""

    for rb_node in rbtree_inorder_for_each(dir.root):
        ctl_node = container_of(rb_node, "struct ctl_node", "node")
        if ctl_node.header.unregistering:
            continue
        head = ctl_node.header
        node_offset = ctl_node - head.node
        ct = head.ctl_table[node_offset]
        yield ct, head


def __process_symlink(
    prog: Program, head: Object, ct: Object
) -> Union[Object, None]:
    """Process a symlink"""

    root = Object(prog, "struct ctl_table_root", address=ct.data.value_())
    lookup = root.lookup
    if prog.symbol(lookup).name == "net_ctl_header_lookup":
        ctset = prog["init_task"].nsproxy.net_ns.sysctls
    else:
        return None
    return __xlate_dir(ctset, head.parent)


def __xlate_dir(ctset: Object, ctdir: Object) -> Union[Object, None]:
    """Process a xlate_dir"""

    if not ctdir.header.parent:
        return ctset.dir
    parent = __xlate_dir(ctset, ctdir.header.parent)
    if parent is None or parent.address_of_().value_() > (1 << 64) - 4095:
        return None

    procname = ctdir.header.ctl_table[0].procname.string_().decode()
    entry, head = __find_entry(parent, procname)
    if entry is None or not S_ISDIR(int(entry.mode)):
        return None

    return container_of(head, "struct ctl_dir", "header")


def __find_entry(
    parent_dir: Object, name: str
) -> Union[Tuple[Object, Object], Tuple[None, None]]:
    """Find the entry of a ctl_tir"""

    for entry, head in __for_all_sysdir_entries(parent_dir):
        if entry.procname.string_().decode() == name:
            return (entry, head)
    return (None, None)


def get_data_entry(prog: Program, ct: Object) -> Any:
    """
    Extract the data of a ct a control table entry value given procname.

    :param ct: ``struct ctl_table``
    :returns: the ctl_table data
    """

    out = []
    maxlen = int(ct.maxlen)
    phandler = ct.proc_handler
    phandler_name = ""
    try:
        phandler_name = prog.symbol(phandler).name
    except LookupError:
        pass

    # for the cases where the data encoded is a text string
    if phandler_name == "proc_dostring":
        return __decode_sysctl_string(prog.read(ct.data, maxlen))
    if phandler_name == "cdrom_sysctl_info":
        idstr = __decode_sysctl_string(prog.read(ct.data, maxlen))
        for s in idstr.split("\n"):
            out.append("    " + s)
        out[0] = out[0].strip()
        return "\n".join(out)
    read_val = None
    data = ct.data
    # for the cases where the data is a 'long' type we use read_u64
    if phandler_name in (
        "proc_doulongvec_minmax",
        "dirty_background_bytes_handler",
        "dirty_bytes_handler",
        "proc_ipc_doulongvec_minmax",
        "ipv4_tcp_mem",
    ):
        sz = maxlen // 8
        read_val = prog.read_u64
        interval = 8
    # for the cases where the data is an 'int' type we use read_u32
    elif maxlen != 0:
        sz = maxlen // 4
        read_val = prog.read_u32
        interval = 4
    else:
        return "(?)"
    if sz <= 1:
        try:
            iv = read_val(data)
        except FaultError:
            return "(?)"
        if phandler_name.find("jiffies") >= 0:
            # convert from jiffies to ms
            iv = iv // 1000
        return iv
    for _ in range(sz):
        try:
            iv = read_val(data)
        except FaultError:
            return "(?)"
        if phandler_name.find("jiffies") >= 0:
            # convert from jiffies to ms
            iv = iv // 1000
        out.append(iv)
        data += interval
    # print first 5 elements
    if len(out) > 5:
        out = out[:5] + ["... %d more elements" % (len(out) - 5)]
    return out


def __decode_sysctl_string(data: bytes) -> str:
    """Decode bytes to readable string"""

    bytes_before_nul = data.split(b"\x00", 1)[0]
    return bytes_before_nul.decode("ascii", errors="backslashreplace")
