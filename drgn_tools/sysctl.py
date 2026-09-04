# Copyright (c) 2023, 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for fetching sysctl values and displaying them

The sysctl system of the kernel is surprisingly versatile. It allows sysctl
values to be allocated statically, referencing global variables, or allocated
dynamically, for cases like per-net-device settings. What's more, since procfs
can be mounted into other namespaces, it provides a mechanism for providing
different sets of sysctls depending on the currently active namespaces. The
result is a powerful but somewhat complicated system for looking up or
enumerating sysctl keys.

Once the actual sysctl entries are found, interpreting them is another hurdle.
While the idea of sysctl entries is that they simply point at a variable, in
practice many cases need their own handlers for custom logic. Some sysctl
handlers scale or modify the value stored in the kernel; others derive their
value dynamically and don't store them directly.

This module provides helpers for enumerating and looking up sysctl helpers, in
the context of any task. Once found, it provides helpers that format the sysctl
values in the same manner that the sysctl userspace utility does, as well as a
Corelens module which imitates that utility.

It is not expected that *every* sysctl key can be displayed. While we could
implement custom handlers for keys that have bespoke logic, that's probably
going to be fragile. We draw the line as follows:
- Standard proc handlers: work great!
- Custom proc handlers that do custom logic on top of proc handlers: we aim to
  support them all. However, we need to maintain a list of these handlers.
- Proc handlers that perform totally custom logic and do not store anything in a
  kernel variable: NOT supported.

Finally, if you're looking at this module in order to get a sysctl value as an
integer, please *look elsewhere*. Chances are the sysctl variable is also a
standard global variable that can be looked up directly. This module provides
string formatting, but no way to access the underlying programatic values.
"""
import argparse
import uuid
from stat import S_ISDIR
from stat import S_ISLNK
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterator
from typing import NamedTuple
from typing import Optional
from typing import Tuple

from drgn import Architecture
from drgn import cast
from drgn import container_of
from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn import sizeof
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.bitops import for_each_set_bit
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.rbtree import rb_find
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry

from drgn_tools.corelens import CorelensModule
from drgn_tools.task import task_active_pid_ns
from drgn_tools.util import align
from drgn_tools.util import int_list_to_range_list
from drgn_tools.util import program_cached_item
from drgn_tools.util import type_has_member


def _sysctl_cmp(key: bytes, ctl_node: Object) -> int:
    """
    Comparator for rb_find()
    :param key: string to find
    :param ctl_node: object of type ``struct ctl_node *``
    """
    head = ctl_node.header
    entry = head.ctl_table[ctl_node - head.node]
    name = entry.procname.string_()
    if key < name:
        return -1
    else:
        return int(key > name)


def _find_entry(dir: Object, name: bytes) -> Object:
    """
    Lookup an entry name in a sysctl directory
    :param dir: object of type ``struct ctl_dir *``
    :param name: entry name to find
    :returns: object of type ``struct ctl_node *``
    """
    return rb_find(
        "struct ctl_node", dir.root.address_of_(), "node", name, _sysctl_cmp
    )


def _lookup_header_set(root: Object, task: Object) -> Object:
    """
    Resolve the sysctl set for a given root.

    Rough equivalent of the kernel's lookup_header_set().

    In the kernel, lookup_header_set() actually calls the root->lookup function
    pointer, which we obviously cannot do. What's more, these lookup functions
    are almost all static functions named ``set_lookup()``, so we cannot tell
    them apart by their symbol name. However, since there are actually very few
    possible roots, we can just check each one.

    :param root: the ``struct ctl_table_root *``
    :param task: the context (a ``struct task_struct *``) to use for namespaces
    :returns: a ``struct ctl_table_set *``
    """
    prog = root.prog_
    candidates = [
        task.nsproxy.net_ns.sysctls,
    ]
    if hasattr(task.cred.user_ns, "set"):
        candidates.append(task.cred.user_ns.set)
    if hasattr(task.nsproxy.ipc_ns, "ipc_set"):
        candidates.append(task.nsproxy.ipc_ns.ipc_set)
    if hasattr(task.nsproxy.ipc_ns, "mq_set"):
        candidates.append(task.nsproxy.ipc_ns.mq_set)
    if type_has_member(prog, "struct pid_namespace", "set"):
        candidates.append(task_active_pid_ns(task).set)
    for set_ in candidates:
        if set_.dir.header.root == root:
            return set_.address_of_()

    if not root.lookup:
        return root.default_set.address_of_()

    try:
        lookup_fn = prog.symbol(root.lookup).name
    except LookupError:
        lookup_fn = hex(root.lookup)
    raise NotImplementedError(
        f"unknown namespaced sysctl root 0x{root.value_():x}"
        f" (lookup_fn: {lookup_fn})"
    )


def _xlate_dir(set_: Object, dir_: Object) -> Object:
    """
    Rough equivalent of the kernel's xlate_dir()
    :param set_: the ``struct ctl_table_set *`` to lookup the directory within
    :param dir_: the ``struct ctl_dir *`` we're looking up
    :returns: a ``struct ctl_dir *`` within the set
    """
    if not dir_.header.parent:
        return set_.dir.address_of_()
    parent = _xlate_dir(set_, dir_.header.parent)
    name = dir_.header.ctl_table[0].procname.string_()
    node = _find_entry(parent, name)
    assert node
    entry = node.header.ctl_table[node - node.header.node].address_of_()
    if not S_ISDIR(entry.mode.value_()):
        raise ValueError("While resolving sysctl symlink, got non-dir parent")
    return container_of(node.header, "struct ctl_dir", "header")


def _follow_link(
    entry: Object, header: Object, name: bytes, context: Object
) -> Tuple[Object, Object]:
    """
    Follow a sysctl symlink into the specific namespace (given a task context)

    Sysctl entries that vary based on a namespace (network, user, ipc) are
    represented as "symlink" entries. Their data points to a ``struct
    ctl_table_root *``, and this root contains different "sets" of entries.
    We first lookup the appropriate set of tree entries for this task's context,
    then translate the current directory into its equivalent within that set,
    and then lookup the link name in the current directory. The result is a new
    entry/header which will be either a sysctl entry or a directory.

    :param entry: ``struct ctl_table *`` entry associated with a symlink
    :param header: ``struct ctl_table_header *`` associated with its parent
    :param name: the procname of the sysctl entry
    :param context: a ``struct task_struct *`` from which to follow the context
    :returns: the target (entry, header) tuple within the context's namespace
    """
    root = cast("struct ctl_table_root *", entry.data)
    set = _lookup_header_set(root, context)
    dir_ = _xlate_dir(set, header.parent)
    node = _find_entry(dir_, name)
    assert node
    new_header = node.header
    new_entry = new_header.ctl_table[node - new_header.node].address_of_()
    return new_entry, new_header


class SysctlEntry(NamedTuple):
    kind: str
    """The kind of this entry ('dir', 'ctl', or 'lnk')"""
    name: str
    """The name of this entry (not the full path, just this component)"""
    value: Object
    """
    Object representing the entry:
    - For links: a ``struct ctl_node *``
    - For directories: a ``struct ctl_dir *``
    - For ctls: a ``struct ctl_table *``
    """


def sysctl_dir_for_each(
    dir: Object,
    follow_symlinks: bool = True,
    context: Optional[Object] = None,
) -> Iterator[SysctlEntry]:
    """
    Yield each child of a sysctl directory

    :param dir: object of type ``struct ctl_dir *``
    :param follow_symlinks: if True, then we resolve symlinks in a specific task
      context, and so we do not yield any symlink entries
    :param context: a ``struct task_struct *`` to use as the context for
      resolving symlinks (ignored when not following symlinks)
    :yields: each sysctl entry in the directory
    """
    if context is None:
        context = dir.prog_["init_task"].address_of_()

    for ctl_node in rbtree_inorder_for_each_entry(
        "struct ctl_node", dir.root.address_of_(), "node"
    ):
        if ctl_node.header.unregistering:
            continue
        header = ctl_node.header
        entry = header.ctl_table[ctl_node - header.node]
        name = entry.procname.string_()

        if S_ISLNK(entry.mode.value_()):
            if follow_symlinks:
                entry, header = _follow_link(entry, header, name, context)
            else:
                yield SysctlEntry("lnk", name, ctl_node)

        if S_ISDIR(entry.mode.value_()):
            yield SysctlEntry(
                "dir", name, container_of(header, "struct ctl_dir", "header")
            )
        else:
            yield SysctlEntry("ctl", name, entry)


def for_each_sysctl_in_dir(
    dir: Object,
    dir_path: str,
    context: Object,
) -> Iterator[Tuple[str, Object]]:
    for entry in sysctl_dir_for_each(dir, context=context):
        name_str = escape_ascii_string(entry.name)
        if entry.kind == "dir":
            yield from for_each_sysctl_in_dir(
                entry.value, f"{dir_path}{name_str}.", context=context
            )
        else:
            yield f"{dir_path}{name_str}", entry.value


def for_each_sysctl(
    prog: Program,
    context: Optional[Object] = None,
) -> Iterator[Tuple[str, Object]]:
    root_dir = prog["sysctl_table_root"].default_set.dir.address_of_()
    return for_each_sysctl_in_dir(root_dir, "", context)


def find_sysctl(
    prog: Program,
    name: str,
    context: Optional[Object] = None,
) -> SysctlEntry:
    """
    Lookup a sysctl by name
    """
    dir_ = prog["sysctl_table_root"].default_set.dir.address_of_()
    components = [s for s in name.split(".")]

    if context is None:
        context = prog["init_task"].address_of_()

    for i, component in enumerate(components):
        comp_bytes = component.encode()
        ctl_node = _find_entry(dir_, comp_bytes)
        if not ctl_node:
            parent = ".".join(components[:i])
            raise LookupError(
                f"Cannot find '{component}' in sysctl dir '{parent}'"
            )

        header = ctl_node.header
        entry = header.ctl_table[ctl_node - header.node]
        if S_ISLNK(entry.mode.value_()):
            entry, header = _follow_link(entry, header, comp_bytes, context)

        is_dir = S_ISDIR(entry.mode.value_())
        is_last = i + 1 == len(components)
        if not (is_dir or is_last):
            current = ".".join(components[: i + 1])
            remainder = ".".join(components[i + 1 :])
            raise ValueError(
                f"Sysctl entry '{current}' is a file, cannot lookup '{remainder}' within it"
            )
        elif is_dir:
            dir_ = container_of(header, "struct ctl_dir", "header")

    if is_dir:
        return SysctlEntry("dir", name, dir_)
    else:
        return SysctlEntry("ctl", name, entry)


INTVEC_HANDLERS = (
    "addrconf_sysctl_disable",
    "addrconf_sysctl_disable_policy",
    "addrconf_sysctl_forward",
    "addrconf_sysctl_ignore_routes_with_linkdown",
    "addrconf_sysctl_mtu",
    "addrconf_sysctl_proxy_ndp",
    "armv8pmu_proc_user_access_handler",
    "bpf_unpriv_handler",
    "cdrom_sysctl_handler",
    "devinet_conf_proc",
    "devinet_sysctl_forward",
    "dirty_background_ratio_handler",
    "dirty_ratio_handler",
    "fscache_max_active_sysctl",
    "ftrace_enable_sysctl",
    "ipv4_doint_and_flush",
    "ipv4_privileged_ports",
    "kexec_limit_handler",
    "kswapd_threads_sysctl_handler",
    "lowmem_reserve_ratio_sysctl_handler",
    "mac_hid_toggle_emumouse",
    "min_free_kbytes_sysctl_handler",
    "neigh_proc_dointvec_zero_intmax",
    "overcommit_policy_handler",
    "overcommit_ratio_handler",
    "percpu_pagelist_high_fraction_sysctl_handler",
    "percpu_pagelist_fraction_sysctl_handler",
    "perf_cpu_time_max_percent_handler",
    "perf_event_max_sample_rate_handler",
    "perf_event_max_stack_handler",
    "perf_proc_update_handler",
    "pid_mfd_noexec_dointvec_minmax",
    "proc_dentry_fs_klimit",
    "proc_do_entropy",
    "proc_do_dev_weight",
    "proc_do_rointvec",
    "proc_do_skb_defer_max",
    "proc_dointvec",
    "proc_dointvec_minmax",
    "proc_dointvec_minmax_bpf_enable",
    "proc_dointvec_minmax_bpf_restricted",
    "proc_dointvec_minmax_coredump",
    "proc_dointvec_minmax_sysadmin",
    "proc_dointvec_minmax_warn_RT_change",
    "proc_kprobes_optimization_handler",
    "proc_nmi_watchdog",
    "proc_soft_watchdog",
    "proc_tfo_blackhole_detect_timeout",
    "proc_udp_early_demux",
    "proc_tcp_early_demux",
    "proc_watchdog",
    "proc_watchdog_thresh",
    "sched_proc_update_handler",
    "sched_rr_handler",
    "sched_rt_handler",
    "stack_trace_sysctl",
    "sysctl_latencytop",
    "sysctl_min_slab_ratio_sysctl_handler",
    "sysctl_min_unmapped_ratio_sysctl_handler",
    "sysctl_sched_uclamp_handler",
    "sysctl_vm_numa_stat_handler",
    "tracepoint_printk_sysctl",
    "watermark_scale_factor_sysctl_handler",
    "watermark_boost_factor_sysctl_handler",
    "xfs_deprecated_dointvec_minmax",
    "xfs_panic_mask_proc_handler",
    "yama_dointvec_minmax",
)

INTVEC_SECONDS_JIFFIES_HANDLERS = (
    "laptop_mode_handler",
    "neigh_proc_dointvec_jiffies",
    "proc_dointvec_jiffies",
)

INTVEC_MILLISECONDS_JIFFIES_HANDLERS = (
    "neigh_proc_dointvec_ms_jiffies",
    "neigh_proc_dointvec_ms_jiffies_positive",
    "proc_dointvec_ms_jiffies",
    "proc_dointvec_ms_jiffies_minmax",
)

INTVEC_USER_HZ_JIFFIES_HANDLERS = (
    "neigh_proc_dointvec_userhz_jiffies",
    "proc_dointvec_userhz_jiffies",
)

UINTVEC_HANDLERS = (
    "addrconf_sysctl_force_forwarding",
    "compaction_proactiveness_sysctl_handler",
    "dirty_writeback_centisecs_handler",
    "dirtytime_interval_handler",
    "flow_limit_table_len_sysctl",
    "nf_conntrack_hash_sysctl",
    "proc_blackhole_detect_timeout",
    "proc_dopipe_max_size",
    "proc_douintvec",
    "proc_douintvec_minmax",
    "proc_fib_multipath_hash_fields",
    "proc_rt6_multipath_hash_fields",
    "sched_itmt_update_handler",
    "sysctl_compaction_proactiveness_handler",
    "timer_migration_handler",
)

U8VEC_HANDLERS = (
    "ipv4_fwd_update_priority",
    "proc_dou8vec_minmax",
    "proc_fib_multipath_hash_policy",
    "proc_pm_type",
)

ULONGVEC_HANDLERS = (
    "dirty_background_bytes_handler",
    "dirty_bytes_handler",
    "mmap_min_addr_handler",
    "overcommit_kbytes_handler",
    "sysctl_panic_print_handler",
    "proc_dohung_task_timeout_secs",
    "proc_dolongvec_minmax_bpf_restricted",
    "proc_doulongvec_minmax",
    "proc_dqstats",
    "proc_nr_dentry",
    "proc_nr_files",
    "proc_nr_inodes",
)

STRING_HANDLERS = (
    "devkmsg_sysctl_set_loglvl",
    "numa_zonelist_order_handler",
    "proc_do_uts_string",
    "proc_dostring",
    "proc_dostring_coredump",
    "proc_neg_dentry_pc",
    "proc_path_manager",
    "proc_scheduler",
)

STATIC_KEY_HANDLERS = (
    "bpf_stats_handler",
    "proc_do_static_key",
    "proc_mem_profiling_handler",
)

BITMAP_HANDLERS = ("proc_do_large_bitmap", "proc_watchdog_cpumask")

INTVEC_IPC_HANDLERS = (
    # NOTE: These handlers are for values specific to the IPC namespace.
    # Prior to v5.19 commit 1f5c135ee509e ("ipc: Store ipc sysctls in the ipc
    # namespace"), their sysctl tables point at init_ipc_ns, and the handler
    # adjusts the target based on the context's IP namespace. We store them
    # separately so that we can detect the older kernel and activate logic for
    # "rebasing" the ct.data pointer in the handler.
    "proc_ipc_dointvec",
    "proc_ipc_dointvec_minmax_orphans",
    "proc_ipc_sem_dointvec",
    "proc_ipc_dointvec_minmax",
    # Same as above, but see v5.19 commit dc55e35f9e810 ("ipc: Store mqueue
    # sysctls in the ipc namespace"). These were in the same series and can be
    # treated together.
    "proc_mq_dointvec",
    "proc_mq_dointvec_minmax",
)

ULONGVEC_IPC_HANDLERS = ("proc_ipc_doulongvec_minmax",)

# These handlers are expected to be a single integer and will choose based on
# the sysctl maxlen:
# 4 => int
# 1 => u8
# This mirrors a pattern seen in several networking sysctls which started out as
# ints, but were migrated to u8. Most simply used the global sysctl handler for
# the new type, but custom handlers need custom logic.
INT_SIZE_HANDLERS = (
    # v5.13: 1c69dedc8fa7c ("ipv4: convert ip_forward_update_priority sysctl to
    # u8")
    "ipv4_fwd_update_priority",
    # v5.13: a6175633a2af0 ("ipv6: convert elligible sysctls to u8")
    "proc_rt6_multipath_hash_policy",
    # v5.13: be205fe6ec4ff ("ipv4: convert fib_multipath_{use_neigh|hash_policy}
    # sysctls to u8")
    "proc_fib_multipath_hash_policy",
)


@program_cached_item
def _get_hz(prog: Program) -> int:
    # Since v4.19 commit d4ce58082f206 ("net-tcp:
    # /proc/sys/net/ipv4/tcp_probe_interval is a u32 not int"), the variable
    # u32_max_div_HZ has existed - it's a read-only value used as the limit for
    # some sysctls. We can determine hz by comparing its value against the
    # values for the common HZ configurations.
    common_hz = (1000, 250, 100, 500)
    try:
        u32_max_div_HZ = int(prog["u32_max_div_HZ"])
    except LookupError:
        u32_max_div_HZ = 0
    for candidate_hz in common_hz:
        if ((1 << 32) - 1) // candidate_hz == u32_max_div_HZ:
            return candidate_hz

    # For older kernels, we'll do the most obvious thing: hard-code it based on
    # UEK / RHCK configuration.
    uts_release = prog["UTS_RELEASE"].string_().decode()
    if "uek" in uts_release:
        return 1000 if prog.platform.arch == Architecture.X86_64 else 250
    if ".el" in uts_release and prog.platform.arch == Architecture.X86_64:
        return 1000
    raise ValueError(f"CONFIG_HZ is unknown for kernel {uts_release}")


@program_cached_item
def _get_user_hz(prog: Program) -> int:
    if prog.platform.arch == Architecture.X86_64:
        return 100
    try:
        tick_usec = int(prog["tick_usec"])
    except LookupError:
        # Since v6.13 commit 68f66f97c5689 ("ntp: Introduce struct ntp_data")
        try:
            tick_usec = prog["tk_ntp_data"].tick_usec
        except AttributeError:
            # Since v6.16 commit 8515714b0f88a ("ntp: Add support for auxiliary
            # timekeepers")
            tick_usec = prog["tk_ntp_data"][0].tick_usec
    return round(1_000_000 / tick_usec)


@program_cached_item
def _get_skb_truesize(prog: Program) -> int:
    return (
        1514
        + align(sizeof(prog.type("struct sk_buff")), 64)
        + align(sizeof(prog.type("struct skb_shared_info")), 64)
    )


class _SysctlUnknownHandler(Exception):
    pass


def _sysctl_make_intvec(
    prog: Program,
    kind: str,
    scale: Optional[Tuple[int, int]] = None,
    rebase_ipc_ns: bool = False,
) -> Callable[[Object, Optional[Object]], str]:
    # Lookup the type once for efficiency
    tp = prog.type(kind)
    ptr = prog.pointer_type(tp)

    def _get_intvec(ct: Object, ctx: Optional[Object]) -> str:
        array_len = int(ct.maxlen) // sizeof(ct.prog_.type(kind))
        data = ct.data

        # For pre-v5.19 kernels, see note in INTVEC_IPC_HANDLERS
        if rebase_ipc_ns and ctx is not None:
            new_addr = (
                ctx.nsproxy.ipc_ns.value_()
                + data.value_()
                - prog["init_ipc_ns"].address_
            )
            data = Object(prog, "void *", value=new_addr)
        if array_len == 1:
            value = cast(ptr, data)[0]
            if scale:
                value = value * scale[0] / scale[1]
            return value.format_(type_name=False)
        else:
            arrtp = prog.pointer_type(prog.array_type(tp, array_len))
            array = cast(arrtp, data)[0].value_()
            if scale:
                array = [value * scale[0] / scale[1] for value in array]
            return "\t".join(map(str, array))

    return _get_intvec


def _sysctl_int_size(ct: Object, ctx: Optional[Object]) -> str:
    size = int(ct.maxlen)
    if size == 1:
        val = cast("u8 *", ct.data)[0]
    elif size == 4:
        val = cast("int *", ct.data)[0]
    else:
        raise ValueError(f"unexpected int size {size}")
    return val.format_(type_name=False)


def _sysctl_string(ct: Object, ctx: Optional[Object]) -> str:
    # avoid reading too far if maxlen is bogus
    readlen = min(4096, ct.maxlen)
    data = ct.prog_.read(ct.data, readlen)
    nulterm = data.split(b"\0")[0]
    # escape_ascii_string will convert newline to "\n" which we don't really
    # want here
    lines = nulterm.split(b"\n")
    return "\n".join(escape_ascii_string(line) for line in lines)


def _sysctl_bool(ct: Object, ctx: Optional[Object]) -> str:
    value = cast("bool *", ct.data)
    return str(int(bool(value[0])))


def _sysctl_static_key(ct: Object, ctx: Optional[Object]) -> str:
    key = cast("struct static_key *", ct.data)
    return str(int(bool(key.enabled.counter)))


def _sysctl_bitmap(ct: Object, ctx: Optional[Object]) -> str:
    bitmap = cast("unsigned long **", ct.data)
    return int_list_to_range_list(for_each_set_bit(bitmap[0], ct.maxlen))


def _sysctl_uint_hex(ct: Object, ctx: Optional[Object]) -> str:
    value = int(cast("unsigned int *", ct.data)[0])
    return f"0x{value:04x}"


def _sysctl_uuid(ct: Object, ctx: Optional[Object]) -> str:
    if not ct.data:
        return "(null)"
    b = cast("unsigned char(*)[16]", ct.data)[0].to_bytes_()
    return str(uuid.UUID(bytes=b))


def _sysctl_sys_info(ct: Object, ctx: Optional[Object]) -> str:
    val = int(cast("unsigned long *", ct.data)[0])
    return ",".join(
        escape_ascii_string(name.string_())
        for i, name in enumerate(ct.prog_["si_names"])
        if val & (1 << i)
    )


def _sysctl_hung_task_detect_count(ct: Object, ctx: Optional[Object]) -> str:
    # Yes, this is basically a hard-coded handler for one sysctl. But it seems
    # to be a possibly very useful one for debugging kernel hung task issues,
    # thus it is included.
    prog = ct.prog_
    return prog["sysctl_hung_task_detect_count"].counter.format_(
        type_name=False
    )


def _sysctl_delegate(
    prog: Program,
    name_to_handler: Dict[bytes, Callable[[Object, Optional[Object]], str]],
) -> Callable[[Object, Optional[Object]], str]:
    def inner(ct: Object, ctx: Optional[Object]) -> str:
        procname = ct.procname.string_()
        if procname in name_to_handler:
            return name_to_handler[procname](ct, ctx)
        raise _SysctlUnknownHandler()

    return inner


@program_cached_item
def _sysctl_get_handlers(
    prog: Program,
) -> Dict[str, Callable[[Object, Optional[Object]], str]]:
    handlers: Dict[str, Callable[[Object, Optional[Object]], str]] = {}
    handlers["proc_dobool"] = _sysctl_bool
    handlers["proc_dodebug"] = _sysctl_uint_hex
    handlers["proc_do_uuid"] = _sysctl_uuid
    handlers["sysctl_sys_info_handler"] = _sysctl_sys_info
    handlers["sysctl_sys_info_handler"] = _sysctl_sys_info
    handlers["proc_dohung_task_detect_count"] = _sysctl_hung_task_detect_count

    # Scaled by SKB_TRUESIZE(ETH_FRAME_LEN):
    handlers["neigh_proc_dointvec_unres_qlen"] = _sysctl_make_intvec(
        prog, "int", (1, _get_skb_truesize(prog))
    )

    intvec_handler = _sysctl_make_intvec(prog, "int")
    for handler in INTVEC_HANDLERS:
        handlers[handler] = intvec_handler

    intvec_seconds = _sysctl_make_intvec(prog, "int", (1, _get_hz(prog)))
    for handler in INTVEC_SECONDS_JIFFIES_HANDLERS:
        handlers[handler] = intvec_seconds

    intvec_ms = _sysctl_make_intvec(prog, "int", (1000, _get_hz(prog)))
    for handler in INTVEC_MILLISECONDS_JIFFIES_HANDLERS:
        handlers[handler] = intvec_ms

    intvec_userhz = _sysctl_make_intvec(
        prog, "int", (_get_user_hz(prog), _get_hz(prog))
    )
    for handler in INTVEC_USER_HZ_JIFFIES_HANDLERS:
        handlers[handler] = intvec_userhz

    uintvec_handler = _sysctl_make_intvec(prog, "unsigned int")
    for handler in UINTVEC_HANDLERS:
        handlers[handler] = uintvec_handler

    ulongvec_handler = _sysctl_make_intvec(prog, "unsigned long")
    for handler in ULONGVEC_HANDLERS:
        handlers[handler] = ulongvec_handler

    u8vec_handler = _sysctl_make_intvec(prog, "u8")
    for handler in U8VEC_HANDLERS:
        handlers[handler] = u8vec_handler

    for handler in STRING_HANDLERS:
        handlers[handler] = _sysctl_string

    for handler in STATIC_KEY_HANDLERS:
        handlers[handler] = _sysctl_static_key

    for handler in BITMAP_HANDLERS:
        handlers[handler] = _sysctl_bitmap

    for handler in INT_SIZE_HANDLERS:
        handlers[handler] = _sysctl_int_size

    # For pre-v5.19 kernels, see note in INTVEC_IPC_HANDLERS
    if type_has_member(prog, "struct ipc_namespace", "ipc_sysctls"):
        intvec_ipc_handler = intvec_handler
        ulongvec_ipc_handler = ulongvec_handler
    else:
        intvec_ipc_handler = _sysctl_make_intvec(
            prog, "int", rebase_ipc_ns=True
        )
        ulongvec_ipc_handler = _sysctl_make_intvec(
            prog, "unsigned long", rebase_ipc_ns=True
        )
    for handler in INTVEC_IPC_HANDLERS:
        handlers[handler] = intvec_ipc_handler
    for handler in ULONGVEC_IPC_HANDLERS:
        handlers[handler] = ulongvec_ipc_handler

    handlers["ndisc_ifinfo_sysctl_change"] = _sysctl_delegate(
        prog,
        {
            b"retrans_time": intvec_handler,
            b"base_reachable_time": intvec_seconds,
            b"retrans_time_ms": intvec_ms,
            b"base_reachable_time_ms": intvec_ms,
        },
    )

    handlers["neigh_proc_base_reachable_time"] = _sysctl_delegate(
        prog,
        {
            b"base_reachable_time": intvec_seconds,
            b"base_reachable_time_ms": intvec_ms,
        },
    )

    return handlers


def sysctl_data(ct: Object, ctx: Optional[Object]) -> Any:
    """
    Extract the data of a sysctl entry

    Normally, the context was already used in looking up the sysctl entry. But
    on older kernels, the same ctl entry was used to lookup the value in all
    namespaces, by rebasing the pointer, so for those systems you need to
    provide a context object.

    :param ct: ``struct ctl_table``
    :param ctx: ``struct task_struct *`` to use as the context for lookup
    :returns: the ctl_table data cast to an appropriate python type
    """
    prog = ct.prog_
    if "drgn_tools.sysctl.symbols" not in prog.cache:
        prog.cache["drgn_tools.sysctl.symbols"] = {}

    # Resolve the name of the handler. Cache the symbol lookup since this can be
    # rather expensive.
    cache = prog.cache["drgn_tools.sysctl.symbols"]
    phandler = ct.proc_handler.value_()
    if phandler in cache:
        phandler_name = cache[phandler]
    else:
        try:
            phandler_name = prog.symbol(phandler).name
        except LookupError:
            phandler_name = hex(phandler)
        cache[phandler] = phandler_name

    handlers = _sysctl_get_handlers(prog)
    if phandler_name in handlers:
        py_handler = handlers[phandler_name]
        try:
            return py_handler(ct, ctx)
        except FaultError:
            return f"FaultError (handler: {phandler_name}, using {py_handler.__name__})"
        except _SysctlUnknownHandler:
            pass  # return the unknown handler value below
    return f"? (handler: {phandler_name})"


def print_sysctl_table(
    prog: Program,
    dir: Optional[Object] = None,
    prefix: str = "",
    context: Optional[Object] = None,
) -> None:
    if not dir:
        dir = prog["sysctl_table_root"].default_set.dir.address_of_()
    if not context:
        context = prog["init_task"].address_of_()

    for name, ct in for_each_sysctl_in_dir(dir, prefix, context):
        formatted = sysctl_data(ct, context)
        print(f"{name} = {formatted}")


def get_sysctl_table(
    prog: Program, context: Optional[Object] = None
) -> Dict[str, str]:
    table = {}
    for name, ct in for_each_sysctl(prog, context):
        table[name] = sysctl_data(ct, context)
    return table


class SysCtl(CorelensModule):
    """Display sysctl entries like sysctl(8)"""

    name = "sysctl"

    default_args = [["-a"]]

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--all",
            "-a",
            action="store_true",
            help="print all sysctl values",
        )
        parser.add_argument(
            "--pid",
            "-p",
            type=int,
            help="print sysctls in the context of the given task "
            "(from init pid namespace)",
        )
        parser.add_argument(
            "variable",
            type=str,
            nargs="*",
            help="print the given sysctl(s) or sysctl directory(s)",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if args.pid:
            context = find_task(prog, args.pid)
        else:
            context = prog["init_task"].address_of_()

        if args.variable:
            for name in args.variable:
                entry = find_sysctl(prog, name, context=context)
                if entry.kind == "dir":
                    print_sysctl_table(
                        prog,
                        dir=entry.value,
                        prefix=f"{entry.name}.",
                        context=context,
                    )
                else:
                    formatted = sysctl_data(entry.value, context)
                    print(f"{name} = {formatted}")
        else:
            print_sysctl_table(prog, context=context)
