# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for diagnosing issues with dnotify, inotify, fanotify: the "fsnotify"
subsystem.
"""
import argparse
from datetime import timedelta
from typing import Dict
from typing import Iterator
from typing import Optional
from typing import Tuple

from drgn import cast
from drgn import container_of
from drgn import NULL
from drgn import Object
from drgn import Program
from drgn.helpers.common.format import decode_flags
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.fs import for_each_file
from drgn.helpers.linux.list import hlist_for_each_entry
from drgn.helpers.linux.list import list_count_nodes
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.slab import slab_object_info
from drgn.helpers.linux.wait import waitqueue_active
from drgn.helpers.linux.wait import waitqueue_for_each_entry

from drgn_tools.bt import bt
from drgn_tools.corelens import CorelensModule
from drgn_tools.dentry import dentry_path_any_mount
from drgn_tools.dentry import sb_first_mount_point
from drgn_tools.task import is_group_leader
from drgn_tools.task import task_lastrun2now
from drgn_tools.util import type_has_member

FSNOTIFY_FLAGS = {
    # Prefixed by "FS_" in the code: include/linux/fsnotify_backend.h
    # The prefix is removed for nicer printing.
    "ACCESS": 0x00000001,  # File was accessed
    "MODIFY": 0x00000002,  # File was modified
    "ATTRIB": 0x00000004,  # Metadata changed
    "CLOSE_WRITE": 0x00000008,  # Writtable file was closed
    "CLOSE_NOWRITE": 0x00000010,  # Unwrittable file closed
    "OPEN": 0x00000020,  # File was opened
    "MOVED_FROM": 0x00000040,  # File was moved from X
    "MOVED_TO": 0x00000080,  # File was moved to Y
    "CREATE": 0x00000100,  # Subfile was created
    "DELETE": 0x00000200,  # Subfile was deleted
    "DELETE_SELF": 0x00000400,  # Self was deleted
    "MOVE_SELF": 0x00000800,  # Self was moved
    "OPEN_EXEC": 0x00001000,  # File was opened for exec
    "UNMOUNT": 0x00002000,  # inode on umount fs
    "Q_OVERFLOW": 0x00004000,  # Event queued overflowed
    "ERROR": 0x00008000,  # Filesystem Error (fanotify)
    "OPEN_PERM": 0x00010000,  # open event in an permission hook
    "ACCESS_PERM": 0x00020000,  # access event in a permissions hook
    "OPEN_EXEC_PERM": 0x00040000,  # open/exec event in a permission hook
    "EVENT_ON_CHILD": 0x08000000,
    "RENAME": 0x10000000,  # File was renamed
    "DN_MULTISHOT": 0x20000000,  # dnotify multishot
    "ISDIR": 0x40000000,  # event occurred against dir
}


def fsnotify_group_for_each_mark(group: Object) -> Iterator[Object]:
    """
    Iterate over all fsnotify marks for a given group.
    :param group: ``struct fsnotify_group *``
    :returns: iterator of ``struct fsnotify_mark *``
    """
    return list_for_each_entry(
        "struct fsnotify_mark", group.marks_list.address_of_(), "g_list"
    )


def _get_object_no_type(obj: Object) -> Tuple[str, Object]:
    # obj may be:
    #  - struct fsnotify_mark_connector  (if it exists)
    #  - struct fsnotify_mark  (if this kernel version has no connector struct)
    if obj.flags & 0x1:
        return "inode", obj.inode
    elif obj.flags & 0x2:
        return "vfsmount", obj.vfsmount
    else:
        return "unknown", NULL(obj.prog_, "void *")


def fsnotify_mark_object(mark: Object) -> Tuple[str, Object]:
    """
    For an fsnotify mark, determine what kind of object and return it

    Fsnotify marks can be applied to an inode, superblock, or vfsmount. Identify
    which kind of object the mark is applied to, and return that along with a
    pointer to the object. If we don't understand the object type, then we
    return ("unknown", NULL).

    :param mark: ``struct fsnotify_mark *``
    :returns: (object type, object pointer)
    """
    prog = mark.prog_

    try:
        conn = mark.connector
    except AttributeError:
        # Commit 9dd813c15b2c1 ("fsnotify: Move mark list head from object into
        # dedicated structure") is the beginning of a series that introduces the
        # fsnotify_mark_connector. Prior to this, the mark directly pointed at
        # the object it contained. This was merged in 4.12.
        return _get_object_no_type(mark)

    try:
        type_ = conn.type.read_()
    except AttributeError:
        # Commit d6f7b98bc8147 ("fsnotify: use type id to identify connector
        # object type") adds a type field to the connector. Before this, type
        # was expressed as bits in the flag field. The bit numbers were
        # preprocessor definitions, let's just hardcode them here.
        return _get_object_no_type(conn)

    # See fsnotify_conn_{inode,mount,sb} in fs/notify/fsnotify.h
    if type_ == prog.constant("FSNOTIFY_OBJ_TYPE_INODE"):
        # Prior to 36f10f55ff1d2 ("fsnotify: let connector point to an abstract
        # object"), there were direct pointers in the connector.
        if hasattr(conn, "inode"):
            return "inode", conn.inode
        return "inode", container_of(
            conn.obj, "struct inode", "i_fsnotify_marks"
        )
    elif type_ == prog.constant("FSNOTIFY_OBJ_TYPE_VFSMOUNT"):
        # Prior to 36f10f55ff1d2 ("fsnotify: let connector point to an abstract
        # object"), there were direct pointers in the connector.
        if hasattr(conn, "vfsmount"):
            return "vfsmount", conn.vfsmount
        return "vfsmount", container_of(
            conn.obj, "struct mount", "mnt_fsnotify_marks"
        )
    elif type_ == prog.constant("FSNOTIFY_OBJ_TYPE_SB"):
        # The "sb" object type was not present when 36f10f55ff1d2 ("fsnotify:
        # let connector point to an abstract object") so it will never have an
        # "sb" field.
        return "sb", container_of(
            conn.obj, "struct super_block", "s_fsnotify_marks"
        )
    else:
        return "unknown", NULL(prog, "void *")


def hlist_first_entry_or_null(type: str, head: Object, field: str):
    # Return the first entry of an hlist, or NULL. Equivalent to the drgn
    # list_first_entry_or_null function, just a useful helper.
    for obj in hlist_for_each_entry(type, head, field):
        return obj
    return NULL(head.prog_, type + " *")


def fsnotify_summarize_object(kind: str, obj: Object) -> str:
    """
    Given an object marked by fsnotify, return a string representation

    This is typically a file path: either the path to the watched file/dir, or
    the path to the mounted filesystem when a vfsmount or superblock. It should
    be noted that in all cases, there can be multiple paths (e.g. hard linked
    files, multiple mounts, etc). We output only one and hope it is useful.

    :param kind: either inode, vfsmount, sb, or unknown
    :param obj: a corresponding drgn object (see :func:`fsnotify_mark_object()`)
    :returns: a string representation for printing to a user
    """
    if kind == "inode":
        # Arbitrarily choose the first dentry for this inode, and further use
        # the first mount point all the way up the tree. We just want something
        # useful, not exhaustive.
        # 946e51f2bf37f ("move d_rcu from overlapping d_child to overlapping d_alias")
        field = (
            "d_alias"
            if type_has_member(obj.prog_, "struct dentry", "d_alias")
            else "d_u.d_alias"
        )
        dentry = hlist_first_entry_or_null(
            "struct dentry", obj.i_dentry.address_of_(), field
        )
        if dentry:
            return escape_ascii_string(dentry_path_any_mount(dentry))
        else:
            return "(ANON INODE)"
    elif kind == "vfsmount":
        fstype = obj.mnt.mnt_sb.s_type.name.string_().decode()
        path = escape_ascii_string(dentry_path_any_mount(obj.mnt_mountpoint))
        return f"FS:{fstype} MOUNT:{path}"
        pass
    elif kind == "sb":
        fstype = obj.s_type.name.string_().decode()
        first = sb_first_mount_point(obj)
        path = escape_ascii_string(dentry_path_any_mount(first))
        return f"SUPER:{fstype} ({path})"
    else:
        return "(not implemented)"


def _print_waiter(task: Object, kind: str, pfx: Optional[str]):
    if not pfx:
        pfx = ""
    wait_time = task_lastrun2now(task)
    wait_time_fmt = str(timedelta(seconds=wait_time / 1000000000))
    print(
        f"{pfx}[PID: {task.pid.value_()} COMM: {task.comm.string_().decode()}] WAIT: {kind} DURATION: {wait_time_fmt}"
    )


def print_waitqueue(
    wq: Object, indent: int = 2, stack_trace: bool = False
) -> None:
    """
    Print the waiters of a waitqueue

    This function enumerates all entries of a wait queue, and prints out
    information about each entry. Many entries are simply a task directly
    waiting. However, wait queues may be waited on by select and epoll objects,
    and probably other possibilities too. This function tries to print enough
    information to know who is waiting on a waitqueue, even if there's a select
    or epoll happening. Since epoll objects themselves could be waited upon,
    it's possible that this function will recursively call itself.

    :param wq: the ``wait_queue_head_t`` object
    :param indent: indentation for the output
    :param stack_trace: whether to print stack trace for waiters
    """
    if not waitqueue_active(wq):
        print("  <no waiters>")
        return
    prog = wq.prog_
    pfx = " " * indent
    for entry in waitqueue_for_each_entry(wq):
        func = "UNKNOWN"
        try:
            func = prog.symbol(entry.func.value_()).name
        except LookupError:
            pass

        if func == "pollwake":
            wqueues = cast("struct poll_wqueues *", entry.private)
            task = wqueues.polling_task
            _print_waiter(task, "select", pfx)
            if stack_trace:
                bt(task, indent=indent + 2)
        elif func == "ep_poll_callback":
            epitem = container_of(entry, "struct eppoll_entry", "wait").base
            ep = epitem.ep
            print(f"{pfx}[EVENTPOLL: {ep.value_():x}]")
            found_waiter = False
            if waitqueue_active(ep.wq):
                print(f"{pfx}Waiting in epoll_wait():")
                print_waitqueue(ep.wq, indent + 2, stack_trace=stack_trace)
                found_waiter = True
            if waitqueue_active(ep.poll_wait):
                print(f"{pfx}Waiting in file->poll():")
                print_waitqueue(
                    ep.poll_wait, indent + 2, stack_trace=stack_trace
                )
                found_waiter = True
            if not found_waiter:
                print(f"{pfx}No waiters found.")
        else:
            info = slab_object_info(entry.private)
            if info and info.slab_cache.name.string_() == b"task_struct":
                task = cast("struct task_struct *", entry.private)
                _print_waiter(task, "direct", pfx)
                if stack_trace:
                    bt(task, indent=indent + 2)


def fsnotify_group_report(
    group: Object, group_kind: str, verbose: int = 1
) -> None:
    """
    Print a report about an fsnotify group.
    :param group: ``struct fsnotify_group *``
    :param group_kind: either inotify or fanotify
    :param verbose: a verbosity level:
      0: summarize only
      1: output vfsmounts and super blocks, and a limited number of inodes
      2: same as above, but also include stack traces for waiters
      3: output every marked inode (this could be a very large amount)
    """
    print(f"FSNOTIFY GROUP: {group.value_():x}")
    kind_counts: Dict[str, int] = {}
    for mark in fsnotify_group_for_each_mark(group):
        kind, ptr = fsnotify_mark_object(mark)
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        mask = decode_flags(
            mark.mask, FSNOTIFY_FLAGS.items(), bit_numbers=False
        )
        # 8e17bf975102c ("fanotify: prepare for setting event flags in ignore
        # mask")
        try:
            ignore_mask = decode_flags(
                mark.ignore_mask, FSNOTIFY_FLAGS.items(), bit_numbers=False
            )
        except AttributeError:
            ignore_mask = decode_flags(
                mark.ignored_mask, FSNOTIFY_FLAGS.items(), bit_numbers=False
            )
        try:
            count = mark.refcnt.refs.counter.value_()
        except AttributeError:
            # 7761daa6a1599 ("fsnotify: convert fsnotify_group.refcnt from
            # atomic_t to refcount_t")
            count = mark.refcnt.counter.value_()
        summary = fsnotify_summarize_object(kind, ptr)
        if verbose < 1:
            continue
        if verbose < 3 and kind == "inode":
            if kind_counts[kind] == 10:
                print(
                    "  <note: skipped printing inodes, use verbose to see all>"
                )
            if kind_counts[kind] >= 10:
                continue
        print(f"  MARK: {kind} {ptr.value_():x} {summary}")
        print(f"    CNT:{count} MASK:{mask} IGN:{ignore_mask}")
    print(
        "OBJECT SUMMARY: "
        + ", ".join(f"{kind}: {count}" for kind, count in kind_counts.items())
    )

    pending_notifications = list_count_nodes(
        group.notification_list.address_of_()
    )
    print(f"{pending_notifications} notifications are pending.")
    print("Tasks waiting for notification:")
    print_waitqueue(group.notification_waitq, stack_trace=verbose >= 2)

    if group_kind == "fanotify":
        resp_cnt = list_count_nodes(
            group.fanotify_data.access_list.address_of_()
        )
        print(f"{resp_cnt} pending permission responses")
        print("Tasks waiting for permission response from userspace:")
        print_waitqueue(
            group.fanotify_data.access_waitq, stack_trace=verbose >= 2
        )
    elif group_kind in ("inotify", "dnotify"):
        pass  # nothing special to report
    else:
        print(f"unknown kind {group_kind}")


def fsnotify_show(prog: Program, verbose: int = 1) -> None:
    """
    Print a report of every fsnotify group on the system.

    This enumerates all fsnotify and inotify groups, by iterating over each task
    & finding relevant files. Each one has a report printed. Finally, the system
    dnotify group (there is only one) is printed.

    :param verbose: verbosity level (see :func:`fsnotify_group_report()`)
    """
    fanotify_ops = prog["fanotify_fops"].address_of_()
    inotify_ops = prog["inotify_fops"].address_of_()
    group_type = prog.type("struct fsnotify_group *")
    seen_groups = set()
    for task in for_each_task(prog):
        # No point in looking at threads, since file descriptions are shared.
        if not is_group_leader(task):
            continue

        for fd, file in for_each_file(task):
            if file and file.f_op == fanotify_ops:
                kind = "fanotify"
            elif file and file.f_op == inotify_ops:
                kind = "inotify"
            else:
                continue
            print(
                f"[PID {task.pid.value_()} COMM: {task.comm.string_().decode()} {kind} FD {fd}]"
            )
            group = cast(group_type, file.private_data)

            # Since file descriptors can be shared even across tasks, we need to
            # track groups we've already reported and skip re-reporting. This
            # reduces the output size and runtime. For example, crond seems to
            # share an inotify FD across tasks.
            if group.value_() not in seen_groups:
                seen_groups.add(group.value_())
                fsnotify_group_report(group, kind, verbose=verbose)
            else:
                print(f"FSNOTIFY GROUP {group.value_():x}: already seen")
            print()
    if prog["dnotify_group"]:
        # dnotify_group can be NULL early in boot. No use crashing if that's the
        # case.
        print("[SYSTEM DNOTIFY GROUP]")
        fsnotify_group_report(
            prog["dnotify_group"], "dnotify", verbose=verbose
        )


class Fsnotify(CorelensModule):
    """Print details about the fsnotify subsystem"""

    name = "fsnotify"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--verbose",
            "-v",
            type=int,
            default=1,
            help="Set verbosity: 0-4 (default 1)",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        fsnotify_show(prog, verbose=args.verbose)
