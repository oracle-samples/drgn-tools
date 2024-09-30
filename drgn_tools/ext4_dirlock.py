# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Help detect hung by ext4 direcotry inode lock

Exadata customers run into bug 32016306 many times. The symptom of the bug
is that some process is reading one ext4 directory with inode lock held,
some other processes are trying to access the same directory and get hung
by inode lock of that directory. In most of the cases, that directory is
some db trace direcotory under /u01 in exadata system since db tracing is
enabled, once CRS detects those hung db processes, it will evict the system,
sometimes due to some unknown reason, CRS eviction doesn't happen, instead
the system just hung or panic by hung task panic.

The following is an example of the culprit process that causes hung.
The other processs will be hung by rwsem write block or mutex depending on
kernel verison.

.. code-block::

    PID: 106479  TASK: ffff9bcb1c8c5f00  CPU: 46  COMMAND: "ohasd.bin"
     #0 [ffffb54e916efa10] __schedule at ffffffffb988ff6c
     #1 [ffffb54e916efab0] schedule at ffffffffb9890586
     #2 [ffffb54e916efac8] io_schedule at ffffffffb9890a06
     #3 [ffffb54e916efae0] bit_wait_io at ffffffffb9890fb1
     #4 [ffffb54e916efaf8] __wait_on_bit at ffffffffb9890a96
     #5 [ffffb54e916efb38] out_of_line_wait_on_bit at ffffffffb9890b51
     #6 [ffffb54e916efb90] __wait_on_buffer at ffffffffb92d1432
     #7 [ffffb54e916efba8] ext4_bread at ffffffffc019024e [ext4]
     #8 [ffffb54e916efbd0] __ext4_read_dirblock at ffffffffc01a75f4 [ext4]
     #9 [ffffb54e916efc28] htree_dirblock_to_tree at ffffffffc01a7ecb [ext4]
    #10 [ffffb54e916efce0] ext4_htree_fill_tree at ffffffffc01a928b [ext4]
    #11 [ffffb54e916efdc0] ext4_readdir at ffffffffc0173bea [ext4]
    #12 [ffffb54e916efe80] iterate_dir at ffffffffb92aa1b8
    #13 [ffffb54e916efec8] sys_getdents at ffffffffb92aaaf8
    #14 [ffffb54e916eff28] do_syscall_64 at ffffffffb9003ca9
    #15 [ffffb54e916eff50] entry_SYSCALL_64_after_hwframe at ffffffffb9a001b1

Since ``ext4_readdir()`` reads each dir block synchronized, so either of the
following reason can lead to this hung.
1. The size of that ext4 inode direcotry is large
2. The volume hosting the direcotry has high io latency

This helper will dump the following output if hung detected. From the metric
it report we can tell what's causing the hung.
The "Lastrun2now" of the first lock waiter can tell how long this hung has
been there, any hung time close or over 30s could lead to CRS eviction.
If direcotory size is large, please clean up it, if that direcotry doesn't
has much files in it, please recreate the directory, ext4 may not free some
direcotry blocks even all dentry in it are already removed.
If it's db trace direcotry, please also disable db tracing to avoid that
directory get filled up again.

If directory size is not large, but hung time is long, then it's probably
underlying disk volume is slow. For example in the following output, lock
owner stays in D status 259ms, run the helper again with call trace enabled,
if it is waiting io done, then that means the underlying disk volume has
long I/O latency, you should review iostat from oswatcher for more details.

.. code-block::

    >>> ext4_dirlock.ext4_dirlock_scan(prog)
    Directory   : /u01/app/grid/diag/crs/lrlupxa5adm02vm02/crs/trace
    Volume      : dm-2
    dentry      : 0xffff9bd0bd8a3a40
    inode       : 0xffff9bd9d09611e8
    Size        : 21835776
    Sectors     : 42728
    Inode Lock  : Command          Pid      Status Lastrun2now(ms)
    Lock owner  : ohasd.bin        106479   D      259
    Lock waiter :
            [0] : ocssd.bin        120176   D      31128
            [1] : gipcd.bin        110130   D      22267
            [2] : cssdagent        118193   D      14643
            [3] : cssdmonitor      118117   D      14074
            [4] : ohasd.bin        106260   D      603

Please note even though I mention a lot of exadata/db/crs, it doesn't mean
this helper only works there, it can help detect ext4 directory hung in
other systems also.

This helper will only work with vmcore, because it requires unwinding the stack
trace of each process for searching the hung, which is not supported by live
system. Also debuginfo is always required for this helper because it will grab
variable from the stack frame.
"""
import argparse

import drgn
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.fs import d_path
from drgn.helpers.linux.list import list_for_each
from drgn.helpers.linux.sched import task_state_to_char

from drgn_tools.bt import bt
from drgn_tools.bt import bt_has
from drgn_tools.corelens import CorelensModule
from drgn_tools.itertools import count
from drgn_tools.locking import for_each_mutex_waiter
from drgn_tools.locking import for_each_rwsem_waiter
from drgn_tools.locking import show_lock_waiter
from drgn_tools.module import ensure_debuginfo
from drgn_tools.task import task_lastrun2now
from drgn_tools.util import has_member
from drgn_tools.util import timestamp_str


def ext4_dirlock_scan(prog: drgn.Program, stacktrace: bool = False) -> None:
    """
    Scan processes hung by ext4 directory inode lock

    The inode lock is ``struct mutex`` in uek4 and
    ``struct rw_semaphore`` in uek5+

    :param prog: drgn program
    :param stacktrace: True to dump process stack trace
    :returns: None
    """
    msg = ensure_debuginfo(prog, ["ext4"])
    if msg:
        print(msg)
        return

    frame_list = bt_has(prog, "ext4_htree_fill_tree")
    lock_detected = bool(frame_list)
    if not lock_detected:
        print("No ext4 dir lock used.")
        return

    for task, frame in frame_list:
        try:
            dentry = frame["dir_file"].f_path.dentry
        except (drgn.ObjectAbsentError, KeyError):
            print(
                f"warning: task {task.pid.value_()} "
                f"({escape_ascii_string(task.comm.string_())}) has "
                "ext4_htree_fill_tree() in its stack, but we cannot "
                "read the stack frame variables. Results may be "
                "incomplete."
            )
            if stacktrace:
                bt(task)
            continue
        inode = frame["dir_file"].f_inode
        disk = dentry.d_sb.s_bdev.bd_disk
        print(
            "%-12s: %s"
            % ("Directory", d_path(frame["dir_file"].f_path).decode())
        )
        print("%-12s: %s" % ("Volume", disk.disk_name.string_().decode()))
        print("%-12s: 0x%x" % ("dentry", dentry.value_()))
        print("%-12s: 0x%x" % ("inode", inode.value_()))
        print("%-12s: %d" % ("Size", inode.i_size.value_()))
        print("%-12s: %d" % ("Sectors", inode.i_blocks.value_()))
        print(
            "%-12s: %d"
            % ("subdirs", count(list_for_each(dentry.d_subdirs.address_of_())))
        )
        print(
            "%-12s: %-16s %-8s %-6s %-16s"
            % ("Inode Lock", "Command", "Pid", "Status", "Lastrun2now")
        )
        print(
            "%-12s: %-16s %-8d %-6s %-16s"
            % (
                "Lock owner",
                task.comm.string_().decode(),
                task.pid.value_(),
                task_state_to_char(task),
                timestamp_str(task_lastrun2now(task)),
            )
        )
        if stacktrace:
            bt(task)
        print("%-12s:" % "Lock waiter")

        index = 0
        if has_member(inode, "i_rwsem"):
            for waiter in for_each_rwsem_waiter(prog, inode.i_rwsem):
                show_lock_waiter(prog, waiter, index, stacktrace)
                index = index + 1
        elif has_member(inode, "i_mutex"):
            for waiter in for_each_mutex_waiter(prog, inode.i_mutex):
                show_lock_waiter(prog, waiter, index, stacktrace)
                index = index + 1


class Ext4DirLock(CorelensModule):
    """Scan processes hung by ext4 directory inode lock"""

    name = "ext4_dirlock_scan"
    skip_unless_have_kmod = "ext4"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--stack-trace",
            action="store_true",
            help="Print task stack traces",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        ext4_dirlock_scan(prog, args.stack_trace)
