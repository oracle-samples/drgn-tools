# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for soft raid
"""
import argparse
from typing import Iterable

from drgn import Object
from drgn import Program
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.block import blkdev_ro
from drgn_tools.block import for_each_badblocks
from drgn_tools.block import get_inflight_io_nr
from drgn_tools.corelens import CorelensModule
from drgn_tools.module import ensure_debuginfo
from drgn_tools.util import enum_flags_str
from drgn_tools.util import has_member
from drgn_tools.util import percpu_ref_sum


def for_each_md(prog: Program) -> Iterable[Object]:
    """
    List all soft raid disk in the system

    :param prog: drgn program
    :returns: an iterator of all ``struct mddev *`` in the system
    """
    return list_for_each_entry(
        "struct mddev",
        prog["all_mddevs"].address_of_(),
        "all_mddevs",
    )


def md_pending_writes(prog: Program, mddev: Object) -> int:
    """
    Get pending write IO request number from ``struct mddev *``

    :param prog: drgn program
    :param mddev: ``struct mddev *``
    :returns: pending write IO request number
    """
    writes_pending = mddev.writes_pending
    if has_member(writes_pending, "counter"):
        return writes_pending.counter
    else:
        return percpu_ref_sum(prog, mddev.writes_pending)


def for_each_md_pv(prog: Program, mddev: Object) -> Iterable[Object]:
    """
    List all physical disks of the md

    :param prog: drgn program
    :param mddev: ```struct mddev *```
    :returns: an iterator of all ``struct md_rdev *`` of the md
    """
    return list_for_each_entry(
        "struct md_rdev", mddev.disks.address_of_(), "same_set"
    )


def md_pv_name(rdev: Object) -> str:
    """
    Get the name of one physical disk for the md

    :param rdev: ``struct md_rdev *``
    :returns: the name of the physical disk
    """
    gendisk = rdev.bdev.bd_disk
    if has_member(rdev.bdev, "bd_partno"):
        partno = rdev.bdev.bd_partno
    else:
        partno = rdev.bdev.bd_part.partno
    diskname = gendisk.disk_name.string_().decode()
    if partno != 0:
        return "%s%d" % (diskname, partno)
    else:
        return diskname


def md_pv_pending_io(rdev: Object) -> str:
    """
    Get pending IO request from ``struct md_rdev *``

    Only raid level 1,4,5,6,10 supports this

    :param rdev: ``struct md_rdev *``
    :returns: pending io number for supporting raid level, otherwise '-'
    """
    mddev = rdev.mddev
    if mddev.level in (1, 4, 5, 6, 10):
        return str(rdev.nr_pending.counter.value_())
    else:
        return "-"


def md_pv_badblocks(prog: Program, mddev: Object) -> int:
    num = 0
    for rdev in for_each_md_pv(prog, mddev):
        num += rdev.badblocks.count.value_()
    return num


def show_md_pv_badblocks(prog: Program, mddev: Object) -> None:
    print("%10s: %-8s %-20s" % ("Badblocks", "PV", "[(off,len,ack)]"))
    for rdev in for_each_md_pv(prog, mddev):
        if rdev.badblocks.count.value_() == 0:
            continue
        print(
            "%10s: %-8s " % (" ", md_pv_name(rdev)),
            end="",
        )
        bb_list = [(o, l, a) for o, l, a in for_each_badblocks(rdev.badblocks)]
        print(bb_list)


def show_md_pv(prog: Program, mddev: Object) -> None:
    """
    Dump the physical disk specific info

    :param prog: drgn program
    :param mddev: ``struct mddev *``
    :returns: None
    """
    index = 0
    for rdev in for_each_md_pv(prog, mddev):
        prefix = "[%d] " % index
        pending = "%-8s    %-8d" % (
            md_pv_pending_io(rdev),
            get_inflight_io_nr(prog, rdev.bdev.bd_disk),
        )
        print(
            "%10s: %-8s %-4d %-20s %-8s %-10s %-8s"
            % (
                prefix,
                md_pv_name(rdev),
                blkdev_ro(rdev.bdev),
                pending,
                enum_flags_str(prog, "enum flag_bits", rdev.flags),
                rdev.data_offset.value_(),
                rdev.badblocks.count.value_(),
            )
        )
        index = index + 1


def show_raid5_info(prog: Program, mddev: Object) -> None:
    """
    Show raid5 only info

    :param prog: drgn program
    :param mddev: ``struct mddev *``
    :returns: None
    """
    msg = ensure_debuginfo(prog, ["raid456"])
    if msg:
        print(msg)
        return

    conf = Object(prog, "struct r5conf *", value=mddev.private.value_())
    print(
        "%-10s: %d chunk size aligned bio. Non-aligned bio not tracked."
        % ("pending-rd", conf.active_aligned_reads.counter)
    )
    max_stripes = (
        conf.max_stripes
        if has_member(conf, "max_stripes")
        else conf.max_nr_stripes
    )
    active_stripes = conf.active_stripes.counter
    workers_per_grp = conf.worker_cnt_per_group
    print(
        "%-10s: max %d active %d workers_per_grp %d"
        % ("Stripe", max_stripes, active_stripes, workers_per_grp)
    )
    if active_stripes >= (3 * max_stripes / 4):
        print(
            "%-10s: %s"
            % (
                " ",
                """This raid disk is very busy, the number of active stripes
            are over 3/4 max stripes, processes may stuck.""",
            )
        )
        msg = "%s group_thread_cnt may improve the performance." % (
            "Enable" if workers_per_grp == 0 else "Tune up"
        )
        print("%-10s: %s" % (" ", msg))
        disk_name = mddev.gendisk.disk_name.string_().decode()
        print(
            "%-10s: %s%s"
            % (
                " ",
                "echo $thread_cnt > /sys/block/",
                "%s/md/group_thread_cnt" % disk_name,
            )
        )


def raid1_nr_value(nr: Object) -> int:
    """
    Get nr_pending/waiting value

    Those fields are changed by 824e47daddbfc from "int" to atomic *

    :param nr: nr_* of ``struct r1conf``
    :returns: value as int
    """
    if nr.type_.type_name() == "int":
        return nr
    # The type of nr is atomic_t *
    value = 0
    # BARRIER_BUCKETS_NR = 1024
    for i in range(1024):
        value += nr[i].counter
    return value


def show_raid1_info(prog: Program, mddev: Object) -> None:
    """
    Show raid1 only info

    :param prog: drgn program
    :param mddev: ``struct mddev *``
    :returns: None
    """
    msg = ensure_debuginfo(prog, ["raid1"])
    if msg:
        print(msg)
        return

    conf = Object(prog, "struct r1conf *", value=mddev.private.value_())
    print(
        "%-10s: %d processes waiting raid ready to issue io"
        % ("Waiting", raid1_nr_value(conf.nr_waiting))
    )
    print("%-10s: %d" % ("pending-io", raid1_nr_value(conf.nr_pending)))
    pending_count = conf.pending_count
    max_queued_requests = None
    try:
        max_queued_requests = prog["max_queued_requests"]
        congested = pending_count >= max_queued_requests
    except KeyError:
        # 9a3abe191fd6 ("md: drop queue limitation for RAID1 and RAID10")
        # removes this variable, only report if it exists
        congested = False
    if congested:
        msg = (
            "%-10s: Yes, processes will be stuck when issuing write io."
            % "Congested"
        )
    else:
        msg = "%-10s: No" % "Congested"
    print(msg)
    print(
        "%-10s: %d writes queued for raid1 thread to handle"
        % (" ", pending_count)
    )
    if max_queued_requests is not None:
        print(
            "%-10s: max allowed queued requests are %d"
            % (" ", max_queued_requests)
        )


def show_md(prog: Program) -> None:
    """
    Dump md info in the system

    :param prog: drgn program
    :returns: None
    """
    for mddev in for_each_md(prog):
        print(
            "%-10s: %s - (struct mddev *)%s"
            % (
                "Raid",
                mddev.gendisk.disk_name.string_().decode(),
                hex(mddev.value_()),
            )
        )
        LEVEL_NONE = -1000000
        if mddev.level == LEVEL_NONE:
            level = "None"
        else:
            level = mddev.pers.name.string_().decode()
        print("%-10s: %s" % ("Level", level))
        container = mddev.metadata_type.string_().decode()
        if container == "":
            container = "None"
        print("%-10s: %s" % ("Container", container))
        print("%-10s: %dk" % ("chunk-size", mddev.chunk_sectors / 2))
        print(
            "%-10s: %s"
            % ("flags", enum_flags_str(prog, "enum mddev_flags", mddev.flags))
        )
        if has_member(mddev, "sb_flags"):
            print(
                "%-10s: %s"
                % (
                    "sb_flags",
                    enum_flags_str(
                        prog, "enum mddev_sb_flags", mddev.sb_flags
                    ),
                )
            )
        # linear and raid0 doesn't support recovery
        if mddev.level != 0 and mddev.level != -1:
            print(
                "%-10s: %s"
                % (
                    "recovery",
                    enum_flags_str(
                        prog, "enum recovery_flags", mddev.recovery
                    ),
                )
            )
        if mddev.ro == 1:
            ro = "Readonly"
        elif mddev.ro == 2:
            ro = "Readauto"
        else:
            ro = "Readwrite"
        print("%-10s: %s" % ("RW", ro))
        print(
            "%-10s: %d range(%d %d)"
            % (
                "Suspended",
                mddev.suspended,
                mddev.suspend_lo,
                mddev.suspend_hi,
            )
        )
        print("%-10s: %d processes" % ("IO-issuing", mddev.active_io.counter))
        print(
            "%10s: %-8s %-4s %-20s %-8s %-10s %-8s"
            % (
                "PV ",
                "Name",
                "RO",
                "Pending-IO(md-block)",
                "Flags",
                "sector_off",
                "badblocks",
            )
        )
        show_md_pv(prog, mddev)
        if md_pv_badblocks(prog, mddev):
            show_md_pv_badblocks(prog, mddev)
        # raid0 didn't maintain pending writes
        if mddev.level != 0:
            print("%-10s: %d" % ("pending-wr", md_pending_writes(prog, mddev)))
        if mddev.level == 5:
            show_raid5_info(prog, mddev)
        elif mddev.level == 1:
            show_raid1_info(prog, mddev)
        print()


class Md(CorelensModule):
    """Display info about "Multiple device" software RAID"""

    name = "md"
    debuginfo_kmods = [r"re:raid\d+"]

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        show_md(prog)
