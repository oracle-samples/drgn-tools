# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for block layers.

No kernel modules are required since uek built in all io schduler modules.
"""
import argparse
from typing import Iterable
from typing import Tuple

import drgn
from drgn import cast
from drgn import container_of
from drgn import Object
from drgn import TypeKind
from drgn.helpers.common.format import decode_enum_type_flags
from drgn.helpers.linux.block import for_each_disk
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.device import MAJOR
from drgn.helpers.linux.device import MINOR
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.xarray import xa_for_each

from drgn_tools.bitops import for_each_bit_set
from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table
from drgn_tools.util import has_member
from drgn_tools.util import timestamp_str
from drgn_tools.util import type_exists

BB_LEN_MASK = 0x00000000000001FF
BB_OFFSET_MASK = 0x7FFFFFFFFFFFFE00
BB_ACK_MASK = 0x8000000000000000


def for_each_badblocks(bb: Object) -> Iterable[Object]:
    """
    List all bad blocks

    :param bb: ``struct badblocks``
    :returns: an iterator of (sector_offset, length, ack)
    """
    if bb.value_() == 0 or bb.page.value_() == 0:
        return
    bb_list = cast("u64 *", bb.page)
    for i in range(bb.count):
        item = bb_list[i].value_()
        offset = (item & BB_OFFSET_MASK) >> 9
        length = (item & BB_LEN_MASK) + 1
        ack = (item & BB_ACK_MASK) != 0
        yield (offset, length, ack)


def blkdev_devt_str(bdev: Object) -> str:
    return "%d:%d" % (MAJOR(bdev.bd_dev), MINOR(bdev.bd_dev))


def blkdev_ro(bdev: Object) -> int:
    """
    Check whether ``struct block_device *`` is read only

    :param bdev: ``struct block_device *``
    :returns: 1 if readonly, 0 if readwrite, -1 if unknown
    """
    if has_member(bdev, "__bd_flags"):
        # v6.10: 01e198f01d55 ("bdev: move ->bd_read_only to ->__bd_flags")
        BD_READ_ONLY = 1 << 8
        return int(bool(bdev.__bd_flags.counter & BD_READ_ONLY))
    elif has_member(bdev, "bd_read_only"):
        # v5.11: 83950d359010 ("block: move the policy field to struct
        # block_device")
        return int(bool(bdev.bd_read_only.value_()))
    # "bd_part" is NULL if bdev was not opened yet.
    if bdev.bd_part:
        return int(bdev.bd_part.policy != 0)
    else:
        return -1


def BD_INODE(bdev: Object) -> Object:
    """
    Return the inode associated with a block device. Analogous to the kernel
    function of the same name.

    :param bdev: ``struct block_device *``
    :returns: ``struct inode *``
    """
    if has_member(bdev, "bd_inode"):
        return bdev.bd_inode
    else:
        # v6.10: 203c1ce0bb06 ("RIP ->bd_inode")
        return container_of(
            bdev, "struct bdev_inode", "bdev"
        ).vfs_inode.address_of_()


def blkdev_size(bdev: Object) -> int:
    """
    Return block device size

    :param bdev: ``struct block_device *``
    :returns: device size
    """
    return BD_INODE(bdev).i_size.value_()


def blkdev_name(bdev: Object) -> str:
    """
    Return block device name

    :param bdev: ``struct block_device *``
    :returns: device name
    """
    if has_member(bdev, "bd_partno"):
        partno = int(bdev.bd_partno)
    elif has_member(bdev, "__bd_flags"):
        # v6.10: 1116b9fa15c0 ("bdev: infrastructure for flags")
        partno = int(bdev.__bd_flags.counter & 0xFF)
    else:
        partno = int(bdev.bd_part.partno)

    disk_name = bdev.bd_disk.disk_name.string_().decode()
    if partno == 0:
        return disk_name
    if disk_name[len(disk_name) - 1].isdigit():
        return disk_name + "p" + str(partno)
    return disk_name + str(partno)


def for_each_request_queue(prog: drgn.Program) -> Iterable[Object]:
    """
    List all request_queue in the system.

    :param prog: drgn program
    :returns: an iterator of all ``struct request_queue *`` on the system
    """
    for disk in for_each_disk(prog):
        yield disk.queue


def is_mq(q: Object) -> bool:
    """
    Check whether request queue support multiple queue

    :param q: ``struct request_queue *``
    :returns: true if mq, otherwise false
    """
    return has_member(q, "mq_ops") and q.mq_ops.value_() != 0


def for_each_hw_queue(q: Object) -> Iterable[Object]:
    """
    List all hw queues of some request_queue

    :param q: ``struct request_queue *``
    :returns: all ``struct blk_mq_hw_ctx *`` of the queue as Iterator,
        or None if not mq
    """
    if not is_mq(q):
        return
    try:
        for i in range(q.nr_hw_queues):
            yield q.queue_hw_ctx[i]
    except AttributeError:
        # Since 4e5cc99e1e48 ("blk-mq: manage hctx map via xarray"), these are
        # managed with xarray via hctx_table. This was merged in 5.18 and thus
        # first would first appear in UEK8. Appears to be backported to RHCK in
        # OL9.
        for _, voidp in xa_for_each(q.hctx_table):
            yield cast("struct blk_mq_hw_ctx *", voidp)


def for_each_sbitmap_set_bit(sb: Object) -> Iterable[int]:
    """
    List set bit in struct sbitmap

    :param sb: ``struct sbitmap *``
    :returns: each set bit as Iterator
    """
    # Until 3301bc53358a ("lib/sbitmap: kill 'depth' from sbitmap_word"), there
    # was a "depth" field inside struct sbitmap_word. However, its value can be
    # inferred by the index, and so it is no longer present. We can use the new
    # approach here even on older kernels.
    depth = 1 << sb.shift
    for index in range(sb.map_nr):
        sb_word = sb.map[index]
        if index == sb.map_nr - 1:
            depth = sb.depth - (index << sb.shift)
        word = sb_word.word
        # See commit ea86ea2cdced ("sbitmap: ammortize cost of clearing bits")
        if has_member(sb_word, "cleared"):
            word = word & ~sb_word.cleared
        for nr in for_each_bit_set(word, depth):
            yield int((index << sb.shift) + nr)


def for_each_tag_bt_set_bit(bt: Object) -> Iterable[int]:
    """
    List all used tag from struct blk_mq_bitmap_tags

    :param bt: ``struct blk_mq_bitmap_tags *``
    :returns: each used tag as Iterator
    """
    index = 0
    while index < bt.map_nr:
        bm = bt.map[index]
        for nr in for_each_bit_set(bm.word.value_(), bm.depth.value_()):
            yield index * bm.depth.value_() + nr
        index += 1


def for_each_tag_pending_rq_uek4(tags: Object) -> Iterable[Object]:
    """
    List all pending request from struct blk_mq_tags

        It only works for the kernel where struct sbitmap_queue doesn't exist.

    :param tags: ``struct blk_mq_tags *``
    :returns: each pending ``struct request *`` as Iterator
    """
    prog = tags.prog_
    if (
        tags.type_.kind == TypeKind.STRUCT
        and tags.type_.tag == "blk_mq_bitmap_tags"
    ):
        return
    reserved = tags.nr_reserved_tags
    if reserved != 0:
        for tag in for_each_tag_bt_set_bit(tags.breserved_tags):
            addr = tags.rqs[tag].value_()
            if addr == 0:
                continue
            yield Object(prog, "struct request *", value=addr)
    for tag in for_each_tag_bt_set_bit(tags.bitmap_tags):
        addr = tags.rqs[tag + reserved].value_()
        if addr == 0:
            continue
        yield Object(prog, "struct request *", value=addr)


def for_each_tag_pending_rq(tags: Object) -> Iterable[Object]:
    """
    List all pending request from struct blk_mq_tags

    :param tags: ``struct blk_mq_tags *``
    :returns: each pending ``struct request *`` as Iterator
    """
    prog = tags.prog_
    # older than uek5
    if not type_exists(prog, "struct sbitmap_queue"):
        for rq in for_each_tag_pending_rq_uek4(tags):
            yield rq
        return
    reserved = tags.nr_reserved_tags
    if reserved != 0:
        for tag in for_each_sbitmap_set_bit(tags.breserved_tags.sb):
            addr = tags.rqs[tag].value_()
            if addr == 0:
                continue
            yield Object(prog, "struct request *", value=addr)
    for tag in for_each_sbitmap_set_bit(tags.bitmap_tags.sb):
        addr = tags.rqs[tag + reserved].value_()
        if addr == 0:
            continue
        # Since commit 568f27006577("blk-mq: centralise related handling
        # into blk_mq_get_driver_tag") was merged in v5.10, for requests
        # that are not yet dispatched, like those in the plug list, we
        # should get from "tags.static_rqs", otherwise we may get a wrong
        # request. To resolve this, first check request from "tags.rqs"
        # is valid or not, if not get it from "tags.static_rqs".
        rq = Object(prog, "struct request *", value=addr)
        if rq.tag == -1:
            addr = tags.static_rqs[tag + reserved].value_()
            if addr == 0:
                continue
            rq = Object(prog, "struct request *", value=addr)
        yield rq


def for_each_hwq_pending_rq(hwq: Object) -> Iterable[Object]:
    """
    List pending requests from ``struct blk_mq_hw_ctx *``

    :param hwq: ``struct blk_mq_hw_ctx *``
    :returns: all ``struct request *`` in this hwq as Iterator
    """
    if has_member(hwq, "sched_tags") and hwq.sched_tags.value_() != 0:
        for rq in for_each_tag_pending_rq(hwq.sched_tags):
            yield rq
    for rq in for_each_tag_pending_rq(hwq.tags):
        yield rq


def for_each_mq_pending_request(q: Object) -> Iterable[Tuple[Object, Object]]:
    """
    List pending requests from ``struct request_queue *`` that supports mq

    :param q: ``struct request_queue *``
    :returns: an iterator of objects of type ``struct blk_mq_hw_ctx *``
        and ``struct request *``
    """
    if is_mq(q):
        for hwq in for_each_hw_queue(q):
            for rq in for_each_hwq_pending_rq(hwq):
                yield (hwq, rq)


def rq_pending_time_ns(rq: Object) -> int:
    """
    Get io pending time in ns

    :param rq: ``struct request *`` or ``struct request``
    :returns: request pending time
    """
    prog = rq.prog_
    if has_member(rq, "start_time"):
        return (prog["jiffies"] - rq.start_time).value_() * 1000000
    elif has_member(rq, "start_time_ns"):
        base = prog["tk_core"].timekeeper.tkr_mono.base
        delta = base - rq.start_time_ns
        return delta.value_() if base > rq.start_time_ns else 0
    else:
        return 0


def rq_op_ef295ecf(rq: Object) -> str:
    """
    Get request operation name

    This only works for kernel which is newer than
    commit ef295ecf090d ("block: better op and flags encoding") like uek5.

    :param rq: ``struct request *``
    :returns: combined request operation enum name as str
    """
    prog = rq.prog_
    # rq.cmf_flags: 8 bits for encoding the operation, and the remaining 24 for flags
    REQ_OP_BITS = 8
    op_mask = (1 << REQ_OP_BITS) - 1
    # commit ff07a02e9e8e6("treewide: Rename enum req_opf into enum req_op")
    opf = "enum req_op" if type_exists(prog, "enum req_op") else "enum req_opf"
    req_opf = {value: name for (name, value) in prog.type(opf).enumerators}
    cmd_flags = rq.cmd_flags.value_()
    key = cmd_flags & op_mask
    op = req_opf[key] if key in req_opf.keys() else "%s-%d" % ("UNKOP", key)
    flags = cmd_flags & ~op_mask
    if flags == 0:
        return op
    flags_str = "|"
    flags_str += decode_enum_type_flags(flags, prog.type("enum req_flag_bits"))
    return op + flags_str


def rq_op_old(rq: Object) -> str:
    """
    Get request operation name for kernel which is older than commit ef295ecf(uek4)

    :param rq: ``struct request *``
    :returns: combined request operation enum name as str
    """
    prog = rq.prog_
    # last bit for data direction, remaining bits for flags.
    op = "WRITE" if rq.cmd_flags & 0x1 else "READ"
    flags = rq.cmd_flags.value_() & (-2)
    if flags == 0:
        return op
    flags_str = "|"
    flags_str += decode_enum_type_flags(flags, prog.type("enum rq_flag_bits"))
    return op + flags_str


def rq_op(rq: Object) -> str:
    """
    Get request operation name

    :param rq: ``struct request *`` or ``struct request``
    :returns: combined request operation enum name as str
    """
    prog = rq.prog_
    if type_exists(prog, "enum req_opf") or type_exists(prog, "enum req_op"):
        return rq_op_ef295ecf(rq)
    elif type_exists(prog, "enum rq_flag_bits"):
        return rq_op_old(rq)
    else:
        return bin(rq.cmd_flags)


def rq_flags(rq: Object) -> str:
    """
    Get request operation flags

    :param rq: ``struct request *`` or ``struct request``
    :returns: operation flags of the request
    """
    # uek4 didn't have this member
    if has_member(rq, "rq_flags"):
        return str(bin(rq.rq_flags))
    else:
        return "-"


def for_each_sq_elevator_rq(q: Object) -> Iterable[Object]:
    """
    List request in elevator of legacy request_queue

    :param q: ``struct request_queue *``
        :returns: pending ``struct request *`` from elevator of sq as Iterator
    """
    if q.elevator.value_() == 0:
        return []
    prog = q.prog_
    name = q.elevator.type.elevator_name.string_().decode()
    addr = q.elevator.elevator_data.value_()
    list1 = None
    list2 = None
    if name == "noop":
        elevator_data = Object(prog, "struct noop_data *", value=addr)
        list1 = elevator_data.queue
    elif name == "deadline":
        elevator_data = Object(prog, "struct deadline_data *", value=addr)
        list1 = elevator_data.fifo_list[0].address_of_()
        list2 = elevator_data.fifo_list[1].address_of_()
    elif name == "cfq":
        # TODO: implement this
        print(
            "queue 0x%lx: dump pending IO from cfq not supported!" % q.value_()
        )
        return []
    else:
        return []

    for rq in list_for_each_entry(
        prog.type("struct request"), list1, "queuelist"
    ):
        yield rq
    for rq in list_for_each_entry(
        prog.type("struct request"), list2, "queuelist"
    ):
        yield rq


def for_each_sq_pending_request(q: Object) -> Iterable[Object]:
    """
    List pending requests from legacy ``struct request_queue``

    :param q: ``struct request_queue *``
    :returns: pending ``struct request *`` as Iterator
    """
    if (not has_member(q, "queue_head")) or is_mq(q):
        return
    # dispatched request
    if q.queue_tags.value_() != 0:
        # for request_queue that support tags, there maybe IO requests
        # which were under error handling, those requests will be in
        # "tag_busy_list" while not in "timeout_list".
        for rq in list_for_each_entry(
            "struct request",
            q.tag_busy_list.address_of_(),
            "queuelist",
        ):
            yield rq
    else:
        for rq in list_for_each_entry(
            "struct request",
            q.timeout_list.address_of_(),
            "timeout_list",
        ):
            yield rq
    # to be dispatched
    for rq in list_for_each_entry(
        "struct request", q.queue_head.address_of_(), "queuelist"
    ):
        yield rq
    # request in elevator
    for rq in for_each_sq_elevator_rq(q):
        yield rq


def request_target(rq: Object) -> Object:
    """
    Get the target disk of io request

    :param rq: ``struct request *``
    :returns: ``struct gendisk *``
    """
    if has_member(rq, "rq_disk"):
        return rq.rq_disk
    else:
        # rq.part not null only when doing IO statistics.
        if rq.part.value_():
            return rq.part.bd_disk
        else:
            for _ in for_each_disk(rq.prog_):
                if _.queue.value_() == rq.q.value_():
                    return _.queue
            return None


def show_rq_issued_cpu(rq: Object) -> str:
    """
    Get the cpu that request was issued from, if cpu is offline,
    it will be marked in the output with "offline". For sq, "-"
    will be returned.

    :param rq: ``struct request *``
    :returns: str combining cpu number and offline status for mq,
              '-' for sq.
    """
    if has_member(rq, "mq_ctx") and rq.mq_ctx:
        cpu = int(rq.mq_ctx.cpu)
    else:
        return "-"
    if cpu not in for_each_online_cpu(rq.prog_):
        return "%d(offline)" % cpu
    else:
        return str(cpu)


def dump_inflight_io(prog: drgn.Program, diskname: str = "all") -> None:
    """
    Dump all inflight io from all disks

    :param prog: drgn program
    :param diskname: name of some disk or "all" for all disks.
    """
    print(
        "%-20s %-20s %-20s %-16s %-16s\n%-20s %-20s %-20s %-16s"
        % (
            "device",
            "hwq",
            "request",
            "cpu",
            "op",
            "flags",
            "offset",
            "len",
            "inflight-time",
        )
    )

    try:
        BLK_MQ_F_TAG_SHARED = prog.constant("BLK_MQ_F_TAG_SHARED")
    except LookupError:
        BLK_MQ_F_TAG_SHARED = prog.constant("BLK_MQ_F_TAG_QUEUE_SHARED")
    for disk in for_each_disk(prog):
        name = disk.disk_name.string_().decode()
        if diskname != "all" and diskname != name:
            continue
        # Read the requests all at once into a list, and use read_() to
        # transform them into "values" - this is in case we are running on a
        # live system, as it reduces the chances of in-memory changes breaking
        # things.
        mq_pending = [
            (hwq.value_(), hwq[0].read_(), rq.value_(), rq[0].read_())
            for hwq, rq in for_each_mq_pending_request(disk.queue)
        ]
        for hwq_ptr, hwq, rq_ptr, rq in mq_pending:
            # for mq disk from same hba host who are sharing hwq.tags
            # check gendisk to dump io only from this particular disk.
            if (hwq.flags & BLK_MQ_F_TAG_SHARED) != 0 and request_target(
                rq
            ).value_() != disk.value_():
                continue
            print(
                "%-20s %-20lx %-20lx %-16s %-16s\n%-20s %-20d %-20d %-16s"
                % (
                    name,
                    hwq_ptr,
                    rq_ptr,
                    show_rq_issued_cpu(rq),
                    rq_op(rq),
                    rq_flags(rq),
                    rq.__sector,
                    rq.__data_len,
                    timestamp_str(rq_pending_time_ns(rq)),
                )
            )
        sq_pending = [
            (rq.value_(), rq[0].read_())
            for rq in for_each_sq_pending_request(disk.queue)
        ]
        for rq_ptr, rq in sq_pending:
            print(
                "%-20s %-20s %-20lx %-16s %-16s\n%-20s %-20d %-20d %-16s"
                % (
                    name,
                    "-",
                    rq_ptr,
                    "-",
                    rq_op(rq),
                    rq_flags(rq),
                    rq.__sector,
                    rq.__data_len,
                    timestamp_str(rq_pending_time_ns(rq)),
                )
            )


def get_inflight_io_nr(prog: drgn.Program, disk: Object) -> int:
    """
    Get inflight io number from some disk

    :param prog: drgn program
    :param disk: ``struct gendisk *``
    :returns: number of in-flight io
    """
    q = disk.queue
    if not is_mq(q):
        return len(list(for_each_sq_pending_request(q)))
    nr = 0
    try:
        BLK_MQ_F_TAG_SHARED = prog.constant("BLK_MQ_F_TAG_SHARED")
    except LookupError:
        BLK_MQ_F_TAG_SHARED = prog.constant("BLK_MQ_F_TAG_QUEUE_SHARED")

    try:
        BLK_MQ_F_TAG_HCTX_SHARED = prog.constant("BLK_MQ_F_TAG_HCTX_SHARED")
    except LookupError:
        BLK_MQ_F_TAG_HCTX_SHARED = 0

    for hwq in for_each_hw_queue(q):
        # hwq.tags were shared across different disks from same hba host.
        if (hwq.flags & BLK_MQ_F_TAG_SHARED) != 0:
            if (hwq.flags & BLK_MQ_F_TAG_HCTX_SHARED) != 0:
                nr += hwq.queue.nr_active_requests_shared_tags.counter
            else:
                nr += hwq.nr_active.counter
        else:
            nr += len(list(for_each_hwq_pending_rq(hwq)))
    return int(nr)


def print_block_devs_info(prog: drgn.Program) -> None:
    """
    Prints the block device information
    """
    output = [["MAJOR", "GENDISK", "NAME", "REQUEST_QUEUE", "Inflight I/Os"]]
    for disk in for_each_disk(prog):
        major = int(disk.major)
        gendisk = hex(disk.value_())
        name = disk.disk_name.string_().decode("utf-8")
        rq = hex(disk.queue.value_())
        ios = get_inflight_io_nr(prog, disk)
        output.append([str(major), gendisk, name, rq, str(ios)])
    print_table(output)


class InflightIOModule(CorelensModule):
    """Display I/O requests that are currently pending"""

    name = "inflight-io"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--diskname",
            action="store",
            default="all",
            help="Dump in-flight IO from some disk",
        )

    def run(self, prog: drgn.Program, args: argparse.Namespace) -> None:
        dump_inflight_io(prog, args.diskname)


class BlockInfo(CorelensModule):
    """
    Corelens Module for block device info
    """

    name = "blockinfo"

    def run(self, prog: drgn.Program, args: argparse.Namespace) -> None:
        print_block_devs_info(prog)
