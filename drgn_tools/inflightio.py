# Copyright (c) 2023-2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers to dump inflight IO.
"""
import argparse

import drgn

from drgn_tools.block import for_each_disk
from drgn_tools.block import for_each_mq_pending_request
from drgn_tools.block import for_each_sq_pending_request
from drgn_tools.block import request_target
from drgn_tools.block import rq_flags
from drgn_tools.block import rq_op
from drgn_tools.block import rq_pending_time_ns
from drgn_tools.block import show_rq_issued_cpu
from drgn_tools.corelens import CorelensModule
from drgn_tools.nvme import for_each_nvme_ctrl
from drgn_tools.util import has_member
from drgn_tools.util import timestamp_str


def dump_nvme_mgmt_inflight_io(prog: drgn.Program, qtype: str) -> None:
    """
    Dump inflight io from NVMe's management queue

    :param prog: drgn program
    :param qtype: managment queue name, "admin", "connect" or "fabrics"
    """
    for ctrl in for_each_nvme_ctrl(prog):
        if qtype == "admin" and ctrl.admin_q.value_():
            q = ctrl.admin_q
            name = "nvme" + str(ctrl.instance.value_()) + "-admin"
        elif (
            # commit 07bfcd09a288 ("nvme-fabrics: add a generic NVMe over Fabrics library")
            # since v4.8
            qtype == "connect"
            and has_member(ctrl, "connect_q")
            and ctrl.connect_q.value_()
        ):
            q = ctrl.connect_q
            name = "nvme" + str(ctrl.instance.value_()) + "-connect"
        elif (
            # commit e7832cb48a65 ("nvme: make fabrics command run on a separate request queue")
            # since v5.4
            qtype == "fabrics"
            and has_member(ctrl, "fabrics_q")
            and ctrl.fabrics_q.value_()
        ):
            q = ctrl.fabrics_q
            name = "nvme" + str(ctrl.instance.value_()) + "-fabrics"
        else:
            return

        mq_pending = [
            (hwq.value_(), hwq[0].read_(), rq.value_(), rq[0].read_())
            for hwq, rq in for_each_mq_pending_request(q)
        ]
        for hwq_ptr, hwq, rq_ptr, rq in mq_pending:
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

    # dump nvme management inflight IO
    if diskname == "all":
        dump_nvme_mgmt_inflight_io(prog, "admin")
        dump_nvme_mgmt_inflight_io(prog, "connect")
        dump_nvme_mgmt_inflight_io(prog, "fabrics")


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
