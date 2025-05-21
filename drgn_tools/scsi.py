# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
 Helper to print SCSI subsytem useful information from the vmcore or
 live system.
"""
import argparse
import enum
from typing import Iterator

from drgn import container_of
from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn import sizeof
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.block import for_each_mq_pending_request
from drgn_tools.block import for_each_sq_pending_request
from drgn_tools.block import is_mq
from drgn_tools.block import request_target
from drgn_tools.corelens import CorelensModule
from drgn_tools.device import class_to_subsys
from drgn_tools.module import ensure_debuginfo
from drgn_tools.table import print_table
from drgn_tools.util import has_member
from drgn_tools.util import timestamp_str


class Opcode(enum.Enum):
    TUR = 0x00
    READ_6 = 0x8
    WRITE_6 = 0xA
    INQUIRY = 0x12
    READ_10 = 0x28
    WRITE_10 = 0x2A


def for_each_scsi_host(prog: Program) -> Iterator[Object]:
    """
    Iterate through all scsi hosts and returns an iterator.

    :returns: an iterator of ``struct Scsi_Host *``
    """
    class_in_private = prog.type("struct device_private").has_member(
        "knode_class"
    )

    subsys_p = class_to_subsys(prog["shost_class"].address_of_())
    devices = subsys_p.klist_devices.k_list.address_of_()

    if class_in_private:
        for device_private in list_for_each_entry(
            "struct device_private", devices, "knode_class.n_node"
        ):
            dev = device_private.device
            yield container_of(dev, "struct Scsi_Host", "shost_dev")
    else:
        for dev in list_for_each_entry(
            "struct device", devices, "knode_class.n_node"
        ):
            yield container_of(dev, "struct Scsi_Host", "shost_dev")


def host_module_name(shost: Object) -> str:
    """
    Fetch the module name associated with the scsi host.

    :param shost: ``struct Scsi_Host *``
    :returns: the module name string.
    """
    try:
        name = shost.hostt.module.name.string_().decode()
    except FaultError:
        name = "unknown"
    return name


def for_each_scsi_host_device(shost: Object) -> Iterator[Object]:
    """
    Iterates thru all scsi device and returns a scsi_device address

    :param shost: ``struct Scsi_Host *``
    :returns: an iterator of ``struct scsi_device *``
    """
    for scsi_dev in list_for_each_entry(
        "struct scsi_device", shost.__devices.address_of_(), "siblings"
    ):
        yield scsi_dev


def scsi_device_name(sdev: Object) -> str:
    """
    Get the device name associated with scsi_device.

    :param sdev: ``struct scsi_device *``
    :returns: ``str``
    """
    rq = sdev.request_queue
    if has_member(rq, "mq_kobj"):
        # uek5 thru uek8 has mq_obj with upstream commit id 320ae51fee
        dev = container_of(rq.mq_kobj.parent, "struct device", "kobj")
    if has_member(rq, "kobj"):
        dev = container_of(rq.kobj.parent, "struct device", "kobj")
    try:
        return dev.kobj.name.string_().decode()
    except FaultError:
        return ""


def for_each_scsi_cmnd(prog: Program, scsi_device: Object) -> Iterator[Object]:
    """
    Iterates thru all scsi commands for a given SCSI device.

    :param scsi_device: ``struct scsi_device *``
    :returns: an iterator of ``struct scsi_cmnd *``
    """
    q = scsi_device.request_queue
    if is_mq(q):
        for scmnd in for_each_scsi_cmd_mq(prog, scsi_device):
            yield scmnd
    else:
        for scmnd in for_each_scsi_cmd_sq(prog, scsi_device):
            yield scmnd


def rq_to_scmnd(prog: Program, rq: Object) -> Object:
    """
    Fetch the scsi_cmnd from request address

    :param rq: ``struct request_queue *``
    :returns: Object of ``struct scsi_cmnd *``
    """
    scmnd = rq.value_() + sizeof(prog.type("struct request"))
    return Object(prog, "struct scsi_cmnd *", value=scmnd)


def for_each_scsi_cmd_sq(prog: Program, dev: Object) -> Iterator[Object]:
    """
    Iterates thru all SCSI commands from the block layer pending requests.

    :param dev: ``strcut scsi_device *``
    :returns: an iterator of ``struct scsi_cmnd *``
    """
    q = dev.request_queue
    for rq in for_each_sq_pending_request(q):
        yield rq_to_scmnd(prog, rq)


def for_each_scsi_cmd_mq(prog: Program, dev: Object) -> Iterator[Object]:
    """
    Iterates thru all SCSI commands in all multi hardware queue.

    :param dev: ``strcut scsi_device *``
    :returns: an iterator of ``struct scsi_cmnd *``
    """
    try:
        BLK_MQ_F_TAG_SHARED = prog.constant("BLK_MQ_F_TAG_SHARED")
    except LookupError:
        BLK_MQ_F_TAG_SHARED = prog.constant("BLK_MQ_F_TAG_QUEUE_SHARED")

    q = dev.request_queue
    disk = dev.request_queue.disk
    for hwq, rq in for_each_mq_pending_request(q):
        if (hwq.flags & BLK_MQ_F_TAG_SHARED) != 0 and request_target(
            rq
        ).value_() != disk.value_():
            continue
        yield rq_to_scmnd(prog, rq)


def scsi_id(scsi_dev: Object) -> str:
    """
    Fetch SCSI id of the device.

    :param scsi_dev: ``struct scsi_device *``
    :returns: ``str``
    """
    if not scsi_dev:
        return "<unknown>"
    hctl = (
        "["
        + str(scsi_dev.host.host_no.value_())
        + ":"
        + str(scsi_dev.channel.value_())
        + ":"
        + str(scsi_dev.id.value_())
        + ":"
        + str(scsi_dev.lun.value_())
        + "]"
    )
    return hctl


def print_scsi_hosts(prog: Program) -> None:
    """
    Prints scsi host information
    """
    output = [
        [
            "SCSI_HOST",
            "NAME",
            "DRIVER",
            "Version",
            "Busy",
            "Blocked",
            "Fail",
            "State",
            "EH val",
        ]
    ]

    for shost in for_each_scsi_host(prog):
        if shost.hostt.module.version:
            modver = shost.hostt.module.version.string_().decode()
        else:
            modver = "n/a"

        """
        Since 6eb045e092ef ("scsi: core: avoid host-wide host_busy counter for scsi_mq"),
        host_busy is no longer a member of struct Scsi_Host.
        """
        if has_member(shost, "host_busy"):
            host_busy = shost.host_busy.counter.value_()
        else:
            host_busy = "n/a"

        if has_member(shost, "eh_deadline"):
            eh_deadline = shost.eh_deadline.value_()
        else:
            eh_deadline = "n/a"

        output.append(
            [
                hex(shost.value_()),
                f"host{shost.host_no.value_():>}",
                host_module_name(shost),
                modver,
                host_busy,
                shost.host_blocked.counter.value_(),
                shost.host_failed.value_(),
                shost.shost_state.format_(type_name=False),
                eh_deadline,
            ]
        )
    print_table(output)
    return


def print_shost_header(shost: Object) -> None:
    """
    print scsi host header.
    """
    print("-" * 110)
    output = [
        [
            "HOST",
            "DRIVER",
            "Scsi_Host",
            "shost_data",
            "hostdata",
        ]
    ]

    shostdata = hex(shost.shost_data.address_of_().value_())
    hostdata = hex(shost.hostdata.address_of_().value_())
    output.append(
        [
            shost.shost_gendev.kobj.name.string_().decode(),
            host_module_name(shost),
            hex(shost),
            shostdata,
            hostdata,
        ]
    )
    print_table(output)
    print("-" * 110)
    return


def print_shost_devs(prog: Program) -> None:
    """
    print all scsi devices for a Scsi_Host
    """
    msg = ensure_debuginfo(prog, ["sd_mod"])
    if msg:
        print(msg)
        return

    for shost in for_each_scsi_host(prog):
        print_shost_header(shost)
        output = [
            [
                "Device",
                "H:C:T:L",
                "Scsi Device Addr",
                "Vendor",
                "State",
                "IO Req",
                "IO Done",
                "IO Error",
            ]
        ]

        for scsi_dev in for_each_scsi_host_device(shost):
            vendor = scsi_dev.vendor.string_().decode()
            devstate = str(scsi_dev.sdev_state.format_(type_name=False))

            output.append(
                [
                    scsi_device_name(scsi_dev),
                    scsi_id(scsi_dev),
                    hex(scsi_dev),
                    str(vendor),
                    devstate,
                    f"{scsi_dev.iorequest_cnt.counter.value_():>7}",
                    f"{scsi_dev.iodone_cnt.counter.value_():>7}",
                    f"{scsi_dev.ioerr_cnt.counter.value_():>4}",
                ]
            )
        print_table(output)


def print_inflight_scsi_cmnds(prog: Program):
    """
    print all inflight SCSI commands for all SCSI devices.
    """
    TotalInflight = 0
    for shost in for_each_scsi_host(prog):
        for scsi_dev in for_each_scsi_host_device(shost):
            diskname = scsi_device_name(scsi_dev)

            counter = 0
            output = [
                [
                    "Count",
                    "Request",
                    "Bio",
                    "SCSI Cmnd",
                    "Opcode",
                    "Length",
                    "Age",
                    "Sector",
                ]
            ]

            for scsi_cmnd in for_each_scsi_cmnd(prog, scsi_dev):
                if counter == 0:
                    vendor = scsi_dev.vendor.string_().decode()
                    devstate = str(
                        scsi_dev.sdev_state.format_(type_name=False)
                    )
                    scsiid = scsi_id(scsi_dev)

                    print(
                        f" Diskname : {diskname} {scsiid}\t\t\tSCSI Device Addr : {hex(scsi_dev.value_())}"
                    )
                    print(
                        f" Vendor   : {vendor}    \tDevice State\t : {devstate}"
                    )
                    print("-" * 115)

                if has_member(scsi_cmnd, "request"):
                    req = scsi_cmnd.request
                else:
                    reqp = scsi_cmnd.value_() - sizeof(
                        prog.type("struct request")
                    )
                    req = Object(prog, "struct request *", value=reqp)

                try:
                    opcode = Opcode(scsi_cmnd.cmnd[0].value_()).name
                except ValueError:
                    opcode = str(hex(scsi_cmnd.cmnd[0].value_()))

                if scsi_cmnd.cmnd[0] == 0x2A or scsi_cmnd.cmnd[0] == 0x28:
                    xfer_len = (
                        scsi_cmnd.cmnd[7] << 8 | scsi_cmnd.cmnd[8]
                    ) * scsi_cmnd.transfersize
                else:
                    xfer_len = 0

                if req.bio:
                    if has_member(req.bio, "bi_sector"):
                        sector = req.bio.bi_sector
                    else:
                        sector = req.bio.bi_iter.bi_sector
                else:
                    sector = 0

                age = (
                    prog["jiffies"] - scsi_cmnd.jiffies_at_alloc
                ).value_() * 1000000
                counter += 1

                output.append(
                    [
                        f"{counter:>4}",
                        hex(req.value_()),
                        hex(req.bio.value_()),
                        hex(scsi_cmnd.value_()),
                        opcode,
                        f"{int(xfer_len):>7}",
                        timestamp_str(age),
                        f"{int(sector):>11}",
                    ]
                )

            if counter > 1:
                TotalInflight += counter
                print_table(output)
                print("-" * 115)
    print(f" Total inflight commands across all disks : {TotalInflight}")
    print("-" * 115)
    return


class ScsiInfo(CorelensModule):
    """
    Corelens Module for scsi device information
    """

    name = "scsiinfo"

    debuginfo_kmods = ["sd_mod"]

    default_args = [
        [
            "--hosts",
            "--devices",
            "--queue",
        ]
    ]

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--hosts",
            action="store_true",
            help="Print Scsi Hosts",
        )
        parser.add_argument(
            "--devices",
            action="store_true",
            help="Print Scsi Devices",
        )
        parser.add_argument(
            "--queue",
            action="store_true",
            help="Print Inflight SCSI commands",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if args.hosts:
            print_scsi_hosts(prog)
        elif args.devices:
            print_shost_devs(prog)
        elif args.queue:
            print_inflight_scsi_cmnds(prog)
        else:
            print_scsi_hosts(prog)
