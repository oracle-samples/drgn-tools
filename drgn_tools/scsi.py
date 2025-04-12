# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
 Helper to print IO substem useful information from the vmcore or
 live system.
"""
import argparse
from typing import Iterator

from drgn import cast
from drgn import container_of
from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn.helpers.linux.block import _class_to_subsys
from drgn.helpers.linux.block import for_each_disk
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.corelens import CorelensModule
from drgn_tools.module import ensure_debuginfo
from drgn_tools.table import print_table
from drgn_tools.util import has_member


"""
 Dictionary of gendisks being used as hashmap with request_queue address as the key,
 this is need to lookup the disk names for UEK6 or older kernel where gendisk is not
 part of the request_queue structure.
"""
gendisk_map = {}


def for_each_scsi_host(prog: Program) -> Iterator[Object]:
    """
    Iterate through all scsi hosts and returns an
    iterator.
    :returns: an iterator of ``struct Scsi_Host *``
    """
    class_in_private = prog.type("struct device_private").has_member(
        "knode_class"
    )

    subsys_p = _class_to_subsys(prog["shost_class"].address_of_())
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
    returns: the module name string.
    """
    try:
        name = shost.hostt.module.name.string_().decode()
    except FaultError:
        name = "unknown"
    return name


def for_each_scsi_host_device(shost: Object) -> Iterator[Object]:
    """
    Iterates thru all scsi device and returns a scsi_device address
    """
    for scsi_dev in list_for_each_entry(
            "struct scsi_device",
            shost.__devices.address_of_(),
            "siblings"):
        yield scsi_dev


def scsi_device_name(prog: Program, sdev: Object) -> str:
    """
    Get the device name associated with scsi_device.
    :return ``str``
    """
    rq = sdev.request_queue
    dev = container_of(rq.kobj.parent, "struct device", "kobj")
    try:
        return dev.kobj.name.string_().decode()
    except FaultError:
        return ""


def load_gendisk(prog: Program) -> None:
    """
    This method loads the all the gendisk into the global hashmap.
    """
    msg = ensure_debuginfo(prog, ["sd_mod"])
    if msg:
        print(msg)
        return

    for disk in for_each_disk(prog):
        disk_rq = hex(disk.queue)
        gendisk_map[disk_rq] = disk
    return


def scsi_id(scsi_dev: Object) -> str:
    """
    Return Host:Controller:Target:Lun as a string.
    """
    if not scsi_dev:
        return "<unknown>"
    hctl = "[" + str(scsi_dev.host.host_no.value_()) + ":" + \
        str(scsi_dev.channel.value_()) + ":" + \
        str(scsi_dev.id.value_()) + ":" + \
        str(scsi_dev.lun.value_()) + "]"
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
        """
        Since 6eb045e092ef ("scsi: core: avoid host-wide host_busy counter for scsi_mq"),
        host_busy is no longer a member of struct Scsi_Host.
        """
        if host_module_name(shost) == "ahci":
            continue

        if shost.hostt.module.version:
            modver = shost.hostt.module.version.string_().decode()
        else:
            modver = "n/a"

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
                f"host{shost.host_no.value_()}",
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


def print_shost_header(shost: Object) -> None:
    """
    print scsi host header.
    """
    print(
        "--------------------------------------------------"
        "-------------------------------------------------"
    )
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
    print(
        "--------------------------------------------------"
        "-------------------------------------------------"
    )
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
        if host_module_name(shost) == "ahci":
            continue
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
            if prog.type("struct request_queue").has_member("disk"):
                gendisk = cast("struct gendisk *", scsi_dev.request_queue.disk)
                if not gendisk:
                    continue
                diskname = gendisk.disk_name.address_of_().string_().decode()
            else:
                diskname = gendisk_map[hex(scsi_dev.request_queue)].disk_name.string_().decode()

            vendor = scsi_dev.vendor.string_().decode()
            devstate = str(scsi_dev.sdev_state.format_(type_name=False))

            output.append(
                [
                    str(diskname),
                    scsi_id(scsi_dev),
                    hex(scsi_dev),
                    str(vendor),
                    devstate,
                    scsi_dev.iorequest_cnt.counter.value_(),
                    scsi_dev.iodone_cnt.counter.value_(),
                    scsi_dev.ioerr_cnt.counter.value_(),
                ]
            )
        print_table(output)


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

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if args.hosts:
            print_scsi_hosts(prog)
        if args.devices:
            load_gendisk(prog)
            print_shost_devs(prog)
