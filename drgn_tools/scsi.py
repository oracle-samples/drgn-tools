# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
 Helper to print SCSI subsytem useful information from the vmcore or
 live system.
"""
import argparse
import enum
from typing import Iterator

from drgn import cast
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
from drgn_tools.table import FixedTable
from drgn_tools.table import print_dictionary
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


def scsi_host(prog: Program, disk: Object) -> Object:
    diskname = disk.disk_name.string_().decode()
    if not diskname.startswith("sd"):
        return None
    q = disk.queue
    sdev = Object(prog, "struct scsi_device *", value=q.queuedata.value_())
    return sdev.host


def scsi_disk_driver(prog: Program, disk: Object) -> str:
    return host_module_name(scsi_host(prog, disk))


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


def print_scsi_hosts(prog: Program, verbose: bool = False) -> None:
    """
    Prints scsi host information
    """
    print("-" * 120)
    # Use FixedTable so that each row is printed immediately.
    table = FixedTable(
        header=[
            "SCSI_HOST",
            "NAME",
            "DRIVER",
            "Version",
            "Busy",
            "Blocked",
            "Fail",
            "State",
            "EH val",
            "cmd/lun",
            "hwq",
        ]
    )

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

        table.row(
            hex(shost.value_()),
            f"host{shost.host_no.value_():>}",
            host_module_name(shost),
            modver,
            host_busy,
            shost.host_blocked.counter.value_(),
            shost.host_failed.value_(),
            shost.shost_state.format_(type_name=False),
            eh_deadline,
            shost.cmd_per_lun.value_(),
            shost.nr_hw_queues.value_(),
        )
        if verbose:
            print("-" * 120)
            try:
                if host_module_name(shost) == "qla2xxx":
                    print_qla2xxx_shost_info(prog, shost)
                elif host_module_name(shost) == "lpfc":
                    print_lpfc_shost_info(prog, shost)
                elif host_module_name(shost) == "megaraid_sas":
                    print_megaraid_shost_info(prog, shost)
            except ValueError:
                print(
                    "Details Unavailable for Scsi_Host: {} ({:x})".format(
                        shost.shost_gendev.kobj.name.string_().decode(),
                        shost.value_(),
                    )
                )

    if not verbose:
        print("-" * 120)
        print(
            "  Run with -v or --verbose for more Host HBA specific information."
        )


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


def fc_hba_port_attr(shost: Object) -> Object:
    return cast("struct fc_host_attrs *", shost.shost_data)


def print_port_addr(fc_host_attrs: Object) -> None:
    if fc_host_attrs:  # NULL check
        print("{:<20}: 0x{:x}".format("fc_host_attrs", fc_host_attrs.value_()))
        print(
            "{:<20}: 0x{:x}".format(
                "node_name (wwn)", fc_host_attrs.node_name.value_()
            )
        )
        print(
            "{:<20}: 0x{:x}".format(
                "port_name (wwpn)", fc_host_attrs.port_name.value_()
            )
        )
    else:
        print("Port attributes are NULL\n")


def print_megaraid_shost_info(prog: Program, shost: Object) -> None:
    """
    print MegaRAID-specific host details, if available.
    """
    try:
        prog.module("megaraid_sas")
    except LookupError:
        return

    msg = ensure_debuginfo(prog, ["megaraid_sas"])
    if msg:
        print("megaraid_sas debuginfo not loaded!")
        return

    megasas_inst = cast("struct megasas_instance *", shost.hostdata)
    if not megasas_inst:
        return

    output = {}

    print("\nMegaRAID SAS HBA specific details\n")
    output["megasas_instance"] = hex(megasas_inst.value_())
    output["megasas_ctrl_info"] = hex(megasas_inst.ctrl_info_buf.value_())
    output[
        "serial_no"
    ] = megasas_inst.ctrl_info_buf.serial_no.string_().decode()
    output[
        "product_name"
    ] = megasas_inst.ctrl_info_buf.product_name.string_().decode()
    output[
        "package_version"
    ] = megasas_inst.ctrl_info_buf.package_version.string_().decode()
    output["pci_dev"] = hex(megasas_inst.pdev.value_())
    output["pci_dev slot"] = megasas_inst.pdev.dev.kobj.name.string_().decode()
    output["ld_ids"] = megasas_inst.ld_ids.value_()
    output["max_num_sge"] = megasas_inst.max_num_sge.value_()
    output["max_fw_cmds"] = megasas_inst.max_fw_cmds.value_()
    output["max_mpt_cmds"] = megasas_inst.max_mpt_cmds.value_()
    output["max_mfi_cmds"] = megasas_inst.max_mfi_cmds.value_()
    output["max_scsi_cmds"] = megasas_inst.max_scsi_cmds.value_()
    output["ldio_threshold"] = megasas_inst.ldio_threshold.value_()
    output["cur_can_queue"] = megasas_inst.cur_can_queue.value_()
    output["max_sectors_per_req"] = megasas_inst.max_sectors_per_req.value_()
    output["fw_outstanding"] = megasas_inst.fw_outstanding.counter.value_()
    output["ldio_outstanding"] = megasas_inst.ldio_outstanding.counter.value_()
    output[
        "fw_reset_no_pci_access"
    ] = megasas_inst.fw_reset_no_pci_access.counter.value_()
    output["total_io_count"] = megasas_inst.total_io_count.counter.value_()
    output[
        "high_iops_outstanding"
    ] = megasas_inst.high_iops_outstanding.counter.value_()
    output["megasas_inst.flag"] = megasas_inst.flag.value_()
    output["issuepend_done"] = megasas_inst.issuepend_done.value_()
    output[
        "disableOnlineCtrlReset"
    ] = megasas_inst.disableOnlineCtrlReset.value_()
    output["adprecovery"] = megasas_inst.adprecovery.counter.value_()
    output[
        "fw_supported_vd_count"
    ] = megasas_inst.fw_supported_vd_count.value_()
    output[
        "fw_supported_pd_count"
    ] = megasas_inst.fw_supported_pd_count.value_()
    output[
        "drv_supported_vd_count"
    ] = megasas_inst.drv_supported_vd_count.value_()
    output[
        "drv_supported_pd_count"
    ] = megasas_inst.drv_supported_pd_count.value_()
    output["reset_flags"] = megasas_inst.reset_flags.value_()
    output["throttle queue depth"] = megasas_inst.throttlequeuedepth.value_()
    output["adapter_type"] = megasas_inst.adapter_type.format_(type_name=False)
    output[
        "support_nvme_passthru"
    ] = megasas_inst.support_nvme_passthru.value_()
    output["task_abort_tmo"] = megasas_inst.task_abort_tmo.value_()
    output["max_reset_tmo"] = megasas_inst.max_reset_tmo.value_()
    output["perf_mode"] = megasas_inst.perf_mode.format_(type_name=False)
    print_dictionary(output)
    print("-" * 120)


def print_lpfc_shost_info(prog: Program, shost: Object) -> None:
    """
    print lpfc HBA specific information.
    """
    print("\nFC/FCoE HBA attributes")
    print("----------------------")

    port_attr = fc_hba_port_attr(shost)
    print_port_addr(port_attr)

    print("\nEmulex HBA specific details")
    print("---------------------------")

    output = {}

    lpfc_vport = cast("struct lpfc_vport *", shost.hostdata)
    if lpfc_vport:
        lpfc_hba = lpfc_vport.phba

        output["lpfc_vport"] = hex(lpfc_vport.value_())
        output["lpfc_hba"] = hex(lpfc_hba.value_())
        output["sli_ver"] = lpfc_hba.sli_rev.value_()
        output["pci_dev"] = hex(lpfc_hba.pcidev.value_())
        output[
            "pci_dev slot"
        ] = lpfc_hba.pcidev.dev.kobj.name.string_().decode()
        output["board no"] = lpfc_hba.brd_no.value_()
        output["Serial no"] = lpfc_hba.SerialNumber.string_().decode()
        output[
            "OptionROMVersion"
        ] = lpfc_hba.OptionROMVersion.string_().decode()
        output["BIOSVersion"] = lpfc_hba.BIOSVersion.string_().decode()
        output["Program Type"] = lpfc_hba.ProgramType.string_().decode()
        output["ModelDesc"] = lpfc_hba.ModelDesc.string_().decode()
        output["ModelName"] = lpfc_hba.ModelName.string_().decode()
        output["cfg_hba_queue_depth"] = lpfc_hba.cfg_hba_queue_depth.value_()
        output["cfg_lun_queue_depth"] = lpfc_vport.cfg_lun_queue_depth.value_()
        if prog.type("struct lpfc_vport").has_member("cfg_tgt_queue_depth"):
            output[
                "cfg_tgt_queue_depth"
            ] = lpfc_vport.cfg_tgt_queue_depth.value_()
    else:
        print("Need to fetch standard queue data")

    print_dictionary(output)
    print("-" * 120)


def print_qla2xxx_shost_info(prog: Program, shost: Object) -> None:
    """
    print QLogic qla2xxx HBA specific information.
    """

    print("\nFC/FCoE HBA attributes")
    print("----------------------")

    port_attr = fc_hba_port_attr(shost)
    print_port_addr(port_attr)

    print("\nQLogic HBA specific details")
    print("---------------------------")

    output = {}

    scsi_qla_host = cast("struct scsi_qla_host *", shost.hostdata)
    if scsi_qla_host:
        qla_hw_data = cast("struct qla_hw_data *", scsi_qla_host.hw)

        output["scsi_qla_host"] = hex(scsi_qla_host.value_())
        output["qla_hw_data"] = hex(qla_hw_data.value_())
        output["pci_dev"] = hex(qla_hw_data.pdev.value_())
        output[
            "pci_dev slot"
        ] = qla_hw_data.pdev.dev.kobj.name.string_().decode()
        output["operating_mode"] = qla_hw_data.operating_mode.value_()
        output["model_desc"] = qla_hw_data.model_desc.string_().decode()
        output["FW version"] = (
            f"{qla_hw_data.fw_major_version.value_()}."
            f"{qla_hw_data.fw_minor_version.value_()}."
            f"{qla_hw_data.fw_subminor_version.value_()}"
        )
        output["fw_dumped"] = qla_hw_data.fw_dumped.value_()
        output["ql2xmaxqdepth"] = prog["ql2xmaxqdepth"].value_()
    else:
        print("Unable to fetch QLogic HBA details")
    print_dictionary(output)
    print("-" * 120)


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


def print_inflight_scsi_cmnds(prog: Program) -> None:
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

            if counter > 0:
                TotalInflight += counter
                print_table(output)
                print("-" * 115)
    print(f" Total inflight commands across all disks : {TotalInflight}")
    print("-" * 115)


class ScsiInfo(CorelensModule):
    """
    Corelens Module for scsi device information
    """

    name = "scsiinfo"

    debuginfo_kmods = ["sd_mod", "megaraid_sas", "qla2xxx", "lpfc"]

    default_args = [
        [
            "--hosts",
            "--devices",
            "--queue",
            "--verbose",
        ]
    ]

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--hosts",
            "-s",
            action="store_true",
            help="Print SCSI Hosts",
        )
        parser.add_argument(
            "--devices",
            "-d",
            action="store_true",
            help="Print SCSI Devices",
        )
        parser.add_argument(
            "--queue",
            "-q",
            action="store_true",
            help="Print Inflight SCSI commands",
        )
        parser.add_argument(
            "--verbose",
            "-v",
            action="store_true",
            help="print verbose",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if args.hosts:
            print_scsi_hosts(prog, verbose=args.verbose)
        elif args.devices:
            print_shost_devs(prog)
        elif args.queue:
            print_inflight_scsi_cmnds(prog)
        else:
            print_scsi_hosts(prog, verbose=args.verbose)
