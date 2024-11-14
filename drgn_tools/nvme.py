# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
from typing import Any
from typing import Iterable
from typing import List

from drgn import cast
from drgn import container_of
from drgn import Object
from drgn import Program
from drgn.helpers.common.type import enum_type_to_class
from drgn.helpers.linux import list_for_each_entry
from drgn.helpers.linux.block import for_each_disk
from drgn.helpers.linux.xarray import xa_for_each

from drgn_tools.block import for_each_hw_queue
from drgn_tools.corelens import CorelensModule
from drgn_tools.module import ensure_debuginfo
from drgn_tools.table import print_table
from drgn_tools.util import enum_name_get


def for_each_nvme_disk(prog: Program) -> Iterable[Object]:
    """
    Return each NVMe device

    :param prog: Program currently debugging
    :returns: iterable of ``struct nvme_ns *`` in the program
    """
    for disk in for_each_disk(prog):
        if disk.disk_name.string_().startswith(b"nvme"):
            yield cast("struct nvme_ns *", disk.private_data)


def show_ns_info(prog: Program) -> None:
    """
    Display namepsace information for each NVMe device
    """
    msg = ensure_debuginfo(prog, ["nvme", "nvme_core"])
    if msg:
        print(msg)
        return
    rows = [["NAME", "NVME_NS", "REFCOUNT", "PI_TYPE", "NVME_NS_FLAG"]]
    for nvme_ns in for_each_nvme_disk(prog):
        if hasattr(nvme_ns.kref.refcount, "refs"):
            refcount = nvme_ns.kref.refcount.refs.counter.value_()
        else:
            refcount = nvme_ns.kref.refcount.counter.value_()

        # In commit b4c1f33a5d59 ("nvme: reorganize nvme_ns_head fields"),
        # pi_type was moved to the nvme_ns_head structure.
        if hasattr(nvme_ns, "pi_type"):
            pi_type = nvme_ns.pi_type.value_()
        else:
            pi_type = nvme_ns.head.pi_type.value_()

        rows.append(
            [
                nvme_ns.disk.disk_name.string_().decode(),
                "{:x}".format(nvme_ns.value_()),
                refcount,
                pi_type,
                nvme_ns.flags.value_(),
            ]
        )
    print_table(rows)


def show_ctrl_info(prog: Program) -> None:
    """
    Display information about each NVMe controller
    """
    msg = ensure_debuginfo(prog, ["nvme", "nvme_core"])
    if msg:
        print(msg)
        return
    NvmeCtrlState = enum_type_to_class(
        prog.type("enum nvme_ctrl_state"), "NvmeCtrlState", prefix="NVME_CTRL_"
    )
    rows: List[List[Any]] = [
        ["NAME", "NVME_CTRL", "NVME_CTRL_STATE", "INSTANCE_ID"]
    ]
    for nvme_ns in for_each_nvme_disk(prog):
        nvme_ns_ctrl_state = nvme_ns.ctrl.state.value_()
        ctrl_state = enum_name_get(
            NvmeCtrlState, nvme_ns_ctrl_state, "UNKNOWN"
        )
        rows.append(
            [
                nvme_ns.disk.disk_name.string_().decode(),
                "{:x}".format(nvme_ns.ctrl.address_of_().value_()),
                ctrl_state,
                nvme_ns.ctrl.instance.value_(),
            ]
        )
    print_table(rows)


def show_firmware_info(prog: Program) -> None:
    """
    Display NVMe firmware information
    """
    msg = ensure_debuginfo(prog, ["nvme", "nvme_core"])
    if msg:
        print(msg)
        return
    rows = [["NAME", "SERIAL#", "MODEL", "FIRMWARE VERSION"]]
    for nvme_ns in for_each_nvme_disk(prog):
        if hasattr(nvme_ns, "head"):
            rows.append(
                [
                    nvme_ns.disk.disk_name.string_().decode(),
                    nvme_ns.head.subsys.serial.string_().decode().strip(),
                    nvme_ns.head.subsys.model.string_().decode().strip(),
                    nvme_ns.head.subsys.firmware_rev.string_().decode(),
                ]
            )
        else:
            rows.append(
                [
                    nvme_ns.disk.disk_name.string_().decode(),
                    "UNSUPPORTED",
                    "UNSUPPORTED",
                    "UNSUPPORTED",
                ]
            )
    print_table(rows)


def show_queue_info(prog: Program) -> None:
    """
    Display details of various allocated NVMe queues
    Value of -1 indicates parameter does not exist in that version

    """
    msg = ensure_debuginfo(prog, ["nvme", "nvme_core"])
    if msg:
        print(msg)
        return
    rows = [
        [
            "NAME",
            "#allocatedQ",
            "#OnlineQ",
            "maxQid",
            "#DefaultQ",
            "#ReadQ",
            "#PollQ",
        ]
    ]
    for nvme_ns in for_each_nvme_disk(prog):
        nvme_dev = container_of(nvme_ns.ctrl, "struct nvme_dev", "ctrl")
        if hasattr(nvme_dev, "nr_allocated_queues"):
            num_q = nvme_dev.nr_allocated_queues.value_()
        else:
            num_q = -1

        if hasattr(nvme_dev, "io_queues"):
            nr_ioqueue_default = nvme_dev.io_queues[0].value_()
            nr_ioqueue_read = nvme_dev.io_queues[1].value_()
            nr_ioqueue_poll = nvme_dev.io_queues[2].value_()
        else:
            nr_ioqueue_default = -1
            nr_ioqueue_read = -1
            nr_ioqueue_poll = -1

        rows.append(
            [
                nvme_ns.disk.disk_name.string_().decode(),
                num_q,
                nvme_dev.online_queues.value_(),
                nvme_dev.max_qid.value_(),
                nr_ioqueue_default,
                nr_ioqueue_read,
                nr_ioqueue_poll,
            ]
        )
    print_table(rows)


def show_queue_map(prog: Program) -> None:
    """
    Display mapping of each NVMe queue, its HW & SW context to the CPU
    """
    msg = ensure_debuginfo(prog, ["nvme", "nvme_core"])
    if msg:
        print(msg)
        return
    for nvme_ns in for_each_nvme_disk(prog):
        print(
            "Queue info for device "
            + nvme_ns.disk.disk_name.string_().decode()
        )
        rows = [["Queue#", "nvmeQ", "hw_ctx", "ctx", "CPU#"]]
        for hw_ctx in for_each_hw_queue(nvme_ns.queue):
            nvmeq = cast("struct nvme_queue *", hw_ctx.driver_data)
            for i in range(hw_ctx.nr_ctx):
                ctx = hw_ctx.ctxs[i]
                rows.append(
                    [
                        hw_ctx.queue_num.value_(),
                        "{:x}".format(nvmeq.value_()),
                        "{:x}".format(hw_ctx.value_()),
                        "{:x}".format(ctx.value_()),
                        ctx.cpu.value_(),
                    ]
                )
        print_table(rows)


def for_each_msi_desc(pdev: Object) -> Iterable[Object]:
    list = None
    if hasattr(pdev, "msi_list"):
        # Older kernels have msi_list in struct pci_dev.
        list = pdev.msi_list
    elif hasattr(pdev.dev, "msi_list"):
        # Starting with 4a7cc8316705 ("genirq/MSI: Move msi_list from struct
        # pci_dev to struct device"), it was moved to struct device
        list = pdev.dev.msi_list
    elif hasattr(pdev.dev.msi.data, "list"):
        # Starting with 125282cd4f33 ("genirq/msi: Move descriptor list to
        # struct msi_device_data"), it was moved again, into the msi_device_data
        # structure.
        list = pdev.dev.msi.data.list

    # Unfortunately, some of the commits below (which switch to an xarray) have
    # been backported without deleting the list_heads above. This leaves a valid
    # list in these structures, but with null next/prev fields. Detect NULL
    # entries here and assume that's the case, falling through to the xarray
    # case.
    if list is not None and list.next:
        return list_for_each_entry(
            "struct msi_desc", list.address_of_(), "list"
        )

    msidata = pdev.dev.msi.data
    prog = msidata.prog_

    if hasattr(msidata, "__store"):
        # And then, the list got turned into an xarray! Wow. cd6cf06590b9
        # ("genirq/msi: Convert storage to xarray")
        xarray = msidata.__store
    else:
        # But wait, there's more. Then, the xarry got split into multiple
        # arrays, one for each MSI domain.
        xarray = msidata.__domains[prog.constant("MSI_DEFAULT_DOMAIN")].store
    return (
        cast("struct msi_desc *", obj)
        for _, obj in xa_for_each(xarray.address_of_())
    )


def show_msi_mask(prog: Program) -> None:
    """
    Display if the MSI has been masked for each NVMe queue
    """
    msg = ensure_debuginfo(prog, ["nvme", "nvme_core"])
    if msg:
        print(msg)
        return

    rows = [["Queue#", "IRQ#", "cq_vector", "MSI mask"]]
    for nvme_ns in for_each_nvme_disk(prog):
        displayDev = (
            "MSI info for device " + nvme_ns.disk.disk_name.string_().decode()
        )
        print(displayDev)
        rows = [["Queue#", "IRQ#", "cq_vector", "MSI mask"]]
        for hw_ctx in for_each_hw_queue(nvme_ns.queue):
            nvmeq = cast("struct nvme_queue *", hw_ctx.driver_data)
            pdev = container_of(nvmeq.dev.dev, "struct pci_dev", "dev")

            for msi_desc in for_each_msi_desc(pdev):
                if hasattr(msi_desc, "pci"):
                    if hasattr(msi_desc.pci.msi_attrib, "entry_nr"):
                        entry_nr = msi_desc.pci.msi_attrib.entry_nr
                    else:
                        entry_nr = msi_desc.msi_index
                else:
                    entry_nr = msi_desc.msi_attrib.entry_nr

                if nvmeq.cq_vector.value_() == entry_nr.value_():
                    row = [
                        nvmeq.qid.value_(),
                        msi_desc.irq.value_(),
                        entry_nr.value_(),
                    ]

                    mask = 0
                    if hasattr(msi_desc, "masked"):
                        mask = msi_desc.masked.value_()
                    elif hasattr(msi_desc, "msix_ctrl"):
                        mask = msi_desc.msix_ctrl.value_()
                    else:
                        mask = msi_desc.pci.msix_ctrl.value_()
                    row.append("{:x}".format(mask))
                    rows.append(row)
        print_table(rows)


class NvmeModule(CorelensModule):
    """Show various details about the NVME subsystem"""

    name = "nvme"
    skip_unless_have_kmod = "nvme"

    debuginfo_kmods = ["nvme", "nvme_core"]

    default_args = [
        [
            "--firmware",
            "--ctrl",
            "--queue",
            "--namespace",
            "--queuemap",
            "--msimask",
        ]
    ]

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--firmware", action="store_true", help="Print firmware info"
        )
        parser.add_argument(
            "--ctrl",
            action="store_true",
            help="Print nvme controller information",
        )
        parser.add_argument(
            "--queue", action="store_true", help="Print nvme queue info"
        )
        parser.add_argument(
            "--namespace",
            action="store_true",
            help="Print nvme namespace info",
        )
        parser.add_argument(
            "--queuemap",
            action="store_true",
            help="Print nvme hw->sw ctx info",
        )
        parser.add_argument(
            "--msimask",
            action="store_true",
            help="Print MSI mask for each nvmeq",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if args.firmware:
            show_firmware_info(prog)
            print()
        if args.ctrl:
            show_ctrl_info(prog)
            print()
        if args.queue:
            show_queue_info(prog)
            print()
        if args.namespace:
            show_ns_info(prog)
            print()
        if args.queuemap:
            show_queue_map(prog)
            print()
        if args.msimask:
            show_msi_mask(prog)
            print()
