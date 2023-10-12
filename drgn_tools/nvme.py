# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
from typing import Iterable

from drgn import container_of
from drgn import Object
from drgn import Program
from drgn.helpers.common.type import enum_type_to_class
from drgn.helpers.linux import list_for_each_entry
from drgn.helpers.linux.block import for_each_disk

from drgn_tools.corelens import CorelensModule
from drgn_tools.module import KernelModule
from drgn_tools.module import load_module_debuginfo
from drgn_tools.util import enum_name_get


def load_modules(prog: Program) -> bool:
    """
    Load nvme modules

    :param prog: drgn program
    :returns: True if module loaded, False if not.
    """
    mods = []
    mod = KernelModule.find(prog, "nvme")
    if not mod:
        print("No nvme module detected.")
        return False
    mods.append(mod)

    mod = KernelModule.find(prog, "nvme-core")
    if not mod:
        print("No nvme-core module detected.")
        return False
    mods.append(mod)

    load_module_debuginfo(prog, mods, extract=True)
    return True


def for_each_nvme_disk(prog: Program) -> Iterable[Object]:
    """
    Return each NVMe device

    :param prog: Program currently debugging
    :returns: iterable of ``struct nvme_ns *`` in the program
    """
    if not load_modules(prog):
        return None
    for disk in for_each_disk(prog):
        if disk.disk_name.string_().decode().startswith("nvme"):
            yield Object(
                prog, "struct nvme_ns *", value=disk.private_data.value_()
            )


def show_ns_info(prog: Program) -> None:
    """
    Display namepsace information for each NVMe device
    """
    if not load_modules(prog):
        return
    fmtHeader = "{:12}{:20}{:10}{:10}{:15}\n"
    fmtValues = "{:12}{:<20x}{:^10}{:^10}{:^15}\n"
    print(
        fmtHeader.format(
            "NAME", "NVME_NS", "REFCOUNT", "PI_TYPE", "NVME_NS_FLAG"
        )
    )
    for nvme_ns in for_each_nvme_disk(prog):
        if hasattr(nvme_ns.kref.refcount, "refs"):
            refcount = nvme_ns.kref.refcount.refs.counter.value_()
        else:
            refcount = nvme_ns.kref.refcount.counter.value_()

        print(
            fmtValues.format(
                nvme_ns.disk.disk_name.string_().decode(),
                nvme_ns.value_(),
                refcount,
                nvme_ns.pi_type.value_(),
                nvme_ns.flags.value_(),
            )
        )


def show_ctrl_info(prog: Program) -> None:
    """
    Display information about each NVMe controller
    """
    if not load_modules(prog):
        return
    fmtHeader = "{:12}{:20}{:15}\n"
    fmtValues = "{:12}{:<20x}{:15}\n"
    NvmeCtrlState = enum_type_to_class(
        prog.type("enum nvme_ctrl_state"), "NvmeCtrlState", prefix="NVME_CTRL_"
    )
    print(
        fmtHeader.format("NAME", "NVME_CTRL", "NVME_CTRL_STATE", "INSTANCE_ID")
    )
    for nvme_ns in for_each_nvme_disk(prog):
        nvme_ns_ctrl_state = nvme_ns.ctrl.state.value_()
        ctrl_state = enum_name_get(
            NvmeCtrlState, nvme_ns_ctrl_state, "UNKNOWN"
        )
        print(
            fmtValues.format(
                nvme_ns.disk.disk_name.string_().decode(),
                nvme_ns.ctrl.address_of_().value_(),
                ctrl_state,
                nvme_ns.ctrl.instance.value_(),
            )
        )


def show_firmware_info(prog: Program) -> None:
    """
    Display NVMe firmware information
    """
    if not load_modules(prog):
        return
    fmtHeader = "{:12}{:20}{:24}{:20}\n"
    fmtValues = "{:12}{:20}{:24}{:20}\n"
    print(fmtHeader.format("NAME", "SERIAL#", "MODEL", "FIRMWARE VERSION"))
    for nvme_ns in for_each_nvme_disk(prog):
        if hasattr(nvme_ns, "head"):
            print(
                fmtValues.format(
                    nvme_ns.disk.disk_name.string_().decode(),
                    nvme_ns.head.subsys.serial.string_().decode().rstrip(),
                    nvme_ns.head.subsys.model.string_().decode().rstrip(),
                    nvme_ns.head.subsys.firmware_rev.string_().decode(),
                )
            )
        else:
            print(
                fmtValues.format(
                    nvme_ns.disk.disk_name.string_().decode(),
                    "UNSUPPORTED",
                    "UNSUPPORTED",
                    "UNSUPPORTED",
                )
            )


def show_queue_info(prog: Program) -> None:
    """
    Display details of various allocated NVMe queues
    Value of -1 indicates parameter does not exist in that version

    """
    if not load_modules(prog):
        return
    fmtHeader = "{:12}{:13}{:10}{:7}{:10}{:10}{:10}\n"
    fmtValues = "{:12}{:^13}{:^10}{:^7}{:^10d}{:^10}{:^10}\n"
    print(
        fmtHeader.format(
            "NAME",
            "#allocatedQ",
            "#OnlineQ",
            "maxQid",
            "#DefaultQ",
            "#ReadQ",
            "#PollQ",
        )
    )
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

        print(
            fmtValues.format(
                nvme_ns.disk.disk_name.string_().decode(),
                num_q,
                nvme_dev.online_queues.value_(),
                nvme_dev.max_qid.value_(),
                nr_ioqueue_default,
                nr_ioqueue_read,
                nr_ioqueue_poll,
            )
        )


def show_queue_map(prog: Program) -> None:
    """
    Display mapping of each NVMe queue, its HW & SW context to the CPU
    """
    if not load_modules(prog):
        return
    fmtHeader = "{:^10}{:^20}{:^20}{:^20}{:^10}"
    fmtValues = "{:^10}{:20x}{:20x}{:20x}{:^10}"
    for nvme_ns in for_each_nvme_disk(prog):
        displayDev = (
            "Queue info for device "
            + nvme_ns.disk.disk_name.string_().decode()
        )
        print(displayDev)
        print(fmtHeader.format("Queue#", "nvmeQ", "hw_ctx", "ctx", "CPU#"))
        for nr in range(nvme_ns.queue.nr_hw_queues):
            hw_ctx = Object(
                prog,
                "struct blk_mq_hw_ctx",
                address=nvme_ns.queue.queue_hw_ctx[nr],
            )
            nvmeq = Object(
                prog, "struct nvme_queue", address=hw_ctx.driver_data.value_()
            )
            for i in range(hw_ctx.nr_ctx):
                ctx = Object(prog, "struct blk_mq_ctx", address=hw_ctx.ctxs[i])
                print(
                    fmtValues.format(
                        hw_ctx.queue_num.value_(),
                        nvmeq.address_of_().value_(),
                        hw_ctx.address_of_().value_(),
                        ctx.address_of_().value_(),
                        ctx.cpu.value_(),
                    )
                )


def show_msi_mask(prog: Program) -> None:
    """
    Display if the MSI has been masked for each NVMe queue
    """
    if not load_modules(prog):
        return
    fmtHeader = "{:^10}{:^10}{:^0}{:^10}"
    fmtValues = "{:^10}{:^10}{:^10}{:^10x}"
    for nvme_ns in for_each_nvme_disk(prog):
        displayDev = (
            "MSI info for device " + nvme_ns.disk.disk_name.string_().decode()
        )
        print(displayDev)
        print(fmtHeader.format("Queue#", "IRQ#", "cq_vector", "MSI mask"))
        for nr in range(nvme_ns.queue.nr_hw_queues):
            hw_ctx = Object(
                prog,
                "struct blk_mq_hw_ctx",
                address=nvme_ns.queue.queue_hw_ctx[nr],
            )
            nvmeq = Object(
                prog, "struct nvme_queue", address=hw_ctx.driver_data.value_()
            )
            pdev = container_of(nvmeq.dev.dev, "struct pci_dev", "dev")

            if hasattr(pdev.dev, "msi_list"):
                msi_holder = pdev.dev
            else:
                msi_holder = pdev

            for msi_desc in list_for_each_entry(
                "struct msi_desc", msi_holder.msi_list.address_of_(), "list"
            ):
                if (
                    nvmeq.cq_vector.value_()
                    == msi_desc.msi_attrib.entry_nr.value_()
                ):
                    if hasattr(msi_desc, "masked"):
                        print(
                            fmtValues.format(
                                nvmeq.qid.value_(),
                                msi_desc.irq.value_(),
                                msi_desc.msi_attrib.entry_nr.value_(),
                                msi_desc.masked.value_(),
                            )
                        )
                    else:
                        print(
                            fmtValues.format(
                                nvmeq.qid.value_(),
                                msi_desc.irq.value_(),
                                msi_desc.msi_attrib.entry_nr.value_(),
                                msi_desc.msix_ctrl.value_(),
                            )
                        )


class NvmeModule(CorelensModule):
    """Show various details about the NVME subsystem"""

    name = "nvme"
    skip_unless_have_kmod = "nvme"

    default_args = [
        "--firmware",
        "--ctrl",
        "--queue",
        "--namespace",
        "--queuemap",
        "--msimask",
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
        if args.ctrl:
            show_ctrl_info(prog)
        if args.queue:
            show_queue_info(prog)
        if args.namespace:
            show_ns_info(prog)
        if args.queuemap:
            show_queue_map(prog)
        if args.msimask:
            show_msi_mask(prog)
