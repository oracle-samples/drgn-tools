# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for dumping virtio device information
"""
import argparse
import typing as t
from collections import namedtuple

from drgn import container_of
from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.corelens import CorelensModule
from drgn_tools.device import bus_to_subsys
from drgn_tools.logging import get_logger
from drgn_tools.util import has_member

try:
    # drgn v0.21.0+
    from drgn.helpers.common import escape_ascii_string
except ImportError:
    # drgn <v0.21.0
    from drgn.helpers import escape_ascii_string


__all__ = [
    "load_virtio_mods",
    "for_each_virtio",
    "for_each_device_virtio",
    "virtio_devices_show",
    "for_each_vring_by_vdev",
    "get_virtio_dev_vrings",
    "get_vring_info",
    "vrings_show",
    "virtio_show",
    "VirtioQueueInfo",
]


VirtioQueueInfo = namedtuple(
    "VirtioQueueInfo",
    [
        "vq_name",
        "vq_address",
        "vring_addr",
        "vring_avail_addr",
        "vring_used_addr",
        "nr_ent",
        "last_used_idx",
        "avail_idx_shadow",
        "avail_idx",
        "used_idx",
        "event",
    ],
)
"""
Represents information about a virtqueue (or vring)

Since there are multiple formats that a vring_virtqueue could take depending on
kernel version, this namedtuple represents common elements. See
:func:`get_vring_info()` for more information.
"""


# Modules which will register virtio_driver by register_virtio_driver().
#   Key:  Name of module in lsModule()
#   Data: [0]: symbol of virtio_driver
#         [1]: Struct of virtio_device->priv
virtio_mod_drv = {
    "virtio_console": [
        "virtio_console",
        "ports_device",
    ],
    "virtio_blk": ["virtio_blk", "virtio_blk"],
    "virtio_rng": ["virtio_rng_driver", "virtrng_info"],
    "virtio_crypto": [
        "virtio_crypto_driver",
        "virtio_crypto",
    ],
    "virtio_gpu": ["virtio_gpu_driver", "drm_device"],
    "virtio_iommu": ["virtio_iommu_drv", "viommu_dev"],
    "caif_virtio": ["caif_virtio_driver", "cfv_info"],
    "virtio_net": ["virtio_net_driver", "virtnet_info"],
    "virtio_pmem": ["virtio_pmem_driver", "virtio_pmem"],
    "virtio_rpmsg_bus": ["virtio_ipc_driver", "virtproc_info"],
    "virtio_scsi": ["virtio_scsi_driver", "Scsi_Host"],
    "virtio_balloon": ["virtio_balloon_driver", "virtio_balloon"],
    "virtio_input": ["virtio_input_driver", "virtio_input"],
    "virtio_fs": ["virtio_fs_driver", "virtio_fs"],
    "vmw_vsock_virtio_transport": ["virtio_vsock_driver", "virtio_vsock"],
    "9pnet_virtio": ["p9_virtio_drv", "virtio_chan"],
    "virtio": ["", ""],
    "virtio_ring": ["", ""],
    "virtio_pci": ["", ""],
    "virtio_pci_modern_dev": ["", ""],
    "virtio_pci_legacy": ["" ""],
}

log = get_logger("drgn_tools.virtio")


def get_virtio_driver(prog: Program, mod: str) -> t.Optional[Object]:
    """
    Get ``struct virtio_driver`` by module name

    NOTE: virtio_pci, virtio_pci_modern_dev and virtio_pci_legacy
          are virtio pci infra and they don't havs virtio_driver.

    :param prog: Program we're debugging
    :param mod: name of virtio module
    :returns: symbol of driver if found, otherwise None
    """
    sym = virtio_mod_drv[mod][0]
    if sym:
        return prog[sym]
    return None


def load_virtio_mods(prog: Program) -> t.List[str]:
    """
    Lookup the list of virtio-related kernel modules and ensure debuginfo is
    loaded for each one.

    :param prog: Program we're debugging
    :returns: list of virtio-related modules
    :raises Exception: if the debuginfo isn't already loaded and we couldn't
      find the file for it
    """
    to_load = []
    mods = []
    for modname in virtio_mod_drv.keys():
        try:
            mod = prog.module(modname)
        except LookupError:
            continue
        mods.append(mod.name)
        if mod.wants_debug_file():
            to_load.append(mod)
    prog.load_module_debug_info(*to_load)
    return mods


def get_virtio_devices(virtio_drv: Object) -> t.List[Object]:
    """
    Get all ``struct device *`` which are linked by a driver's virtio_bus.

    :param virtio_drv: Object of ``struct virtio_driver``
    :returns: List of all virtio device's ``struct device *``
    """
    # virtio_driver -> device_driver -> bus_type
    bus_type = virtio_drv.driver.bus
    subsys_p = bus_to_subsys(bus_type)

    # Get the "struct list_head *" of the list of all devices for this
    # subsys_private.
    list_devs = subsys_p.klist_devices.k_list.address_of_()

    # Build a Python list of the struct devices
    devs = []
    for priv_dev in list_for_each_entry(
        "struct device_private",
        list_devs,
        "knode_bus.n_node",
    ):
        devs.append(priv_dev.device)

    return devs


def for_each_device_virtio(
    prog: Program,
    virtio_mods: t.List[str],
    vd_name: t.Optional[str] = None,
) -> t.List[Object]:
    """
    Generate ``struct device *`` list for all virtio device

    :param prog: Program we're debugging
    :param virtio_mods: virtio kernel module list that has loaded debuginfo
    :param vd_name: optional device name to filter
    :returns: all virtio devices
    """
    for mod in virtio_mods:
        log.debug("** MOD: %s" % mod)
        virtio_drv = get_virtio_driver(prog, mod)
        if virtio_drv is not None:
            devs = get_virtio_devices(virtio_drv)
            if devs:
                # All virtio devices linked on virtio_bus, run it once
                # will get all virtio devices on the list.
                break
    else:
        # didn't hit the break condition above
        return []

    # Apply the vd_name filter
    if vd_name:
        devs = [d for d in devs if get_device_name(d) == vd_name]

    return devs


def for_each_virtio(
    prog: Program,
    virtio_mods: t.List[str],
    vd_name: t.Optional[str] = None,
) -> t.List[Object]:
    """
    Generate ``struct virtio_device *`` object list from core

    :param prog: Program we're debugging
    :param virtio_mods: loaded virtio modules list
    :param vd_name: optional device name to filter
    :returns: list of virtio devices, ``struct virtio_device *``
    """
    vdevs = []

    for dev in for_each_device_virtio(prog, virtio_mods, vd_name):
        vdevs.append(dev_to_virtio(dev))

    return vdevs


def get_device_name(dev: Object) -> str:
    """
    Get device name from device->kboj

    :param dev: object of ``struct device``
    :returns: device's name
    """
    return escape_ascii_string(dev.kobj.name.string_(), escape_backslash=True)


def get_virtio_device_name(vdev: Object) -> str:
    """
    Get virtio device name

    :param dev: object of ``struct virtio_device *``
    :returns: device's name
    """
    return escape_ascii_string(
        vdev.dev.kobj.name.string_(),
        escape_backslash=True,
    )


def get_virtio_pci_dev(dev: Object) -> t.Optional[Object]:
    """
    Get given device's pci_dev

    :param dev: object of ``struct device *``
    :returns: object of ``struct pci_dev *``, or None
    """
    prog = dev.prog_

    # This may not actually be a pci_dev, we need to test whether the .driver
    # is virtio_pci_driver, so be careful here.
    pci_dev = container_of(dev, "struct pci_dev", "dev")
    log.debug("=> struct pci_dev %x" % pci_dev.value_())

    drv_addr = None
    try:
        drv_addr = pci_dev.driver.value_()
        log.debug("=> struct pci_driver %x" % drv_addr)
    except FaultError:
        # We just constructed a pci_dev by subtracting several bytes from the
        # struct device pointer. It's entirely possible that by doing so, we
        # crossed a page boundary, and the prior page is no longer kernel data,
        # and as such, was excluded from the dump. So a drgn.FaultError is
        # possible here. Ignore this error and try for the parent device still.
        pass

    try:
        if drv_addr:
            drv_sym = prog.symbol(drv_addr)
            log.debug("** _drv_sym: %s" % drv_sym)
            if drv_sym.name == "virtio_pci_driver":
                return pci_dev
    except LookupError:
        pass

    # Continue to lookup device->parent. If there's no parent, return None.
    pdev = dev.parent
    if not pdev.value_():
        return None

    log.debug("=> parent struct device %x" % pdev.value_())
    return get_virtio_pci_dev(pdev)


# PCI device device classes:
# ID | NAME
# ---+-----------------------------------
# 00 | Unclassified device
# 01 | Mass storage controller
# 02 | Network controller
# 03 | Display controller
# 04 | Multimedia controller
# 05 | Memory controller
# 06 | Bridge
# 07 | Communication controller
# 08 | Generic system peripheral
# 09 | Input device controller
# 0a | Docking station
# 0b | Processor
# 0c | Serial bus controller
# 0d | Wireless controller
# 0e | Intelligent controller
# 0f | Satellite communications controller
# 10 | Encryption controller
# 11 | Signal processing controller
# 12 | Processing accelerators
# 13 | Non-Essential Instrumentation
# 14 |
# 15 |
# 16 |
# 40 | Coprocessor
# 64 |
# ff | Unassigned class


def get_pci_dev_class(pci_dev: Object) -> str:
    """
    Retrieve class code of from pci_dev

    :param pci_dev: Object of type ``struct pci_dev *``
    :returns: class code as string, format: %04x
    """
    cls = pci_dev.member_("class").value_()
    # Idea of right-shit is come from crash-utility/dev.c, fill_dev_class
    cls = cls >> 8
    return "{:04x}".format(cls)


def get_pci_dev_id(pci_dev: Object) -> str:
    """
    Retrieve vendor_id and device_id from given pci_dev

    :param pci_dev: Object of type ``struct pci_dev *``
    :returns: vendor_id:device_id as string, format: "%04x:%04x"
    """
    return "{:04x}:{:04x}".format(
        pci_dev.vendor.value_(),
        pci_dev.device.value_(),
    )


def get_module_name(dev_obj: Object) -> t.Optional[str]:
    """
    Get module name from the driver

    :param dev_obj: Object of type ``struct device *``
    :returns: module name, or None
    """
    try:
        return dev_obj.prog_.module(dev_obj.driver).name
    except LookupError:
        return None


def dev_to_virtio(dev_obj: Object) -> Object:
    """
    Get ``struct virtio_device *`` corresponding to ``struct device *``

    :param dev_addr: Object of type ``struct device *``
    :returns: Object of type ``struct virtio_device *``
    """
    return container_of(dev_obj, "struct virtio_device", "dev")


def virtio_devices_show(
    dev_list: t.List[Object],
    vd_name: t.Optional[str] = None,
    header: bool = True,
) -> None:
    """
    Print virtio devices information to stdout

    :param show_list: list of virtio device
    :param vd_name: print given device only? Default: None, print all
    :param header: Print header? Default: True, print the header
    """
    show_list = []

    if dev_list is None or len(dev_list) <= 0:
        print("No virtio device found")
        return

    # Get device information
    for dev in dev_list:
        log.debug("---------------------------------------")
        dev_name = get_device_name(dev)
        log.debug("=> device %x" % (dev.address_))
        # Skip the device if not in show list
        if vd_name and dev_name != vd_name:
            continue

        with log.add_context(vdev=dev_name):
            # Get pci_dev which represent real device
            pci_dev = get_virtio_pci_dev(dev)
            if pci_dev is None:
                continue
            log.debug("=> struct pci_dev %x" % (pci_dev.value_()))

            # Get device class ID
            cls = get_pci_dev_class(pci_dev)
            log.debug("** Class code: %s" % (cls))

            # Get pci_id of device, return format: Vendor:Device
            pci_id = get_pci_dev_id(pci_dev)
            log.debug("** pci_id %s" % (pci_id))

            # Driver
            drv_name = get_module_name(dev)
            log.debug("=> device_driver: %s" % (drv_name))

            # struct virtio_device
            vdev = dev_to_virtio(dev)
            log.debug("=> virtio_device % x" % (vdev.value_()))

            vdev_priv = vdev.priv.value_()
            log.debug("** virtio_device->priv %x" % vdev_priv)

            pci_dev_bus_id = get_device_name(pci_dev.dev)
            log.debug("** pci_dev_bus_id: %s" % (pci_dev_bus_id))

            if drv_name and drv_name in virtio_mod_drv:
                struct_name = virtio_mod_drv[drv_name][1]
            else:
                struct_name = "UNKNOWN"

            show_list.append(
                [
                    dev_name,
                    pci_dev_bus_id,
                    pci_dev,
                    dev.address_,
                    vdev,
                    vdev_priv,
                    struct_name,
                    cls,
                    pci_id,
                    drv_name,
                ]
            )

    if len(show_list) <= 0:
        print("[WARNING]: No virtio device found!")
        return

    show_list.sort()

    # Print header
    if header:
        print("\n VIRTIO DEVICES")
        fstr = "{:10} {:14} {:16} {:16} {:16} {:16}[{:14s}] {:4} {:9} {:16}"
        print(
            fstr.format(
                "  DEV",
                "  DO:BU:SL.FN",
                "  PCI DEV",
                "DEVICE",
                "VIRTIO DECICE",
                "PRIV",
                "PRIV_STRUCT",
                "CLS",
                "PCI ID",
                "DRIVER",
            )
        )

    for i in show_list:
        # Print given device only
        if vd_name:
            if i[0] == vd_name:
                print(
                    "%-10s %-14s %16x %16x %16x %16x[%-14s] %4s %9s %-16s"
                    % tuple(i)
                )
                break
            else:
                continue

        print(
            "%-10s %-14s %16x %16x %16x %16x[%-14s] %4s %9s %-16s" % tuple(i)
        )


def get_vq_name(vring_q: Object) -> str:
    """
    Get virtioqueue name

    :param vring_q: Object of ``virtio ring``
    :returns: name of vring
    """
    vq_name = "NONE"
    try:
        vq_name = escape_ascii_string(
            vring_q.vq.name.string_(), escape_backslash=True
        )
    except Exception:
        pass

    return vq_name


# To adapt packed vring support, the sign of this is has member
# packed_ring also set it to True, defination on kernel looks like:
# struct vring_virtqueue {
# ...
#         bool packed_ring;
# ...
#         union {
#                 /* Available for split ring */
#                 struct {
#                         /* Actual memory layout for this queue. */
#                         struct vring vring;
#                 } split;
#
#                 /* Available for packed ring */
#                 struct {
# ...
#                 } packed;
#         };
# ...
# };
# NOTE: This required both host and guest support it.
def get_virtqueue_from_packed(vring_q: Object) -> VirtioQueueInfo:
    """
    Extract vring info from vring_virtqueue->packed

    :param vring_q: Object of ``struct vring_virtqueue *``
    :returns: vring information
    """
    log.debug("** get_virtqueue_from_packed vring_q = %x" % vring_q)
    raise NotImplementedError("Packed virtqueues are not yet supported")


# It works with either packed_ring set to False or it has member @split
# Scenario 1:
# struct vring_virtqueue {
# ...
#         bool packed_ring; <== True
# ...
#         union {
#                 /* Available for split ring */
#                 struct {
#                         /* Actual memory layout for this queue. */
#                         struct vring vring;
#                 } split;
#
#                 /* Available for packed ring */
#                 struct {
# ...
#                 } packed;
#         };
# ...
# };
#
# Scenario #2:
# struct vring_virtqueue {
#       struct virtqueue vq;
# ...
#       /* Last used index we've seen. */
#       u16 last_used_idx;
#
#      struct {
#               /* Actual memory layout for this queue */
#               struct vring vring;
#
#               /* Last written value to avail->flags */
#               u16 avail_flags_shadow;
#
#               /* Last written value to avail->idx in guest byte order */
#               u16 avail_idx_shadow;
#
#               /* Per-descriptor state. */
#               struct vring_desc_state_split *desc_state;
#
#               /* DMA, allocation, and size information */
#               size_t queue_size_in_bytes;
#               dma_addr_t queue_dma_addr;
#       } split;
#
def get_virtqueue_from_split(vring_q: Object) -> VirtioQueueInfo:
    """
    Extract vring info from vring_virtqueue->split

    :param vring_q: Object of ``struct vring_virtqueue *``
    :returns: vring information
    """
    log.debug("** get_virtqueue_from_split vring_q = %x" % vring_q.address_)

    vq_name = get_vq_name(vring_q)

    with log.add_context(vq=vq_name):
        split = vring_q.split

        # struct vring
        vring = split.vring
        vring_addr = "%x" % (vring.address_of_())
        log.debug("=> struct vring %s" % vring_addr)

        # last_used_idx
        last_used_idx = vring_q.last_used_idx.value_()
        # Host publishes avail event idx
        event = "Y" if vring_q.event else "N"

        # Last written value to avail->idx
        avail_idx_shadow = split.avail_idx_shadow.value_()
        nr_ent = split.vring.num.value_()

        vring_avail_addr = "%x" % (split.vring.avail)
        vring_used_addr = "%x" % (split.vring.used)
        log.debug("=> struct vring_avail %s" % vring_avail_addr)
        log.debug("=> struct vring_used %s" % vring_used_addr)

        avail = split.vring.avail
        avail_idx = avail.idx.value_()
        used = split.vring.used
        used_idx = used.idx.value_()
        log.debug(
            "** avil_idx: %d used_idx: %d avail_idx_shadow: %d"
            % (avail_idx, used_idx, avail_idx_shadow)
        )

        return VirtioQueueInfo(
            vq_name,
            vring_q.address_,
            vring_addr,
            vring_avail_addr,
            vring_used_addr,
            nr_ent,
            last_used_idx,
            avail_idx_shadow,
            avail_idx,
            used_idx,
            event,
        )


# Old style of struct vring_virtqueue
# struct vring_virtqueue {
#        struct virtqueue vq;
#
#        /* Actual memory layout for this queue */
#        struct vring vring;
# ...
#        /* Last used index we've seen. */
#        u16 last_used_idx;
#
#        /* Last written value to avail->flags */
#        u16 avail_flags_shadow;
#
#        /* Last written value to avail->idx in guest byte order */
#        u16 avail_idx_shadow;
# ...
# };
def get_virtqueue_direct(vring_q: Object) -> VirtioQueueInfo:
    """
    Extract vring info from vring_virtqueue(For old kernel)

    :param vring_q: Object of ``struct vring_virtqueue *``
    :returns: vring information
    """
    log.debug("** get_virtqueue_direct vring_q = %x" % vring_q.address_)

    vq_name = get_vq_name(vring_q)

    with log.add_context(vq=vq_name):
        # struct vring
        vring = vring_q.vring
        vring_addr = "%x" % (vring.address_)
        log.debug("=> struct vring %s" % vring_addr)

        # last_used_idx
        last_used_idx = vring_q.last_used_idx.value_()
        # Host publishes avail event idx
        event = "Y" if vring_q.event else "N"

        # Last written value to avail->idx
        try:
            avail_idx_shadow = vring_q.avail_idx_shadow.value_()
        except AttributeError:
            # UEK4 does not have this, substitute zero
            avail_idx_shadow = 0

        nr_ent = vring_q.vring.num.value_()

        vring_avail_obj = vring_q.vring.avail
        vring_avail_addr = "%x" % vring_avail_obj.value_()
        vring_used_obj = vring_q.vring.used
        vring_used_addr = "%x" % vring_used_obj.value_()
        log.debug("=> struct vring_avail %s" % vring_avail_addr)
        log.debug("=> struct vring_used %s" % vring_used_addr)
        avail_idx = vring_avail_obj.idx.value_()
        used_idx = vring_used_obj.idx.value_()
        log.debug(
            "** avil_idx: %d used_idx: %d avail_idx_shadow: %d"
            % (avail_idx, used_idx, avail_idx_shadow)
        )

        return VirtioQueueInfo(
            vq_name,
            vring_q.address_,
            vring_addr,
            vring_avail_addr,
            vring_used_addr,
            nr_ent,
            last_used_idx,
            avail_idx_shadow,
            avail_idx,
            used_idx,
            event,
        )


def for_each_vring_by_vdev(vdev: Object) -> t.List[Object]:
    """
    Return all ``struct vring_virtqueue *`` of a ``struct virtio_device *``

    :param vdev: Object of ``struct virtio_device *``
    :return: List of Objects of ``struct vring_virtqueue *``
    """
    vdev_rings = []

    log.debug("--------------------------------------")
    log.debug("=> struct virtio_device %x" % vdev.value_())

    for vq in list_for_each_entry(
        "struct virtqueue", vdev.vqs.address_of_(), "list"
    ):
        vring_q = container_of(vq, "struct vring_virtqueue", "vq")[0]
        log.debug("=> struct vring_virtqueue %x" % (vring_q.address_))
        vdev_rings.append(vring_q)

    return vdev_rings


def get_virtio_dev_vrings(
    vdevs: t.List[Object],
    vd_name: t.Optional[str] = None,
) -> t.Dict[str, t.List[Object]]:
    """
    Get the vrings for the given virtio devices.

    :param vdevs: list of ``struct virtio_device *``
    :param vd_name: virtio device name, if given, will only return the device's
      vrings
    :returns: dict mapping device name to list of ``struct vring_virtqueue *``
    """
    vrings = {}
    for vdev in vdevs:
        vdev_name = get_virtio_device_name(vdev)

        with log.add_context(vdev=vdev_name):
            if not vd_name or vdev_name == vd_name:
                vdev_vrings = for_each_vring_by_vdev(vdev)
                vrings[vdev_name] = vdev_vrings

    return vrings


def get_vring_info(vring: Object) -> VirtioQueueInfo:
    """
    Given a ``struct vring_virtqueue *``, get important info out of it.

    The vring_virtqueue differs across kernel versions, so the VirtioQueueInfo
    structure is used to represent the important information related to the
    virtqueue.  Depending on the present fields of the struct, this function
    chooses the correct implementation and fills this structure out.

    :param vring: Object of type ``struct vring_virtqueue *``
    :returns: Common vring/virtqueue info
    """
    # The packed_ring field is not present in all versions.
    packed_ring = False
    if has_member(vring, "packed_ring"):
        packed_ring = bool(vring.packed_ring)

    if packed_ring:
        log.debug("** packed_ring: %d" % packed_ring)
        return get_virtqueue_from_packed(vring)
    elif has_member(vring, "split"):
        log.debug("** split_ring")
        return get_virtqueue_from_split(vring)
    elif has_member(vring, "vring"):
        log.debug("old_ring")
        return get_virtqueue_direct(vring)
    else:
        log.warn("** unknown ring format")
        raise NotImplementedError("Encountered unknown ring format")


def vdev_vring_show(vd_vring: t.List[Object], key: str) -> None:
    """
    Show all vrings in @vd_ring list

    :param vd_ring: list of ``struct vring_virtqueue *`` belonging to the same
      virtio_device
    :param key: key (name) of virtio device
    """
    with log.add_context(vdev=key):
        for vring in vd_vring:
            log.debug("=> struct vring_virtqueue %x" % (vring.address_))
            vring_info = get_vring_info(vring)
            print(
                "%10s.%-12s %16x %16s %16s %16s %5d %5d:%5d:%5d:%5d %3c"
                % (
                    key,
                    vring_info.vq_name,
                    vring_info.vq_address,
                    vring_info.vring_addr,
                    vring_info.vring_avail_addr,
                    vring_info.vring_used_addr,
                    vring_info.nr_ent,
                    vring_info.last_used_idx,
                    vring_info.avail_idx_shadow,
                    vring_info.avail_idx,
                    vring_info.used_idx,
                    vring_info.event,
                )
            )


def vrings_show(
    vrings: t.Dict[str, t.List[Object]],
    header: bool = True,
    key: t.Optional[str] = None,
) -> None:
    """
    Print all vrings

    :param vrings: dictionary mapping virtio device name to list of ``struct
      virtio_device *``. This should come from :func:`get_virtio_dev_vrings()`
    :param header: Flag to indicate if print header or no, default: Yes
    :param key: If given will only show given virtio device ring
    """
    if key and key not in vrings:
        return

    if header:
        print(
            "{:>10}.{:12} {:16} {:16} {:16} {:16} {:5} {:23} {:6}".format(
                "DEV",
                "VQ NAME",
                "VRING_VIRTQUEUE",
                "VRING",
                "VRING_AVAIL",
                "VRING_USED",
                "N_ENT",
                "L_USD:A_SHD:A_IDX:U_IDX",
                "EVENT",
            )
        )

    if key:
        vdev_vring_show(vrings[key], key)
        return

    for i in vrings:
        vdev_vring_show(vrings[i], i)


def virtio_show(
    prog: Program,
    show_vq: bool = False,
    vd_name: t.Optional[str] = None,
) -> None:
    """
    Show virtio devices info.

    :param prog: Program we're debugging
    :param show_vq: Should we show vrings / virtqueues too
    :param vd_name: Only want to list virtio device's name
    """
    log.debug("starting drgn virtio!")

    # Load all virtio modules if in kernel
    virtio_mods = load_virtio_mods(prog)
    if len(virtio_mods) <= 0:
        print("[WARNING]: No virtio modules found in kernel!")
        return

    vdev_list = for_each_virtio(prog, virtio_mods, vd_name)
    for dev in vdev_list:
        log.debug("struct virtio_device 0x%x" % dev.value_())

    dev_list = for_each_device_virtio(prog, virtio_mods, vd_name)
    if dev_list is None or len(dev_list) <= 0:
        print("[WARNING]: No virtio devices found!")
        return

    log.debug(
        "** All virtio devices [{}]".format(
            ", ".join(hex(__dev.address_) for __dev in dev_list)
        )
    )

    virtio_devices_show(dev_list, vd_name)

    if not show_vq:
        return

    # Retrieve all vrings
    vrings = get_virtio_dev_vrings(vdev_list, vd_name)
    print("\n\n VRING ")

    if len(vrings) > 0:
        vrings_show(vrings, True, vd_name)


class Virtio(CorelensModule):
    """Show details of each virtio device, and optionally virtqueues"""

    name = "virtio"
    debuginfo_kmods = ["*virtio*"]
    default_args = [["--show-vq"]]

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--show-vq",
            action="store_true",
            help="show vrings in output",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        virtio_show(prog, show_vq=args.show_vq)
