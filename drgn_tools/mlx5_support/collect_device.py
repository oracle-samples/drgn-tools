# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Device discovery and summary collection for the mlx5 Corelens report."""
from itertools import chain
from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Set

from drgn import cast
from drgn import container_of
from drgn import NULL
from drgn import Object
from drgn import Program
from drgn.helpers.linux.list import list_for_each_entry

from .defs import _PCI_BDF_RE
from drgn_tools.crash_net import netdev_ipv4s
from drgn_tools.crash_net import netdev_ipv6s

MAX_NETDEV_IPS = 64


def mlx5_core_ib_device(mdev: Object) -> Object:
    """Return the mlx5 RDMA device for an mlx5 core device."""

    prog = mdev.prog_
    protocol = prog.constant("MLX5_INTERFACE_PROTOCOL_IB")
    ib_adev = mdev.priv.adev[protocol]
    if not ib_adev:
        return NULL(prog, "struct mlx5_ib_dev *")

    mlx5_ib = cast("struct mlx5_ib_dev *", ib_adev.adev.dev.driver_data)
    if not mlx5_ib:
        return NULL(prog, "struct mlx5_ib_dev *")
    return mlx5_ib


def for_each_mlx5_core_dev(prog: Program) -> Iterator[Object]:
    """Iterate over every device bound to an mlx5 core driver."""

    driver = prog["mlx5_core_driver"]
    for knode in list_for_each_entry(
        "struct klist_node",
        driver.driver.p.klist_devices.k_list.address_of_(),
        "n_node",
    ):
        device = container_of(
            knode, "struct device_private", "knode_driver"
        ).device
        pdev = container_of(device, "struct pci_dev", "dev")
        yield cast("struct mlx5_core_dev *", pdev.dev.driver_data)


class DeviceRecord:
    """Collected state for one ``struct mlx5_core_dev``."""

    mdev: Object
    mdev_address: str
    pci_bdf: Optional[str]
    ibdev: Optional[Object]
    netdev: Optional[Dict[str, Any]]
    summary: Dict[str, Any]
    health: Dict[str, Any]
    counts: Dict[str, Optional[int]]
    rdma_name: Optional[str]

    def __init__(self, mdev: Object) -> None:
        self.mdev = mdev
        self.mdev_address = hex(int(mdev))
        pci_name = mdev.pdev.dev.kobj.name.string_().decode("utf-8", "replace")
        self.pci_bdf = (
            pci_name.lower() if _PCI_BDF_RE.match(pci_name) else None
        )
        self.ibdev = None
        self.netdev = None
        self.summary = {}
        self.health = {}
        self.counts = {}
        self.rdma_name = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mdev": self.mdev_address,
            "netdev": self.netdev,
            "summary": self.summary,
            "health": self.health,
            "counts": self.counts,
        }


# Linux/netdev/mlx5 object helpers


def collect_health(mdev: Object) -> Dict[str, Any]:
    health = mdev.priv.health
    fatal_error = int(health.fatal_error)
    miss_counter = int(health.miss_counter)
    syndrome = int(health.synd)
    if fatal_error:
        status = "fatal"
    elif syndrome:
        status = "syndrome"
    elif miss_counter:
        status = "missed"
    else:
        status = "ok"
    return {
        "status": status,
        "fatal_error": fatal_error,
        "miss_counter": miss_counter,
    }


def collect_netdev_summary(netdev: Object) -> Dict[str, Any]:
    addresses: List[str] = []
    seen: Set[str] = set()
    for value in chain(netdev_ipv4s(netdev), netdev_ipv6s(netdev)):
        ip = str(value)
        if ip in seen:
            continue
        seen.add(ip)
        addresses.append(ip)
        if len(addresses) >= MAX_NETDEV_IPS:
            break

    no_carrier = int(netdev.prog_.constant("__LINK_STATE_NOCARRIER"))
    return {
        "carrier": ("down" if int(netdev.state) & (1 << no_carrier) else "up"),
        "ip_addresses": addresses,
        "stats": {
            field: int(netdev.stats.member_(field))
            for field in ("rx_errors", "tx_errors")
        },
    }
