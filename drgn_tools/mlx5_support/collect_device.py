# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Device discovery and summary collection for the mlx5 Corelens report."""
import ipaddress
from typing import Any
from typing import Dict
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Optional

from drgn import cast
from drgn import container_of
from drgn import NULL
from drgn import Object
from drgn import Program
from drgn.helpers.linux.list import list_for_each_entry

from .defs import _PCI_BDF_RE
from .format import _hex
from drgn_tools.crash_net import netdev_ipv4s
from drgn_tools.crash_net import netdev_ipv6s
from drgn_tools.util import has_member

MAX_NETDEV_IPS = 64


def mlx5_netdev(mdev: Object) -> Object:
    """Return the uplink netdev for an mlx5 core device."""

    return mdev.mlx5e_res.uplink_netdev


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
    netdevs: List[Dict[str, Any]]
    summary: Dict[str, Any]
    health: Dict[str, Any]
    capabilities: Dict[str, Any]
    counts: Dict[str, Optional[int]]
    rdma_name: Optional[str]
    rdma_port: Optional[int]
    rdma_ibdev: Optional[str]

    def __init__(self, mdev: Object) -> None:
        self.mdev = mdev
        self.mdev_address = hex(int(mdev))
        self.netdevs = []
        self.summary = {}
        self.health = {}
        self.capabilities = {}
        self.counts = {}
        self.rdma_name = None
        self.rdma_port = None
        self.rdma_ibdev = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mdev": self.mdev_address,
            "netdevs": self.netdevs,
            "summary": self.summary,
            "health": self.health,
            "capabilities": self.capabilities,
            "counts": self.counts,
        }


# Linux/netdev/mlx5 object helpers


def _health_status(
    fatal_error: int,
    miss_counter: int,
    syndrome: int,
) -> str:
    if fatal_error:
        return "fatal"
    if syndrome:
        return "syndrome"
    if miss_counter:
        return "missed"
    return "ok"


def _pci_bdf_from_mdev(mdev: Object) -> Optional[str]:
    name = mdev.pdev.dev.kobj.name.string_().decode("utf-8", "replace")
    return name.lower() if _PCI_BDF_RE.match(name) else None


def _symbol_for_addr(prog: Program, addr: Optional[int]) -> Optional[str]:
    if addr is None:
        return None
    try:
        symbol = prog.symbol(addr)
        return symbol.name
    except LookupError:
        return None


def _device_matches_selector(device: DeviceRecord, selector: str) -> bool:
    candidates = {
        device.mdev_address.lower(),
        str(device.rdma_name or "").lower(),
    }
    bdf = _pci_bdf_from_mdev(device.mdev)
    if bdf:
        candidates.add(bdf.lower())
    return selector in candidates


def _device_has_ip(device: DeviceRecord, selector: str) -> bool:
    try:
        wanted = str(ipaddress.ip_address(selector))
    except ValueError:
        wanted = selector
    for netdev in device.netdevs:
        summary = netdev.get("summary", {})
        for ip in summary.get("ip_addresses", []) or []:
            if str(ip) == wanted:
                return True
    return False


def _collect_netdev_summary(netdev: Object) -> Dict[str, Any]:
    stats = {
        field: int(netdev.stats.member_(field))
        for field in (
            "rx_packets",
            "tx_packets",
            "rx_bytes",
            "tx_bytes",
            "rx_dropped",
            "tx_dropped",
            "rx_errors",
            "tx_errors",
        )
    }
    return {
        "ifindex": int(netdev.ifindex),
        "mtu": int(netdev.mtu),
        "flags": _hex(int(netdev.flags)),
        "operstate": int(netdev.operstate),
        "carrier": _netdev_carrier_state(netdev),
        "ip_addresses": _netdev_ip_addresses(netdev),
        "num_tx_queues": int(netdev.real_num_tx_queues),
        "num_rx_queues": int(netdev.real_num_rx_queues),
        "stats": stats,
    }


def _netdev_ip_addresses(netdev: Object) -> List[str]:
    addresses: List[str] = []
    values = [str(value) for value in netdev_ipv4s(netdev)]
    values.extend(str(value) for value in netdev_ipv6s(netdev))
    for ip in values:
        if ip not in addresses:
            addresses.append(ip)
        if len(addresses) >= MAX_NETDEV_IPS:
            return addresses
    return addresses


def _collect_mlx5e_priv_summary(priv: Object) -> Dict[str, Any]:
    channels = priv.channels
    return {
        "address": _hex(int(priv)),
        "mdev": _hex(int(priv.mdev)),
        "netdev": _hex(int(priv.netdev)),
        "state": _hex(int(priv.state)),
        "stats_nch": int(priv.stats_nch),
        "max_nch": int(priv.max_nch),
        "max_opened_tc": int(priv.max_opened_tc),
        "tx_ptp_opened": int(priv.tx_ptp_opened),
        "rx_ptp_opened": int(priv.rx_ptp_opened)
        if has_member(priv, "rx_ptp_opened")
        else None,
        "channels": _hex(int(channels.address_)),
        "channels_source": "struct mlx5e_priv.channels",
        "channels_num": int(channels.num),
        "profile": _hex(int(priv.profile)),
    }


def _netdev_carrier_state(netdev: Object) -> str:
    no_carrier = int(netdev.prog_.constant("__LINK_STATE_NOCARRIER"))
    return "down" if int(netdev.state) & (1 << no_carrier) else "up"


def _sum_known(values: Iterable[Optional[int]]) -> Optional[int]:
    total = 0
    for value in values:
        if value is None:
            return None
        total += value
    return total
