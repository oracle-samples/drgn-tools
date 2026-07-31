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
    """Return the primary RDMA device for an mlx5 core device."""

    prog = mdev.prog_
    protocol = prog.constant("MLX5_INTERFACE_PROTOCOL_IB")
    ib_adev = mdev.priv.adev[protocol]
    if not ib_adev:
        return NULL(prog, "struct ib_device *")

    mlx5_ib = cast("struct mlx5_ib_dev *", ib_adev.adev.dev.driver_data)
    if not mlx5_ib:
        return NULL(prog, "struct ib_device *")
    return mlx5_ib.ib_dev.address_of_()


def _for_each_driver_device(driver: Object) -> Iterator[Object]:
    for knode in list_for_each_entry(
        "struct klist_node",
        driver.driver.p.klist_devices.k_list.address_of_(),
        "n_node",
    ):
        dev_priv = container_of(knode, "struct device_private", "knode_driver")
        yield dev_priv.device


def for_each_mlx5_core_dev(prog: Program) -> Iterator[Object]:
    """Iterate over every device bound to an mlx5 core driver."""

    for device in _for_each_driver_device(prog["mlx5_core_driver"]):
        pdev = container_of(device, "struct pci_dev", "dev")
        yield cast("struct mlx5_core_dev *", pdev.dev.driver_data)

    try:
        sf_driver = prog["mlx5_sf_driver"]
    except LookupError:
        return

    for device in _for_each_driver_device(sf_driver):
        adev = container_of(device, "struct auxiliary_device", "dev")
        sf_dev = container_of(adev, "struct mlx5_sf_dev", "adev")
        yield sf_dev.mdev


class DeviceRecord:
    """Collected state for one ``struct mlx5_core_dev``."""

    name: str
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

    def __init__(self, index: int, mdev: Object) -> None:
        self.name = f"mlx5_{index}"
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
        record: Dict[str, Any] = {
            "name": self.name,
            "mdev": self.mdev_address,
            "netdevs": self.netdevs,
            "summary": self.summary,
            "health": self.health,
            "capabilities": self.capabilities,
            "counts": self.counts,
        }
        if self.rdma_name is not None:
            record["rdma_name"] = self.rdma_name
        if self.rdma_port is not None:
            record["rdma_port"] = self.rdma_port
        if self.rdma_ibdev is not None:
            record["rdma_ibdev"] = self.rdma_ibdev
        return record


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
        device.name.lower(),
        device.mdev_address.lower(),
        str(device.rdma_name or "").lower(),
        str(device.summary.get("pci_bdf", "")).lower(),
        str(device.summary.get("rdma_name", "")).lower(),
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
        "num_tx_queues": int(
            netdev.real_num_tx_queues
            if has_member(netdev, "real_num_tx_queues")
            else netdev.num_tx_queues
        ),
        "num_rx_queues": int(
            netdev.real_num_rx_queues
            if has_member(netdev, "real_num_rx_queues")
            else netdev.num_rx_queues
        ),
        "stats": stats,
    }


def _netdev_ip_addresses(netdev: Object) -> List[str]:
    addresses: List[str] = []
    for helper in (netdev_ipv4s, netdev_ipv6s):
        for value in helper(netdev):
            ip = str(value)
            if ip not in addresses:
                addresses.append(ip)
            if len(addresses) >= MAX_NETDEV_IPS:
                return addresses
    return addresses


def _collect_mlx5e_priv_summary(priv: Optional[Object]) -> Dict[str, Any]:
    if priv is None:
        return {"status": "unavailable"}
    if has_member(priv, "channels"):
        channels = priv.channels
        channels_source = "struct mlx5e_priv.channels"
    else:
        channels = priv.channels_info
        channels_source = "struct mlx5e_priv.channels_info"

    if has_member(channels, "num"):
        channels_num = int(channels.num)
    elif has_member(channels, "num_channels"):
        channels_num = int(channels.num_channels)
    else:
        channels_num = int(channels.params.num_channels)

    return {
        "address": _hex(int(priv)),
        "mdev": _hex(int(priv.mdev)),
        "netdev": _hex(int(priv.netdev)),
        "state": _hex(int(priv.state)),
        "stats_nch": int(priv.stats_nch),
        "max_nch": int(priv.max_nch),
        "max_opened_tc": int(priv.max_opened_tc),
        "tx_ptp_opened": int(priv.tx_ptp_opened)
        if has_member(priv, "tx_ptp_opened")
        else None,
        "rx_ptp_opened": int(priv.rx_ptp_opened)
        if has_member(priv, "rx_ptp_opened")
        else None,
        "channels": _hex(int(channels.address_)),
        "channels_source": channels_source,
        "channels_num": channels_num,
        "profile": _hex(int(priv.profile)),
    }


def _netdev_carrier_state(netdev: Object) -> str:
    if has_member(netdev, "carrier_up_count") and has_member(
        netdev, "carrier_down_count"
    ):
        up = int(netdev.carrier_up_count.counter)
        down = int(netdev.carrier_down_count.counter)
        if up == down == 0:
            return "unknown"
        return "up" if up >= down else "down"
    operstate = int(netdev.operstate)
    if operstate == 6:
        return "up"
    if operstate in (2, 3):
        return "down"
    return "unknown"


def _sum_known(values: Iterable[Optional[int]]) -> Optional[int]:
    total = 0
    for value in values:
        if value is None:
            return None
        total += value
    return total
