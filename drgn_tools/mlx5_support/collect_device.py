# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Device discovery and summary collection for the mlx5 Corelens report."""
import ipaddress
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from drgn import cast
from drgn import container_of
from drgn import NULL
from drgn import Object
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.net import netdev_priv

from . import defs
from . import selection
from .defs import _MLX5_CMDIF_STATE
from .defs import _MLX5_COREDEV_TYPE
from .defs import _MLX5_DEVICE_STATE
from .defs import _MLX5_PCI_STATUS
from .defs import _PCI_BDF_RE
from .format import _enum_name
from .format import _format_fw_revision
from .format import _format_ib_fw_ver
from .format import _format_iseg_fw_revision
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


def _device_record(index: int, mdev: Object) -> Dict[str, Any]:
    mdev_addr = int(mdev)
    return {
        "name": f"mlx5_{index}",
        "mdev": _hex(mdev_addr),
        "netdevs": [],
        "summary": {},
        "health": {},
        "capabilities": {},
        "counts": {},
        "_mdev_obj": mdev,
    }


class DeviceCollectorMixin:
    """Find mlx5 devices and collect device-level report data.

    Mlx5Collector supplies the program, arguments, collection plan, stored
    records, walk helpers, and channel collector. Private ``_*_obj`` keys hold
    raw kernel objects and are removed from JSON output.
    """

    args: Any
    prog: Program
    _want_channels: bool
    _want_cqs: bool
    _want_eqs: bool
    _want_qps: bool
    _cqs: Dict[Any, Any]
    _eqs: Dict[Any, Any]
    _qps: Dict[Any, Any]
    _mlx5_ib_devices_cache: Optional[List[Object]]
    _collect_channels: Callable[..., Any]
    _iter_walk_limited: Callable[..., Iterable[Any]]
    _warn: Callable[[str], None]

    def _discover_devices(self) -> List[Dict[str, Any]]:
        devices_by_key: Dict[str, Dict[str, Any]] = {}
        saw_netdev = False

        mdevs = list(
            self._iter_walk_limited(
                for_each_mlx5_core_dev(self.prog),
                "mlx5 core driver discovery",
            )
        )
        for mdev in mdevs:
            if not mdev:
                raise ValueError("mlx5 driver device has no mlx5_core_dev")
            mdev_addr = int(mdev)
            key = hex(mdev_addr)
            devices_by_key[key] = _device_record(
                len(devices_by_key),
                mdev,
            )

            netdev = mlx5_netdev(mdev)
            if not netdev:
                continue
            name = escape_ascii_string(netdev.name.string_())
            saw_netdev = True
            if self.args.netdev and name != self.args.netdev:
                continue

            netdev_ops = _symbol_for_addr(self.prog, int(netdev.netdev_ops))
            priv = netdev_priv(netdev, "struct mlx5e_priv")
            if int(priv.mdev) != mdev_addr:
                raise ValueError(
                    f"{name}: mlx5e_priv.mdev does not match its core device"
                )
            devices_by_key[key]["netdevs"].append(
                {
                    "name": name,
                    "driver": netdev_ops,
                    "summary": _collect_netdev_summary(netdev),
                    "priv": _collect_mlx5e_priv_summary(priv),
                    "channels": [],
                    "channels_collected": False,
                    "_netdev_obj": netdev,
                    "_priv_obj": priv,
                }
            )

        for mdev in mdevs:
            ib_device = mlx5_core_ib_device(mdev)
            if not ib_device:
                continue
            ibdev = container_of(ib_device, "struct mlx5_ib_dev", "ib_dev")
            self._merge_mlx5_ib_device(devices_by_key, ibdev)

        if self.args.netdev:
            devices_by_key = {
                key: device
                for key, device in devices_by_key.items()
                if any(
                    n.get("name") == self.args.netdev
                    for n in device.get("netdevs", [])
                )
            }

        if not saw_netdev:
            self._warn("no mlx5 uplink netdevs were found")
        if not devices_by_key:
            if self.args.netdev:
                self._warn(
                    f"--netdev {self.args.netdev!r} did not match a discovered mlx5 netdev"
                )
            else:
                self._warn("no devices found in the mlx5 core drivers")

        return list(devices_by_key.values())

    def _merge_mlx5_ib_device(
        self,
        devices: Dict[str, Dict[str, Any]],
        ibdev: Object,
        rdma_name: Optional[str] = None,
    ) -> None:
        mdev = ibdev.mdev
        if not mdev:
            raise ValueError("mlx5_ib_dev.mdev is NULL")
        mdev_addr = int(mdev)
        if rdma_name is None:
            rdma_name = ibdev.ib_dev.name.string_().decode("utf-8", "replace")
        for (
            port_mdev_addr,
            port_num,
            _port_mdev,
        ) in self._iter_mlx5_ib_mdev_ports(ibdev, mdev, mdev_addr):
            key = hex(port_mdev_addr)
            if key not in devices:
                raise ValueError(
                    f"RDMA port {port_num} refers to undiscovered "
                    f"mlx5_core_dev {hex(port_mdev_addr)}"
                )
            self._attach_rdma_identity(
                devices[key], ibdev, rdma_name, port_num
            )

    def _attach_rdma_identity(
        self,
        device: Dict[str, Any],
        ibdev: Object,
        rdma_name: Optional[str],
        rdma_port: Optional[int],
    ) -> None:
        if rdma_name:
            device.setdefault("rdma_name", rdma_name)
        if rdma_port is not None:
            device.setdefault("rdma_port", rdma_port)
        if "rdma_ibdev" not in device:
            device["rdma_ibdev"] = _hex(int(ibdev))

    def _iter_mlx5_ib_mdev_ports(
        self, ibdev: Object, primary_mdev: Object, primary_mdev_addr: int
    ) -> Iterator[Tuple[int, Optional[int], Object]]:
        seen: Set[int] = set()
        for (
            port_mdev_addr,
            port_num,
            port_mdev,
        ) in self._iter_mlx5_ib_port_mdevs(ibdev):
            if port_mdev_addr in seen:
                continue
            seen.add(port_mdev_addr)
            yield port_mdev_addr, port_num, port_mdev
        if primary_mdev_addr not in seen:
            yield primary_mdev_addr, 1, primary_mdev

    def _iter_mlx5_ib_port_mdevs(
        self, ibdev: Object
    ) -> Iterator[Tuple[int, int, Object]]:
        ports = ibdev.port
        num_ports = int(ibdev.num_ports)
        for index in range(max(0, min(num_ports, defs.MAX_MLX5_IB_PORTS))):
            mpi = ports[index].mp.mpi
            if not mpi:
                continue
            port_mdev = mpi.mdev
            if port_mdev:
                yield int(port_mdev), index + 1, port_mdev

    def _iter_mlx5_ib_devices(self, mdev_addr: int) -> Iterator[Object]:
        for ibdev in self._iter_all_mlx5_ib_devices():
            if int(ibdev.mdev) == mdev_addr:
                yield ibdev

    def _iter_mlx5_ib_devices_for_fw(self, mdev: Object) -> Iterator[Object]:
        """Yield direct, multiport, then GUID-matched mlx5 IB devices."""

        mdev_addr = int(mdev)
        target_guid = int(mdev.sys_image_guid)
        target_type = int(mdev.coredev_type)
        direct: List[Object] = []
        multiport: List[Object] = []
        guid_match: List[Object] = []
        for ibdev in self._iter_all_mlx5_ib_devices():
            ib_mdev = ibdev.mdev
            if int(ib_mdev) == mdev_addr:
                direct.append(ibdev)
                continue
            if any(
                port_mdev_addr == mdev_addr
                for port_mdev_addr, _port_num, _port_mdev in self._iter_mlx5_ib_port_mdevs(
                    ibdev
                )
            ):
                multiport.append(ibdev)
                continue
            if target_guid == 0:
                continue
            ib_guid = int(ibdev.sys_image_guid)
            ib_type = int(ib_mdev.coredev_type)
            if ib_guid != target_guid:
                continue
            if ib_type != target_type:
                continue
            guid_match.append(ibdev)
        yield from direct
        yield from multiport
        yield from guid_match

    def _iter_all_mlx5_ib_devices(self) -> Iterator[Object]:
        if self._mlx5_ib_devices_cache is not None:
            yield from self._mlx5_ib_devices_cache
            return

        collected: List[Object] = []
        for mdev in for_each_mlx5_core_dev(self.prog):
            ib_device = mlx5_core_ib_device(mdev)
            if ib_device:
                collected.append(
                    container_of(
                        ib_device,
                        "struct mlx5_ib_dev",
                        "ib_dev",
                    )
                )
        self._mlx5_ib_devices_cache = collected
        yield from collected

    def _filter_devices(
        self, devices: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        filtered = devices
        if self.args.dev:
            selector = str(self.args.dev).lower()
            filtered = [
                dev
                for dev in filtered
                if _device_matches_selector(dev, selector)
            ]
            if not filtered:
                self._warn(
                    f"--dev {self.args.dev!r} did not match a discovered mlx5 device"
                )

        ip_selector = getattr(self.args, "ip", None)
        if ip_selector:
            filtered = [
                dev
                for dev in filtered
                if _device_has_ip(dev, str(ip_selector))
            ]
            if not filtered:
                self._warn(
                    f"--ip {ip_selector!r} did not match a discovered mlx5 netdev address"
                )
        return filtered

    def _collect_device_details(self, device: Dict[str, Any]) -> None:
        mdev = device["_mdev_obj"]
        device["summary"] = self._collect_core_summary(mdev, device)
        device["health"] = self._collect_health(mdev)
        device["capabilities"] = self._collect_capabilities(mdev)

        for netdev in device.get("netdevs", []):
            priv = netdev.get("_priv_obj")
            if self._want_channels:
                netdev["channels"] = self._collect_channels(
                    device, netdev, priv
                )
                netdev["channels_collected"] = True

        device["counts"] = self._device_counts(device)

    def _device_counts(
        self, device: Dict[str, Any]
    ) -> Dict[str, Optional[int]]:
        netdevs = device.get("netdevs", [])
        channels = [
            channel
            for netdev in netdevs
            for channel in netdev.get("channels", [])
        ]
        channels_collected = all(
            netdev.get("channels_collected", False) for netdev in netdevs
        )
        channel_count = len(channels) if channels_collected else None
        queue_count = (
            sum(
                1
                for channel in channels
                for _ in selection._channel_queues(channel)
            )
            if channels_collected
            else None
        )
        counts: Dict[str, Optional[int]] = {
            "netdevs": len(netdevs),
            "channels": channel_count,
            "queues": queue_count,
            "tx_sqs": None
            if channel_count is None
            else sum(len(channel.get("tx_sqs", [])) for channel in channels),
            "rx_rqs": None
            if channel_count is None
            else sum(bool(channel.get("rx_rq")) for channel in channels),
            "xdp_sqs": None
            if channel_count is None
            else sum(len(channel.get("xdp_sqs", [])) for channel in channels),
        }
        device_name = device.get("name")
        for count_name, wanted, records in (
            (
                "cqs",
                self._want_cqs,
                (entry.record for entry in self._cqs.values()),
            ),
            (
                "eqs",
                self._want_eqs,
                (entry.record for entry in self._eqs.values()),
            ),
            (
                "qps",
                self._want_qps,
                (entry.record for entry in self._qps.values()),
            ),
        ):
            counts[count_name] = (
                sum(record.get("device") == device_name for record in records)
                if wanted
                else None
            )
        return counts

    def _collect_core_summary(
        self, mdev: Object, device: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {
            "name": device.get("name"),
            "mdev": device.get("mdev"),
            "rdma_name": device.get("rdma_name"),
            "rdma_port": device.get("rdma_port"),
            "rdma_ibdev": device.get("rdma_ibdev"),
            "pci_bdf": _pci_bdf_from_mdev(mdev) or "unavailable",
            "coredev_type": _enum_name(
                _MLX5_COREDEV_TYPE, int(mdev.coredev_type)
            ),
            "device_state": _enum_name(_MLX5_DEVICE_STATE, int(mdev.state)),
            "pci_status": _enum_name(_MLX5_PCI_STATUS, int(mdev.pci_status)),
            "cmd_state": _enum_name(_MLX5_CMDIF_STATE, int(mdev.cmd.state)),
            "intf_state": _hex(int(mdev.intf_state)),
            "board_id": mdev.board_id.string_().decode("utf-8", "replace"),
            "rev_id": int(mdev.rev_id),
            "sys_image_guid": _hex(int(mdev.sys_image_guid)),
            "numa_node": int(mdev.priv.numa_node),
            "fw_version": self._collect_fw_version(mdev),
        }

    def _collect_fw_version(self, mdev: Object) -> str:
        for ibdev in self._iter_mlx5_ib_devices_for_fw(mdev):
            fw_ver = _format_ib_fw_ver(int(ibdev.ib_dev.attrs.fw_ver))
            if fw_ver is not None:
                return fw_ver
        # Upstream fw_rev_maj/min/sub helpers read MMIO through iseg, which is
        # often unavailable in a vmcore. Some kernels cache these fields; use
        # them only when the complete version tuple is present.
        if has_member(mdev, "fw_rev_maj"):
            fw_ver = _format_fw_revision(
                int(mdev.fw_rev_maj),
                int(mdev.fw_rev_min),
                int(mdev.fw_rev_sub),
            )
        elif has_member(mdev.priv, "fw_rev_maj"):
            fw_ver = _format_fw_revision(
                int(mdev.priv.fw_rev_maj),
                int(mdev.priv.fw_rev_min),
                int(mdev.priv.fw_rev_sub),
            )
        else:
            fw_ver = None
        if fw_ver is not None:
            return fw_ver

        iseg = mdev.iseg
        if not iseg:
            return "unavailable"
        return (
            _format_iseg_fw_revision(
                int(iseg.fw_rev),
                int(iseg.cmdif_rev_fw_sub),
            )
            or "unavailable"
        )

    def _collect_health(self, mdev: Object) -> Dict[str, Any]:
        health = mdev.priv.health
        fatal_error = int(health.fatal_error)
        miss_counter = int(health.miss_counter)
        syndrome = int(health.synd)
        return {
            "status": _health_status(fatal_error, miss_counter, syndrome),
            "fatal_error": fatal_error,
            "miss_counter": miss_counter,
            "syndrome": _hex(syndrome),
            "prev_counter": int(health.prev),
            "flags": _hex(int(health.flags)),
            "crdump_size": int(health.crdump_size),
            "health_buffer": _hex(int(health.health)),
            "health_counter": _hex(int(health.health_counter)),
            "workqueue": _hex(int(health.wq)),
        }

    def _collect_capabilities(self, mdev: Object) -> Dict[str, Any]:
        profile = mdev.profile
        sriov = mdev.priv.sriov
        return {
            "profile_log_max_qp": int(profile.log_max_qp),
            "profile_num_cmd_caches": int(profile.num_cmd_caches)
            if has_member(profile, "num_cmd_caches")
            else None,
            "embedded_cpu": int(mdev.caps.embedded_cpu),
            "roce_en": int(mdev.roce.roce_en),
            "sriov_max_vfs": int(sriov.max_vfs),
            "sriov_enabled_vfs": int(
                sriov.enabled_vfs
                if has_member(sriov, "enabled_vfs")
                else sriov.num_vfs
            ),
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


def _device_matches_selector(device: Dict[str, Any], selector: str) -> bool:
    candidates = {
        str(device.get("name", "")).lower(),
        str(device.get("mdev", "")).lower(),
        str(device.get("rdma_name", "")).lower(),
        str(device.get("summary", {}).get("pci_bdf", "")).lower(),
        str(device.get("summary", {}).get("rdma_name", "")).lower(),
    }
    mdev = device["_mdev_obj"]
    bdf = _pci_bdf_from_mdev(mdev)
    if bdf:
        candidates.add(bdf.lower())
    return selector in candidates


def _device_has_ip(device: Dict[str, Any], selector: str) -> bool:
    try:
        wanted = str(ipaddress.ip_address(selector))
    except ValueError:
        wanted = selector
    for netdev in device.get("netdevs", []) or []:
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
