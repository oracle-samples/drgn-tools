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
from drgn import Object
from drgn import Program
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.net import netdev_priv
from drgn.helpers.linux.xarray import xa_for_each

from . import defs
from . import selection
from .compat import _addr
from .compat import _first_int_path
from .compat import _first_member_path_with_source
from .compat import _for_each_netdev_compat
from .compat import _is_null
from .compat import _safe_container_of
from .compat import _safe_cstr
from .compat import _safe_index
from .compat import _safe_int
from .compat import _safe_iter
from .compat import _safe_member
from .compat import _safe_member_path
from .compat import _safe_pointer
from .compat import _sizeof_type
from .compat import _struct_type_name
from .compat import netdev_name
from .defs import _MLX5_CMDIF_STATE
from .defs import _MLX5_COREDEV_TYPE
from .defs import _MLX5_DEVICE_STATE
from .defs import _MLX5_PCI_STATUS
from .defs import _MLX5E_CHANNELS_OBJECT_PATHS
from .defs import _PCI_BDF_RE
from .format import _enum_name
from .format import _format_fw_revision
from .format import _format_ib_fw_ver
from .format import _format_iseg_fw_revision
from .format import _hex
from drgn_tools.crash_net import netdev_ipv4s
from drgn_tools.crash_net import netdev_ipv6s

MAX_NETDEV_IPS = 64


def _device_record(
    index: int,
    mdev: Optional[Object],
    mdev_addr: Optional[int],
    source: str,
    **discovery: Any,
) -> Dict[str, Any]:
    return {
        "name": f"mlx5_{index}",
        "mdev": _hex(mdev_addr),
        "mdev_present": mdev is not None,
        "netdevs": [],
        "summary": {},
        "health": {},
        "capabilities": {},
        "counts": {},
        "discovery": {"via": [source], **discovery},
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
    _plan: Dict[str, bool]
    _cqs: Dict[Any, Any]
    _eqs: Dict[Any, Any]
    _qps: Dict[Any, Any]
    _mlx5_ib_devices_cache: Optional[List[Object]]
    _collect_channels: Callable[..., Any]
    _iter_limited: Callable[..., Iterable[Any]]
    _warn: Callable[[str], None]

    def _discover_devices(self) -> List[Dict[str, Any]]:
        devices_by_key: Dict[str, Dict[str, Any]] = {}
        saw_netdev = False

        for netdev in self._iter_limited(
            _safe_iter(
                lambda: _for_each_netdev_compat(self.prog),
                self._warn,
                "iterating netdevs",
            ),
            "net_device discovery",
        ):
            saw_netdev = True
            name = _netdev_name(netdev)
            if self.args.netdev and name != self.args.netdev:
                continue

            driver = _driver_name_from_netdev(netdev)
            priv = _mlx5e_priv_from_netdev(netdev)
            mdev = _safe_member(priv, "mdev")
            if _is_null(mdev):
                mdev = None
            if not _looks_like_mlx5_netdev(netdev, driver, priv, mdev):
                continue

            mdev_addr = _addr(mdev)
            key = hex(mdev_addr) if mdev_addr is not None else f"netdev:{name}"
            if key not in devices_by_key:
                devices_by_key[key] = _device_record(
                    len(devices_by_key),
                    mdev,
                    mdev_addr,
                    "netdev",
                    netdev_driver=driver or "unknown",
                )
            devices_by_key[key]["netdevs"].append(
                {
                    "name": name,
                    "driver": driver or "unknown",
                    "summary": _collect_netdev_summary(netdev),
                    "priv": _collect_mlx5e_priv_summary(priv),
                    "channels": [],
                    "channels_collected": False,
                    "_netdev_obj": netdev,
                    "_priv_obj": priv,
                }
            )

        self._merge_rdma_devices(devices_by_key)
        self._merge_symbol_devices(devices_by_key)
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
            self._warn("no net_device entries were visible in this program")
        if not devices_by_key:
            if self.args.netdev:
                self._warn(
                    f"--netdev {self.args.netdev!r} did not match a discovered mlx5 netdev"
                )
            else:
                self._warn(
                    "no mlx5 devices discovered through netdev, RDMA, or symbol paths"
                )

        return list(devices_by_key.values())

    def _discover_devices_from_symbols(self) -> Dict[str, Dict[str, Any]]:
        devices_by_address: Dict[str, Dict[str, Any]] = {}
        # No stable mlx5_core_dev list exists across kernel versions. Probe
        # names found in vendor and debugging kernels.
        for symbol in ("mlx5_core_dev_list", "mlx5_dev_list", "mlx5_devices"):
            try:
                head = self.prog[symbol]
            except Exception:
                continue
            for mdev in self._iter_limited(
                _safe_iter(
                    lambda h=head: list_for_each_entry(  # type: ignore[misc]
                        "struct mlx5_core_dev", h.address_of_(), "list"
                    ),
                    self._warn,
                    f"walking {symbol}",
                ),
                f"{symbol} discovery",
            ):
                mdev_addr = _addr(mdev)
                if mdev_addr is None:
                    continue
                key = hex(mdev_addr)
                devices_by_address[key] = _device_record(
                    len(devices_by_address), mdev, mdev_addr, symbol
                )
        return devices_by_address

    def _merge_rdma_devices(self, devices: Dict[str, Dict[str, Any]]) -> None:
        rdmacg_devices = list(
            self._iter_rdmacg_mlx5_devices(
                "walking rdmacg_devices for mlx5 devices",
                "rdmacg_devices discovery",
            )
        )
        for ibdev, rdma_name in rdmacg_devices:
            self._merge_mlx5_ib_device(
                devices, ibdev, "rdmacg_devices", rdma_name
            )

        for ibdev in self._iter_all_mlx5_ib_devices(rdmacg_devices):
            self._merge_mlx5_ib_device(devices, ibdev, "mlx5_ib_registry")

    def _iter_rdmacg_mlx5_devices(
        self, walk_context: str, truncation_scope: str
    ) -> Iterator[Tuple[Object, Optional[str]]]:
        try:
            rdmacg_head = self.prog["rdmacg_devices"]
        except Exception:
            return
        for cgdev in self._iter_limited(
            _safe_iter(
                lambda h=rdmacg_head: list_for_each_entry(  # type: ignore[misc]
                    "struct rdmacg_device", h.address_of_(), "dev_node"
                ),
                self._warn,
                walk_context,
            ),
            truncation_scope,
        ):
            cg_addr = _addr(cgdev)
            if cg_addr is None:
                continue
            cg_ptr = _safe_pointer(
                self.prog, "struct rdmacg_device *", cg_addr
            )
            ib_device = _safe_container_of(
                cg_ptr, "struct ib_device", "cg_device"
            )
            if ib_device is None:
                continue
            ibdev = self._mlx5_ib_dev_from_ib_device(ib_device)
            if ibdev is None:
                continue
            yield ibdev, _safe_cstr(_safe_member(cgdev, "name"))

    def _merge_mlx5_ib_device(
        self,
        devices: Dict[str, Dict[str, Any]],
        ibdev: Object,
        source: str,
        rdma_name: Optional[str] = None,
    ) -> None:
        mdev = _safe_member(ibdev, "mdev")
        mdev_addr = _addr(mdev)
        if mdev_addr is None:
            return
        if rdma_name is None:
            rdma_name = _safe_cstr(
                _safe_member_path(ibdev, ["ib_dev", "name"])
            )
        for (
            port_mdev_addr,
            port_num,
            port_mdev,
        ) in self._mlx5_ib_dev_mdev_ports(ibdev, mdev, mdev_addr):
            key = hex(port_mdev_addr)
            if key in devices:
                self._attach_rdma_identity(
                    devices[key], ibdev, source, rdma_name, port_num
                )
                continue
            devices[key] = _device_record(
                len(devices), port_mdev, port_mdev_addr, source
            )
            self._attach_rdma_identity(
                devices[key], ibdev, source, rdma_name, port_num
            )

    def _attach_rdma_identity(
        self,
        device: Dict[str, Any],
        ibdev: Object,
        source: str,
        rdma_name: Optional[str],
        rdma_port: Optional[int],
    ) -> None:
        discovery = device.setdefault("discovery", {})
        via = discovery.setdefault("via", [])
        if source not in via:
            via.append(source)
        if rdma_name:
            device.setdefault("rdma_name", rdma_name)
            discovery.setdefault("rdma_name", rdma_name)
        if rdma_port is not None:
            device.setdefault("rdma_port", rdma_port)
            discovery.setdefault("rdma_port", rdma_port)
        ibdev_addr = _addr(ibdev)
        if ibdev_addr is not None and "rdma_ibdev" not in device:
            device["rdma_ibdev"] = _hex(ibdev_addr)

    def _mlx5_ib_dev_mdev_ports(
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
        ports = _safe_member(ibdev, "port")
        num_ports = _safe_int(_safe_member(ibdev, "num_ports"))
        if ports is None or num_ports is None:
            return
        for index in range(max(0, min(num_ports, defs.MAX_MLX5_IB_PORTS))):
            port = _safe_index(ports, index)
            mpi = _safe_member_path(port, ["mp", "mpi"])
            if mpi is None or _is_null(mpi):
                continue
            port_mdev = _safe_member(mpi, "mdev")
            port_mdev_addr = _addr(port_mdev)
            if port_mdev_addr is not None:
                yield port_mdev_addr, index + 1, port_mdev

    def _merge_symbol_devices(
        self, devices: Dict[str, Dict[str, Any]]
    ) -> None:
        for (
            key,
            symbol_device,
        ) in self._discover_devices_from_symbols().items():
            if key in devices:
                discovery = devices[key].setdefault("discovery", {})
                via = discovery.setdefault("via", [])
                for source in symbol_device.get("discovery", {}).get(
                    "via", []
                ):
                    if source not in via:
                        via.append(source)
                continue
            symbol_device["name"] = f"mlx5_{len(devices)}"
            devices[key] = symbol_device

    def _iter_mlx5_ib_devices(self, mdev_addr: int) -> Iterator[Object]:
        for ibdev in self._iter_all_mlx5_ib_devices():
            if _addr(_safe_member(ibdev, "mdev")) == mdev_addr:
                yield ibdev

    def _iter_mlx5_ib_devices_for_fw(self, mdev: Object) -> Iterator[Object]:
        """Yield direct, multiport, then GUID-matched mlx5 IB devices."""

        mdev_addr = _addr(mdev)
        if mdev_addr is None:
            return

        target_guid = _safe_int(_safe_member(mdev, "sys_image_guid"))
        target_type = _safe_int(_safe_member(mdev, "coredev_type"))
        direct: List[Object] = []
        multiport: List[Object] = []
        guid_match: List[Object] = []
        for ibdev in self._iter_all_mlx5_ib_devices():
            ib_mdev = _safe_member(ibdev, "mdev")
            if _addr(ib_mdev) == mdev_addr:
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
            if target_guid in (None, 0):
                continue
            ib_guid = _safe_int(_safe_member(ibdev, "sys_image_guid"))
            ib_type = _safe_int(_safe_member(ib_mdev, "coredev_type"))
            if ib_guid != target_guid:
                continue
            if (
                target_type is not None
                and ib_type is not None
                and ib_type != target_type
            ):
                continue
            guid_match.append(ibdev)
        yield from direct
        yield from multiport
        yield from guid_match

    def _ib_core_devices_xarrays(self) -> Iterator[Tuple[Object, str]]:
        """Find the RDMA core ``devices`` xarray.

        Other subsystems use the same symbol name, so check its size and type
        before walking it.
        """

        seen: Set[int] = set()
        xarray_size = _sizeof_type(self.prog, "struct xarray")

        try:
            symbols = list(self.prog.symbols("devices"))
        except Exception:
            symbols = []
        for symbol in symbols:
            symbol_address = _safe_int(getattr(symbol, "address", None))
            if symbol_address is None or symbol_address in seen:
                continue
            symbol_size = _safe_int(getattr(symbol, "size", None))
            if xarray_size is not None and symbol_size != xarray_size:
                continue
            try:
                devices = Object(
                    self.prog, "struct xarray", address=symbol_address
                )
            except Exception:
                continue
            seen.add(symbol_address)
            yield devices, "ib_core.devices"

        try:
            devices = self.prog["devices"]
        except Exception:
            return
        address = _addr(devices)
        if address is not None and address in seen:
            return
        if _struct_type_name(devices) != "struct xarray":
            return
        if address is not None:
            seen.add(address)
        yield devices, "ib_core.devices"

    def _mlx5_ib_dev_from_ib_device(
        self, ib_device: Optional[Object]
    ) -> Optional[Object]:
        if ib_device is None or _is_null(ib_device):
            return None
        name = _safe_cstr(_safe_member(ib_device, "name"))
        vendor_id = _safe_int(
            _safe_member_path(ib_device, ["attrs", "vendor_id"])
        )
        ibdev = _safe_container_of(ib_device, "struct mlx5_ib_dev", "ib_dev")
        if ibdev is None:
            return None
        mdev = _safe_member(ibdev, "mdev")
        if mdev is None or _is_null(mdev):
            return None
        is_mlx5 = (
            (name and name.startswith("mlx5_"))
            or vendor_id == 0x15B3
            or _mdev_has_mlx5_core_shape(mdev)
        )
        return ibdev if is_mlx5 else None

    def _iter_mlx5_ib_devices_from_ib_core_xarray(self) -> Iterator[Object]:
        for devices, source in self._ib_core_devices_xarrays():
            for _index, entry in self._iter_limited(
                _safe_iter(
                    lambda d=devices: xa_for_each(  # type: ignore[misc]
                        d.address_of_()
                    ),
                    self._warn,
                    f"walking {source}",
                ),
                f"{source} discovery",
            ):
                entry_address = _addr(entry)
                if entry_address in (None, 0):
                    continue
                ib_device = _safe_pointer(
                    self.prog, "struct ib_device *", entry_address
                )
                if ib_device is None:
                    continue
                ibdev = self._mlx5_ib_dev_from_ib_device(ib_device)
                if ibdev is not None:
                    yield ibdev

    def _iter_all_mlx5_ib_devices(
        self,
        rdmacg_devices: Optional[
            Iterable[Tuple[Object, Optional[str]]]
        ] = None,
    ) -> Iterator[Object]:
        if self._mlx5_ib_devices_cache is not None:
            yield from self._mlx5_ib_devices_cache
            return

        seen: Set[int] = set()
        collected: List[Object] = []
        sources: List[Iterable[Object]] = []
        try:
            head = self.prog["mlx5_ib_dev_list"]
        except Exception:
            head = None
        if head is not None:
            sources.append(
                self._iter_limited(
                    _safe_iter(
                        lambda h=head: list_for_each_entry(  # type: ignore[misc]
                            "struct mlx5_ib_dev",
                            h.address_of_(),
                            "ib_dev_list",
                        ),
                        self._warn,
                        "walking mlx5_ib_dev_list",
                    ),
                    "mlx5_ib_dev_list discovery",
                )
            )
        sources.append(self._iter_mlx5_ib_devices_from_ib_core_xarray())
        if rdmacg_devices is None:
            rdmacg_devices = self._iter_rdmacg_mlx5_devices(
                "walking rdmacg_devices", "rdmacg_devices mlx5_ib discovery"
            )
        sources.append((ibdev for ibdev, _rdma_name in rdmacg_devices))

        for source in sources:
            for ibdev in source:
                address = _addr(ibdev)
                if address is not None and address in seen:
                    continue
                if address is not None:
                    seen.add(address)
                collected.append(ibdev)
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
        mdev = device.get("_mdev_obj")
        device["summary"] = self._collect_core_summary(mdev, device)
        device["health"] = self._collect_health(mdev)
        device["capabilities"] = self._collect_capabilities(mdev)

        for netdev in device.get("netdevs", []):
            priv = netdev.get("_priv_obj")
            if self._plan["channels"]:
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
            else sum(len(ch.get("tx_sqs", [])) for ch in channels),
            "rx_rqs": None
            if channel_count is None
            else sum(bool(ch.get("rx_rq")) for ch in channels),
            "xdp_sqs": None
            if channel_count is None
            else sum(len(ch.get("xdp_sqs", [])) for ch in channels),
        }
        device_name = device.get("name")
        plan = getattr(self, "_plan", {})
        for count_name, records in (
            ("cqs", (entry.record for entry in self._cqs.values())),
            ("eqs", (entry.record for entry in self._eqs.values())),
            ("qps", (entry.record for entry in self._qps.values())),
        ):
            counts[count_name] = (
                sum(record.get("device") == device_name for record in records)
                if plan.get(count_name, True)
                else None
            )
        return counts

    def _collect_core_summary(
        self, mdev: Optional[Object], device: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {
            "name": device.get("name"),
            "mdev": device.get("mdev"),
            "rdma_name": device.get("rdma_name"),
            "rdma_port": device.get("rdma_port"),
            "rdma_ibdev": device.get("rdma_ibdev"),
            "pci_bdf": _pci_bdf_from_mdev(mdev) or "unavailable",
            "coredev_type": _enum_name(
                _MLX5_COREDEV_TYPE,
                _safe_int(_safe_member(mdev, "coredev_type")),
            ),
            "device_state": _enum_name(
                _MLX5_DEVICE_STATE, _safe_int(_safe_member(mdev, "state"))
            ),
            "pci_status": _enum_name(
                _MLX5_PCI_STATUS, _safe_int(_safe_member(mdev, "pci_status"))
            ),
            "cmd_state": _enum_name(
                _MLX5_CMDIF_STATE,
                _safe_int(_safe_member_path(mdev, ["cmd", "state"])),
            ),
            "intf_state": _hex(_safe_int(_safe_member(mdev, "intf_state"))),
            "board_id": _safe_cstr(_safe_member(mdev, "board_id"))
            or "unavailable",
            "rev_id": _safe_int(_safe_member(mdev, "rev_id")),
            "sys_image_guid": _hex(
                _safe_int(_safe_member(mdev, "sys_image_guid"))
            ),
            "numa_node": _safe_int(
                _safe_member_path(mdev, ["priv", "numa_node"])
            ),
            "fw_version": self._collect_fw_version(mdev),
        }

    def _collect_fw_version(self, mdev: Optional[Object]) -> str:
        if mdev is None:
            return "unavailable"
        if _addr(mdev) is not None:
            for ibdev in self._iter_mlx5_ib_devices_for_fw(mdev):
                fw_ver = _format_ib_fw_ver(
                    _safe_int(
                        _safe_member_path(ibdev, ["ib_dev", "attrs", "fw_ver"])
                    )
                )
                if fw_ver is not None:
                    return fw_ver
        # Upstream fw_rev_maj/min/sub helpers read MMIO through iseg, which is
        # often unavailable in a vmcore. Some kernels cache these fields; use
        # them only when the complete version tuple is present.
        cached_candidates = (
            (["fw_rev_maj"], ["fw_rev_min"], ["fw_rev_sub"]),
            (
                ["priv", "fw_rev_maj"],
                ["priv", "fw_rev_min"],
                ["priv", "fw_rev_sub"],
            ),
        )
        for major_path, minor_path, subminor_path in cached_candidates:
            fw_ver = _format_fw_revision(
                _safe_int(_safe_member_path(mdev, major_path)),
                _safe_int(_safe_member_path(mdev, minor_path)),
                _safe_int(_safe_member_path(mdev, subminor_path)),
            )
            if fw_ver is not None:
                return fw_ver
        iseg = _safe_member(mdev, "iseg")
        if iseg is None or _is_null(iseg):
            return "unavailable"
        return (
            _format_iseg_fw_revision(
                _safe_int(_safe_member(iseg, "fw_rev")),
                _safe_int(_safe_member(iseg, "cmdif_rev_fw_sub")),
            )
            or "unavailable"
        )

    def _collect_health(self, mdev: Optional[Object]) -> Dict[str, Any]:
        health = _safe_member_path(mdev, ["priv", "health"])
        if health is None:
            return {"status": "unavailable"}
        fatal_error = _safe_int(_safe_member(health, "fatal_error"))
        miss_counter = _safe_int(_safe_member(health, "miss_counter"))
        syndrome = _safe_int(_safe_member(health, "synd"))
        return {
            "status": _health_status(fatal_error, miss_counter, syndrome),
            "fatal_error": fatal_error,
            "miss_counter": miss_counter,
            "syndrome": _hex(syndrome),
            "prev_counter": _safe_int(_safe_member(health, "prev")),
            "flags": _hex(_safe_int(_safe_member(health, "flags"))),
            "crdump_size": _safe_int(_safe_member(health, "crdump_size")),
            "health_buffer": _hex(_addr(_safe_member(health, "health"))),
            "health_counter": _hex(
                _addr(_safe_member(health, "health_counter"))
            ),
            "workqueue": _hex(_addr(_safe_member(health, "wq"))),
        }

    def _collect_capabilities(self, mdev: Optional[Object]) -> Dict[str, Any]:
        if mdev is None:
            return {"status": "unavailable"}
        profile = _safe_member(mdev, "profile")
        sriov = _safe_member_path(mdev, ["priv", "sriov"])
        return {
            "profile_log_max_qp": _safe_int(
                _safe_member(profile, "log_max_qp")
            ),
            "profile_num_cmd_caches": _safe_int(
                _safe_member(profile, "num_cmd_caches")
            ),
            "embedded_cpu": _safe_int(
                _safe_member(_safe_member(mdev, "caps"), "embedded_cpu")
            ),
            "roce_en": _safe_int(
                _safe_member(_safe_member(mdev, "roce"), "roce_en")
            ),
            "sriov_max_vfs": _safe_int(_safe_member(sriov, "max_vfs")),
            "sriov_enabled_vfs": _first_int_path(
                sriov, (["enabled_vfs"], ["num_vfs"])
            ),
        }


# Linux/netdev/mlx5 object helpers


def _health_status(
    fatal_error: Optional[int],
    miss_counter: Optional[int],
    syndrome: Optional[int],
) -> str:
    if fatal_error not in (None, 0):
        return "fatal"
    if syndrome not in (None, 0):
        return "syndrome"
    if miss_counter not in (None, 0):
        return "missed"
    if fatal_error == 0 and miss_counter == 0 and syndrome == 0:
        return "ok"
    return "unavailable"


def _netdev_name(netdev: Object) -> str:
    if netdev_name is not None:
        try:
            return netdev_name(netdev).decode("utf-8", "replace")
        except Exception:
            pass
    name = _safe_cstr(_safe_member(netdev, "name"))
    return name or "<unknown>"


def _mlx5e_priv_from_netdev(netdev: Object) -> Optional[Object]:
    try:
        return netdev_priv(netdev, "struct mlx5e_priv")
    except Exception:
        pass
    netdev_addr = _addr(netdev)
    netdev_size = _sizeof_type(netdev.prog_, "struct net_device")
    if netdev_addr is not None and netdev_size is not None:
        priv_addr = (int(netdev_addr) + int(netdev_size) + 31) & ~31
        priv = _safe_pointer(netdev.prog_, "struct mlx5e_priv *", priv_addr)
        if _safe_member(priv, "mdev") is not None:
            return priv
    ml_priv = _safe_member(netdev, "ml_priv")
    if ml_priv is not None and not _is_null(ml_priv):
        try:
            return cast("struct mlx5e_priv *", ml_priv)
        except Exception:
            return None
    return None


def _looks_like_mlx5_netdev(
    netdev: Object,
    driver: Optional[str],
    priv: Optional[Object],
    mdev: Optional[Object],
) -> bool:
    if driver and driver.startswith("mlx5"):
        return True
    netdev_ops = _safe_member(netdev, "netdev_ops")
    symbol = _symbol_for_addr(netdev.prog_, _addr(netdev_ops))
    if symbol and "mlx5" in symbol:
        return True
    if not _mdev_has_mlx5_core_shape(mdev):
        return False
    return (
        _mlx5e_priv_points_to_netdev(priv, netdev)
        or _pci_bdf_from_mdev(mdev) is not None
    )


def _mlx5e_priv_points_to_netdev(
    priv: Optional[Object], netdev: Object
) -> bool:
    priv_netdev = _safe_member(priv, "netdev")
    priv_netdev_addr = _addr(priv_netdev)
    netdev_addr = _addr(netdev)
    return (
        priv_netdev_addr is not None
        and netdev_addr is not None
        and priv_netdev_addr == netdev_addr
    )


def _mdev_has_mlx5_core_shape(mdev: Optional[Object]) -> bool:
    if mdev is None or _is_null(mdev):
        return False
    return (
        _safe_member(mdev, "priv") is not None
        and _safe_member(mdev, "cmd") is not None
    )


def _driver_name_from_netdev(netdev: Object) -> Optional[str]:
    dev = _safe_member(netdev, "dev")
    # net_device.dev is embedded; its PCI or auxiliary parent usually carries
    # the mlx5_core driver pointer.
    for candidate in _device_parent_walk(dev, max_depth=8):
        name = _device_driver_name(candidate)
        if name:
            return name
    return None


def _device_parent_walk(
    dev: Optional[Object], max_depth: int = 8
) -> Iterator[Object]:
    current = dev
    depth = 0
    while current is not None and not _is_null(current) and depth < max_depth:
        yield current
        current = _safe_member(current, "parent")
        depth += 1


def _device_driver_name(dev: Optional[Object]) -> Optional[str]:
    driver = _safe_member(dev, "driver")
    if driver is None or _is_null(driver):
        return None
    name = _safe_cstr(_safe_member(driver, "name"))
    if name:
        return name
    return _safe_cstr(_safe_member(_safe_member(driver, "owner"), "name"))


def _pci_bdf_from_mdev(mdev: Optional[Object]) -> Optional[str]:
    if mdev is None:
        return None
    pdev_dev = _safe_member_path(mdev, ["pdev", "dev"])
    bdf = _pci_bdf_from_device(pdev_dev)
    return bdf or _pci_bdf_from_device(_safe_member(mdev, "device"))


def _pci_bdf_from_device(dev: Optional[Object]) -> Optional[str]:
    for current in _device_parent_walk(dev, max_depth=8):
        kobj_name = _safe_cstr(_safe_member_path(current, ["kobj", "name"]))
        if kobj_name and _PCI_BDF_RE.match(kobj_name):
            return kobj_name.lower()
    return None


def _symbol_for_addr(prog: Program, addr: Optional[int]) -> Optional[str]:
    if addr is None:
        return None
    try:
        symbol = prog.symbol(addr)
        return symbol.name
    except Exception:
        return None


def _device_matches_selector(device: Dict[str, Any], selector: str) -> bool:
    candidates = {
        str(device.get("name", "")).lower(),
        str(device.get("mdev", "")).lower(),
        str(device.get("rdma_name", "")).lower(),
        str(device.get("summary", {}).get("pci_bdf", "")).lower(),
        str(device.get("summary", {}).get("rdma_name", "")).lower(),
    }
    discovery = device.get("discovery", {})
    if isinstance(discovery, dict):
        candidates.add(str(discovery.get("rdma_name", "")).lower())
    mdev = device.get("_mdev_obj")
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
    stats_obj = _safe_member(netdev, "stats")
    stats: Dict[str, Optional[int]] = {}
    if stats_obj is not None:
        for field in (
            "rx_packets",
            "tx_packets",
            "rx_bytes",
            "tx_bytes",
            "rx_dropped",
            "tx_dropped",
            "rx_errors",
            "tx_errors",
        ):
            stats[field] = _safe_int(_safe_member(stats_obj, field))
    return {
        "ifindex": _safe_int(_safe_member(netdev, "ifindex")),
        "mtu": _safe_int(_safe_member(netdev, "mtu")),
        "flags": _hex(_safe_int(_safe_member(netdev, "flags"))),
        "operstate": _safe_int(_safe_member(netdev, "operstate")),
        "carrier": _netdev_carrier_state(netdev),
        "ip_addresses": _netdev_ip_addresses(netdev),
        "num_tx_queues": _first_int_path(
            netdev, (["real_num_tx_queues"], ["num_tx_queues"])
        ),
        "num_rx_queues": _first_int_path(
            netdev, (["real_num_rx_queues"], ["num_rx_queues"])
        ),
        "stats": stats,
    }


def _netdev_ip_addresses(netdev: Object) -> List[str]:
    addresses: List[str] = []
    for helper in (netdev_ipv4s, netdev_ipv6s):
        try:
            values: Any = helper(netdev)
        except Exception:
            continue
        for value in values:
            ip = str(value)
            if ip not in addresses:
                addresses.append(ip)
            if len(addresses) >= MAX_NETDEV_IPS:
                return addresses
    return addresses


def _collect_mlx5e_priv_summary(priv: Optional[Object]) -> Dict[str, Any]:
    if priv is None:
        return {"status": "unavailable"}
    channels, channels_source = _first_member_path_with_source(
        priv, _MLX5E_CHANNELS_OBJECT_PATHS
    )
    return {
        "address": _hex(_addr(priv)),
        "mdev": _hex(_addr(_safe_member(priv, "mdev"))),
        "netdev": _hex(_addr(_safe_member(priv, "netdev"))),
        "state": _hex(_safe_int(_safe_member(priv, "state"))),
        "stats_nch": _safe_int(_safe_member(priv, "stats_nch")),
        "max_nch": _safe_int(_safe_member(priv, "max_nch")),
        "max_opened_tc": _safe_int(_safe_member(priv, "max_opened_tc")),
        "tx_ptp_opened": _safe_int(_safe_member(priv, "tx_ptp_opened")),
        "rx_ptp_opened": _safe_int(_safe_member(priv, "rx_ptp_opened")),
        "channels": _hex(_addr(channels)),
        "channels_source": channels_source,
        "channels_num": _first_int_path(
            channels, (["num"], ["num_channels"], ["params", "num_channels"])
        ),
        "profile": _hex(_addr(_safe_member(priv, "profile"))),
    }


def _netdev_carrier_state(netdev: Object) -> str:
    up = _safe_int(_safe_member(netdev, "carrier_up_count"))
    down = _safe_int(_safe_member(netdev, "carrier_down_count"))
    if up is not None and down is not None:
        if up == down == 0:
            return "unknown"
        return "up" if up >= down else "down"
    operstate = _safe_int(_safe_member(netdev, "operstate"))
    if operstate == 6:
        return "up"
    if operstate in (2, 3):
        return "down"
    return "unknown"


def _sum_known(values: Iterable[Any]) -> Optional[int]:
    total = 0
    for value in values:
        if value is None:
            return None
        number = _safe_int(value)
        if number is None:
            return None
        total += number
    return total
