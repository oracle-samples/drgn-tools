# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Inspect mlx5 state in live kernels and vmcores.

mlx5 structures vary across upstream, UEK, and OFED kernels, and vmcore pages
may be missing. Unreadable fields produce partial data and warnings.

Examples::
    corelens /proc/kcore -C -M mlx5
    corelens <vmcore> -M mlx5
    corelens <vmcore> -M mlx5 --netdev eth0 --queues
    corelens <vmcore> -M mlx5 --dump-cqe --cqn 123 --maxcqe 64

The default report includes device, queue, CQ, EQ, QP, and limited descriptor
sections. The --max* options can cap sections for smaller captures.
"""
import argparse
import json
from collections import Counter
from collections import defaultdict
from collections import OrderedDict
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterator
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple
from typing import TypeVar
from typing import Union

from drgn import cast
from drgn import container_of
from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn import ProgramFlags
from drgn import TypeKind
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.cpumask import cpumask_to_cpulist
from drgn.helpers.linux.list import list_count_nodes
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.net import netdev_priv
from drgn.helpers.linux.radixtree import radix_tree_for_each
from drgn.helpers.linux.xarray import xa_for_each

from .mlx5_support import collect_device
from .mlx5_support import decode
from .mlx5_support import defs
from .mlx5_support import dumps
from .mlx5_support import format as formatting
from .mlx5_support import render
from .mlx5_support import selection
from drgn_tools.corelens import CorelensModule
from drgn_tools.irq import irq_to_desc
from drgn_tools.util import has_member


# Short aliases used throughout this module.
MAX_DEFAULT_DESCRIPTOR_ENTRIES = defs.MAX_DEFAULT_DESCRIPTOR_ENTRIES
DeviceRecord = collect_device.DeviceRecord
_decode_cqe = decode._decode_cqe
_decode_eqe = decode._decode_eqe
_decode_rq_wqe = decode._decode_rq_wqe
_decode_wqe = decode._decode_wqe
_jsonable = formatting._jsonable

_KeyT = TypeVar("_KeyT")


class Mlx5(CorelensModule):
    """Inspect mlx5 devices, queues, and descriptors."""

    name = "mlx5"
    run_when = "never"
    need_dwarf = False
    live_ok = True

    @property
    def skip_unless_have_kmods(self) -> List[str]:
        return ["mlx5_core"]

    @property
    def debuginfo_kmods(self) -> List[str]:
        return ["mlx5_core", "mlx5_ib"]

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        for option, help_text in (
            (
                "dev",
                "Restrict by RDMA device name, PCI BDF, or mlx5_core_dev address",
            ),
            ("netdev", "Restrict to one netdev name, for example eth0"),
            ("ip", "Restrict to devices with this netdev IP address"),
        ):
            parser.add_argument(f"--{option}", help=help_text)
        report_mode = parser.add_mutually_exclusive_group()
        for option, help_text in (
            ("summary", "Include only the report and device summary"),
            ("full", "Include all tables and automatic descriptor dumps"),
        ):
            report_mode.add_argument(
                f"--{option}", action="store_true", help=help_text
            )
        for option, help_text in (
            ("queues", "Include mlx5e channel/SQ/RQ state"),
            ("cqs", "Include completion queue summary"),
            ("ib-cqs", "Include only mlx5_ib completion queues"),
            ("eth-cqs", "Include only mlx5e/Ethernet completion queues"),
            ("eqs", "Include event queue summary"),
            ("qps", "Include queue pair summary where discoverable"),
        ):
            parser.add_argument(
                f"--{option}", action="store_true", help=help_text
            )
        parser.add_argument(
            "--qp-creator",
            dest="qp_creators",
            action="append",
            choices=("kernel", "user"),
            default=[],
            help="Show only kernel- or user-created QPs; may be repeated to select both",
        )
        for option, help_text in (
            (
                "dump-cqe",
                "Dump CQEs around the consumer index; all matching CQs if --cqn is omitted",
            ),
            (
                "dump-eqe",
                "Dump EQEs for all selected EQs, or one EQ with --eqn",
            ),
            (
                "dump-wqe",
                "Dump WQEs for --qpn, --sqn, or --rqn when a ring is discoverable",
            ),
        ):
            parser.add_argument(
                f"--{option}", action="store_true", help=help_text
            )
        for option, help_text in (
            ("cqn", "Completion queue number for --dump-cqe"),
            ("eqn", "Event queue number for --dump-eqe"),
            ("qpn", "Queue pair number for --dump-wqe or QP filtering"),
            ("sqn", "mlx5e send queue number for --dump-wqe"),
            ("rqn", "mlx5e receive queue number for --dump-wqe"),
        ):
            parser.add_argument(
                f"--{option}", type=lambda text: int(text, 0), help=help_text
            )
        for option, alias, label in (
            ("maxqueues", "max-queues", "mlx5e queue rows"),
            ("maxcq", "max-cq", "CQs"),
            ("maxeq", "max-eq", "EQs"),
            ("maxqp", "max-qp", "QPs"),
        ):
            parser.add_argument(
                f"--{option}",
                f"--{alias}",
                type=int,
                default=None,
                help=f"Maximum {label} to print or auto-dump, default: no cap",
            )
        for option, alias, entry, target in (
            ("maxcqe", "max-cqe", "CQE", "selected CQ"),
            ("maxeqe", "max-eqe", "EQE", "selected EQ"),
            ("maxwqe", "max-wqe", "WQE", "selected queue/QP"),
        ):
            parser.add_argument(
                f"--{option}",
                f"--{alias}",
                type=int,
                default=MAX_DEFAULT_DESCRIPTOR_ENTRIES,
                help=f"Maximum {entry} entries to dump per {target}, default: 32",
            )
        parser.add_argument(
            "--json", action="store_true", help="Emit machine-readable JSON"
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        _run_mlx5_report(prog, args)


def mlx5_report(
    prog: Program,
    dev: Optional[str] = None,
    netdev: Optional[str] = None,
    ip: Optional[str] = None,
    summary: bool = False,
    full: bool = False,
    queues: bool = False,
    cqs: bool = False,
    ib_cqs: bool = False,
    eth_cqs: bool = False,
    eqs: bool = False,
    qps: bool = False,
    qp_creators: Optional[Sequence[str]] = None,
    dump_cqe: bool = False,
    dump_eqe: bool = False,
    dump_wqe: bool = False,
    cqn: Optional[int] = None,
    eqn: Optional[int] = None,
    qpn: Optional[int] = None,
    sqn: Optional[int] = None,
    rqn: Optional[int] = None,
    maxqueues: Optional[int] = None,
    maxcq: Optional[int] = None,
    maxeq: Optional[int] = None,
    maxqp: Optional[int] = None,
    maxcqe: int = MAX_DEFAULT_DESCRIPTOR_ENTRIES,
    maxeqe: int = MAX_DEFAULT_DESCRIPTOR_ENTRIES,
    maxwqe: int = MAX_DEFAULT_DESCRIPTOR_ENTRIES,
    json_output: bool = False,
) -> Dict[str, Any]:
    """Collect, render, and return an mlx5 report."""

    report_args = locals().copy()
    report_args.pop("prog")
    report_args["json"] = report_args.pop("json_output")
    report_args["qp_creators"] = list(qp_creators or [])
    return _run_mlx5_report(prog, argparse.Namespace(**report_args))


def _run_mlx5_report(
    prog: Program, args: argparse.Namespace
) -> Dict[str, Any]:
    selection._resolve_report_sections(args)
    _validate_args(args)

    report = Mlx5Collector(prog, args).collect()

    if args.json:
        print(json.dumps(_jsonable(report), indent=2, sort_keys=True))
    else:
        render.render_report(report, args)
    return report


def _new_channel_record(
    channel: Object,
    index: Union[int, str],
    cpu: Optional[int] = None,
) -> Dict[str, Any]:
    napi = channel.napi
    return {
        "index": index,
        "address": formatting._hex(int(channel)),
        "cpu": cpu,
        "napi": formatting._hex(int(napi.address_of_())),
        "napi_id": int(napi.napi_id),
        "napi_state": formatting._hex(int(napi.state)),
        "napi_weight": int(napi.weight),
        "napi_poll_owner": int(napi.poll_owner),
        "irq_desc": None,
        "irqn": None,
        "eqn": None,
        "vector": None,
        "tx_sqs": [],
        "xdp_sqs": [],
        "icosqs": [],
        "rx_rq": None,
    }


class _RingEntry(NamedTuple):
    """Report record and WQ used for later dumps."""

    record: Dict[str, Any]
    wq: Optional[Object]


class _EqEntry(NamedTuple):
    """Report record and EQ used by later CQ/EQE walks."""

    record: Dict[str, Any]
    core: Object


class _QpEntry(NamedTuple):
    """Report record plus the SQ used for WQE and WR-ID reads."""

    record: Dict[str, Any]
    sq_wq: Optional[Object]


class Mlx5Collector:
    """Collect one mlx5 report."""

    def __init__(self, prog: Program, args: argparse.Namespace) -> None:
        self.prog = prog
        self.args = args
        self.warnings: List[str] = []
        self._want_cqs = bool(args.cqs)
        self._want_qps = bool(args.qps or args.dump_wqe or args.dump_cqe)
        self._want_channels = bool(
            args.queues
            or args.dump_wqe
            or args.eth_cqs
            or args.dump_cqe
            or (args.cqs and not args.ib_cqs)
        )
        self._want_eqs = bool(
            args.eqs or self._want_cqs or self._want_channels
        )
        self._summary_counts_only = bool(
            args.summary
            and not args.full
            and not any(
                (
                    self._want_channels,
                    self._want_eqs,
                    self._want_cqs,
                    self._want_qps,
                )
            )
        )
        self._cqs: Dict[Tuple[str, int], _RingEntry] = {}
        self._eqs: Dict[Tuple[str, int], _EqEntry] = {}
        self._qps: Dict[int, _QpEntry] = {}
        self._mlx5e_queues: Dict[Tuple[str, str, int, str], _RingEntry] = {}
        self._ibdev_by_mdev: Dict[int, Object] = {}
        self._qp_creators: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self._ib_cq_numbers: Dict[int, int] = {}
        self._ib_qpt_driver: Optional[int] = None
        self._qp_has_type: Optional[bool] = None
        self._qp_has_is_rss: Optional[bool] = None
        self._cq_event_names: Dict[int, Optional[str]] = {}
        self._constants: Dict[str, Object] = {}
        self._txq_state_type: Any = None
        self._eq_table_has_xarray: Optional[bool] = None
        self._eq_has_cq_count: Optional[bool] = None
        self._eqe_size: Optional[int] = None
        self._wqe_warning_groups: "OrderedDict[Tuple[str, str, str], Dict[str, Any]]" = (
            OrderedDict()
        )

    def _discover_devices(self) -> List[DeviceRecord]:
        devices_by_key: Dict[str, DeviceRecord] = {}
        saw_netdev = False

        for mdev in collect_device.for_each_mlx5_core_dev(self.prog):
            if not mdev:
                raise ValueError("mlx5 driver device has no mlx5_core_dev")
            mdev_addr = int(mdev)
            key = hex(mdev_addr)
            device = devices_by_key[key] = DeviceRecord(mdev)
            ibdev = collect_device.mlx5_core_ib_device(mdev)
            if ibdev:
                ib_mdev = ibdev.mdev
                if not ib_mdev:
                    raise ValueError("mlx5_ib_dev.mdev is NULL")
                if int(ib_mdev) != mdev_addr:
                    raise ValueError(
                        "mlx5_ib_dev.mdev does not match its core device"
                    )
                device.rdma_name = ibdev.ib_dev.name.string_().decode(
                    "utf-8", "replace"
                )
                device.rdma_port = 1
                device.rdma_ibdev = formatting._hex(int(ibdev))
                self._ibdev_by_mdev[mdev_addr] = ibdev

            netdev = collect_device.mlx5_netdev(mdev)
            if not netdev:
                continue
            name = escape_ascii_string(netdev.name.string_())
            saw_netdev = True
            if self.args.netdev and name != self.args.netdev:
                continue

            netdev_ops = collect_device._symbol_for_addr(
                self.prog, int(netdev.netdev_ops)
            )
            priv = netdev_priv(netdev, "struct mlx5e_priv")
            if int(priv.mdev) != mdev_addr:
                raise ValueError(
                    f"{name}: mlx5e_priv.mdev does not match its core device"
                )
            device.netdevs.append(
                {
                    "name": name,
                    "driver": netdev_ops,
                    "summary": collect_device._collect_netdev_summary(netdev),
                    "priv": collect_device._collect_mlx5e_priv_summary(priv),
                    "channels": [],
                    "channels_collected": False,
                    "_netdev_obj": netdev,
                    "_priv_obj": priv,
                }
            )

        if self.args.netdev:
            devices_by_key = {
                key: device
                for key, device in devices_by_key.items()
                if any(
                    n.get("name") == self.args.netdev for n in device.netdevs
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

    def _filter_devices(
        self, devices: List[DeviceRecord]
    ) -> List[DeviceRecord]:
        filtered = devices
        if self.args.dev:
            selector = str(self.args.dev).lower()
            filtered = [
                dev
                for dev in filtered
                if collect_device._device_matches_selector(dev, selector)
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
                if collect_device._device_has_ip(dev, str(ip_selector))
            ]
            if not filtered:
                self._warn(
                    f"--ip {ip_selector!r} did not match a discovered mlx5 netdev address"
                )
        return filtered

    def _collect_device_details(self, device: DeviceRecord) -> None:
        device.summary = self._collect_core_summary(device.mdev, device)
        device.health = self._collect_health(device.mdev)
        device.capabilities = self._collect_capabilities(device.mdev)

        for netdev in device.netdevs:
            priv = netdev.get("_priv_obj")
            if self._want_channels:
                netdev["channels"] = self._collect_channels(
                    device, netdev, priv
                )
                netdev["channels_collected"] = True

    def _set_device_counts(self, devices: Sequence[DeviceRecord]) -> None:
        object_counts: Dict[str, Dict[str, int]] = {
            device.mdev_address: {"cqs": 0, "eqs": 0, "qps": 0}
            for device in devices
        }
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
            if not wanted:
                continue
            for record in records:
                device_name = record.get("device")
                counts = (
                    object_counts.get(device_name)
                    if device_name is not None
                    else None
                )
                if counts is not None:
                    counts[count_name] += 1

        for device in devices:
            netdevs = device.netdevs
            channels_collected = all(
                netdev.get("channels_collected", False) for netdev in netdevs
            )
            channel_count = queue_count = 0
            tx_sqs = rx_rqs = xdp_sqs = 0
            if channels_collected:
                for netdev in netdevs:
                    for channel in netdev.get("channels", []):
                        tx_count = len(channel.get("tx_sqs", []))
                        xdp_count = len(channel.get("xdp_sqs", []))
                        rx_count = bool(channel.get("rx_rq"))
                        channel_count += 1
                        queue_count += (
                            tx_count
                            + xdp_count
                            + rx_count
                            + len(channel.get("xsk_rqs", []))
                            + len(channel.get("icosqs", []))
                        )
                        tx_sqs += tx_count
                        rx_rqs += rx_count
                        xdp_sqs += xdp_count
            device_counts = object_counts[device.mdev_address]
            device.counts = {
                "netdevs": len(netdevs),
                "channels": channel_count if channels_collected else None,
                "queues": queue_count if channels_collected else None,
                "tx_sqs": tx_sqs if channels_collected else None,
                "rx_rqs": rx_rqs if channels_collected else None,
                "xdp_sqs": xdp_sqs if channels_collected else None,
                "cqs": device_counts["cqs"] if self._want_cqs else None,
                "eqs": device_counts["eqs"] if self._want_eqs else None,
                "qps": device_counts["qps"] if self._want_qps else None,
            }

    def _collect_core_summary(
        self, mdev: Object, device: DeviceRecord
    ) -> Dict[str, Any]:
        return {
            "mdev": device.mdev_address,
            "rdma_name": device.rdma_name,
            "rdma_port": device.rdma_port,
            "rdma_ibdev": device.rdma_ibdev,
            "pci_bdf": collect_device._pci_bdf_from_mdev(mdev)
            or "unavailable",
            "coredev_type": formatting._enum_name(
                mdev.coredev_type, "MLX5_COREDEV_"
            ),
            "device_state": formatting._enum_name(
                mdev.state, "MLX5_DEVICE_STATE_"
            ),
            "pci_status": formatting._enum_name(
                mdev.pci_status, "MLX5_PCI_STATUS_"
            ),
            "cmd_state": formatting._enum_name(
                mdev.cmd.state, "MLX5_CMDIF_STATE_"
            ),
            "intf_state": formatting._hex(int(mdev.intf_state)),
            "board_id": mdev.board_id.string_().decode("utf-8", "replace"),
            "rev_id": int(mdev.rev_id),
            "sys_image_guid": formatting._hex(int(mdev.sys_image_guid)),
            "numa_node": int(mdev.priv.numa_node),
            "fw_version": self._collect_fw_version(mdev),
        }

    def _collect_fw_version(self, mdev: Object) -> str:
        ibdev = self._ibdev_by_mdev.get(int(mdev))
        if ibdev is not None:
            try:
                fw_ver = formatting._format_ib_fw_ver(
                    int(ibdev.ib_dev.attrs.fw_ver)
                )
                if fw_ver is not None:
                    return fw_ver
            except FaultError:
                pass

        try:
            iseg = mdev.iseg
            if iseg:
                fw_ver = formatting._format_iseg_fw_revision(
                    int(iseg.fw_rev),
                    int(iseg.cmdif_rev_fw_sub),
                )
                if fw_ver is not None:
                    return fw_ver
        except FaultError:
            pass
        return "unavailable"

    def _collect_health(self, mdev: Object) -> Dict[str, Any]:
        health = mdev.priv.health
        fatal_error = int(health.fatal_error)
        miss_counter = int(health.miss_counter)
        syndrome = int(health.synd)
        return {
            "status": collect_device._health_status(
                fatal_error, miss_counter, syndrome
            ),
            "fatal_error": fatal_error,
            "miss_counter": miss_counter,
            "syndrome": formatting._hex(syndrome),
            "prev_counter": int(health.prev),
            "flags": formatting._hex(int(health.flags)),
            "crdump_size": int(health.crdump_size),
            "health_buffer": formatting._hex(int(health.health)),
            "health_counter": formatting._hex(int(health.health_counter)),
            "workqueue": formatting._hex(int(health.wq)),
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
            "sriov_enabled_vfs": int(sriov.num_vfs),
        }

    def collect(self) -> Dict[str, Any]:
        devices = self._discover_devices()
        devices = self._filter_devices(devices)

        for device in devices:
            self._collect_device_details(device)

        if self._summary_counts_only:
            for device in devices:
                self._collect_summary_counts(device)
        else:
            for device in devices:
                if self._want_eqs:
                    self._collect_eqs_from_device(device)
                if self._want_cqs:
                    self._collect_cqs_from_eq_tables(device)
                if self._want_qps:
                    for qp in self._iter_qps_from_device(device):
                        self._record_qp(qp, device)

            self._link_cqs_eqs_and_channels(devices)
            self._set_device_counts(devices)

        dump_reports = self._collect_requested_dumps()
        self._flush_wqe_warning_groups()

        def object_count(
            name: str, records: Dict[Any, Any], collected: bool
        ) -> Optional[int]:
            if self._summary_counts_only:
                return collect_device._sum_known(
                    d.counts.get(name) for d in devices
                )
            return len(records) if collected else None

        return {
            "module": "mlx5",
            "mode": (
                "live" if self.prog.flags & ProgramFlags.IS_LIVE else "vmcore"
            ),
            "selection": {
                name: value
                for name, value in vars(self.args).items()
                if not name.startswith("_") and name != "json"
            },
            "devices": [device.to_dict() for device in devices],
            "cqs": sorted(
                (e.record for e in self._cqs.values()),
                key=lambda r: formatting._sort_key(r.get("cqn")),
            ),
            "eqs": sorted(
                (e.record for e in self._eqs.values()),
                key=lambda r: formatting._sort_key(r.get("eqn")),
            ),
            "qps": self._report_qps(),
            "dumps": dump_reports,
            "findings": self._analyze_findings(devices, dump_reports),
            "warnings": self.warnings,
            "counts": {
                "devices": len(devices),
                "netdevs": sum(len(d.netdevs) for d in devices),
                "channels": collect_device._sum_known(
                    d.counts.get("channels") for d in devices
                ),
                "queues": collect_device._sum_known(
                    d.counts.get("queues") for d in devices
                ),
                "cqs": object_count("cqs", self._cqs, self._want_cqs),
                "eqs": object_count("eqs", self._eqs, self._want_eqs),
                "qps": object_count("qps", self._qps, self._want_qps),
            },
        }

    def _collect_summary_counts(self, device: DeviceRecord) -> None:
        """Collect counts without building detailed records."""

        channels, queues = self._count_summary_channels_and_queues(device)
        eqs, cqs = self._count_summary_eqs_and_cqs(device)
        device.counts.update(
            {
                "netdevs": len(device.netdevs),
                "channels": channels,
                "queues": queues,
                "tx_sqs": None,
                "rx_rqs": None,
                "xdp_sqs": None,
                "cqs": cqs,
                "eqs": eqs,
                "qps": self._count_summary_qps(device),
            }
        )

    # Channels, Ethernet queues, and their CQs

    def _constant(self, name: str) -> Object:
        constant = self._constants.get(name)
        if constant is None:
            constant = self.prog.constant(name)
            self._constants[name] = constant
        return constant

    def _count_summary_channels_and_queues(
        self,
        device: DeviceRecord,
    ) -> Tuple[int, int]:
        channel_total = 0
        queue_total = 0
        xsk_bit = int(self._constant("MLX5E_CHANNEL_STATE_XSK"))
        for netdev in device.netdevs:
            priv = netdev["_priv_obj"]
            channels_obj, count, channel_array = self._channel_layout(priv)
            for index in range(count):
                channel = channel_array[index]
                if not channel:
                    continue
                channel_total += 1
                queue_total += 3 + max(
                    0, min(int(channel.num_tc), defs.MAX_TC)
                )
                qos_sqs = channel.qos_sqs
                if qos_sqs:
                    qos_sqs_size = min(
                        max(int(channel.qos_sqs_size), 0), defs.MAX_QOS_SQS
                    )
                    queue_total += sum(
                        bool(qos_sqs[index]) for index in range(qos_sqs_size)
                    )
                if int(channel.xdp):
                    queue_total += 1
                xdpsq = channel.xdpsq
                if (xdpsq.type_.kind != TypeKind.POINTER or xdpsq) and int(
                    xdpsq.sqn
                ):
                    queue_total += 1
                if int(channel.state[0]) & (1 << xsk_bit):
                    queue_total += 2

            ptp_queues = self._count_summary_ptp_queues(channels_obj)
            if ptp_queues:
                channel_total += 1
                queue_total += ptp_queues
        return channel_total, queue_total

    def _channel_layout(
        self,
        priv: Object,
    ) -> Tuple[Object, int, Object]:
        channels = priv.channels
        count = min(max(int(channels.num), 0), defs.MAX_CHANNELS)
        return channels, count, channels.c

    def _iter_channel_queues(
        self, channel: Object
    ) -> Iterator[Tuple[str, Object, str, str, Optional[int]]]:
        yield "rx_rq", channel.rq, "rq", "rx", None

        num_tc = min(int(channel.num_tc), defs.MAX_TC)
        for tc in range(num_tc):
            yield "tx_sqs", channel.sq[tc], "sq", "tx", tc

        qos_sqs = channel.qos_sqs
        if qos_sqs:
            count = min(max(int(channel.qos_sqs_size), 0), defs.MAX_QOS_SQS)
            for index in range(count):
                sq = qos_sqs[index]
                if sq:
                    yield "tx_sqs", sq, "qos_sq", "tx", index

        if int(channel.xdp):
            yield "xdp_sqs", channel.rq_xdpsq, "rq_xdpsq", "xdp", None

        xdpsq = channel.xdpsq
        if (xdpsq.type_.kind != TypeKind.POINTER or xdpsq) and int(xdpsq.sqn):
            yield "xdp_sqs", xdpsq, "xdpsq", "xdp", None

        xsk_bit = int(self._constant("MLX5E_CHANNEL_STATE_XSK"))
        if int(channel.state[0]) & (1 << xsk_bit):
            yield "xsk_rqs", channel.xskrq, "xskrq", "rx", None
            yield "xdp_sqs", channel.xsksq, "xsksq", "xdp", None

        yield "icosqs", channel.icosq, "icosq", "internal", None
        yield (
            "icosqs",
            channel.async_icosq,
            "async_icosq",
            "internal",
            None,
        )

    def _count_summary_ptp_queues(self, channels_obj: Object) -> int:
        ptp, state = self._ptp_object(channels_obj)
        if ptp is None:
            return 0
        count = 0
        rx_bit = int(self._constant("MLX5E_PTP_STATE_RX"))
        if state & (1 << rx_bit):
            count += 1
        tx_bit = int(self._constant("MLX5E_PTP_STATE_TX"))
        if state & (1 << tx_bit):
            count += max(0, min(int(ptp.num_tc), defs.MAX_TC))
        return count

    def _ptp_object(
        self, channels_obj: Object
    ) -> Tuple[Optional[Object], int]:
        ptp = channels_obj.ptp
        if not ptp:
            return None, 0
        state = int(ptp.state[0])
        return (None, state) if state == 0 else (ptp, state)

    def _iter_ptp_sqs(
        self, ptp: Object, state: int
    ) -> Iterator[Tuple[int, Object]]:
        tx_bit = int(self._constant("MLX5E_PTP_STATE_TX"))
        if not state & (1 << tx_bit):
            return
        for tc in range(min(int(ptp.num_tc), defs.MAX_TC)):
            yield tc, ptp.ptpsq[tc]

    def _collect_channels(
        self,
        device: DeviceRecord,
        netdev_record: Dict[str, Any],
        priv: Object,
    ) -> List[Dict[str, Any]]:
        channels, channel_count, channel_array = self._channel_layout(priv)

        result = []
        for index in range(channel_count):
            channel = channel_array[index]
            if not channel:
                continue
            result.append(
                self._collect_channel(
                    device,
                    netdev_record,
                    channel,
                )
            )
        ptp_record = self._collect_ptp_channel(device, netdev_record, channels)
        if ptp_record is not None:
            result.append(ptp_record)
        return result

    def _collect_ptp_channel(
        self,
        device: DeviceRecord,
        netdev_record: Dict[str, Any],
        channels_obj: Object,
    ) -> Optional[Dict[str, Any]]:
        ptp, state = self._ptp_object(channels_obj)
        if ptp is None:
            return None
        record = _new_channel_record(ptp, "ptp")
        record.update({"ptp": True, "state": formatting._hex(state)})

        rx_bit = int(self._constant("MLX5E_PTP_STATE_RX"))
        if state & (1 << rx_bit):
            record["rx_rq"] = self._collect_queue(
                device,
                netdev_record,
                "ptp",
                ptp.rq,
                kind="ptp_rq",
                role="rx",
            )

        for tc, ptpsq in self._iter_ptp_sqs(ptp, state):
            record["tx_sqs"].append(
                self._collect_queue(
                    device,
                    netdev_record,
                    "ptp",
                    ptpsq.txqsq,
                    kind="ptp_sq",
                    role="tx",
                    tc=tc,
                )
            )
            ts_cq = ptpsq.ts_cq
            self._collect_mlx5e_cq(
                ts_cq,
                {
                    "device": device.mdev_address,
                    "netdev": netdev_record.get("name"),
                    "channel": "ptp",
                    "queue_kind": "ptp_ts_cq",
                    "queue_role": "timestamp",
                    "queue_number": int(ts_cq.mcq.cqn),
                    "tc": tc,
                },
            )

        if record["rx_rq"] is None and not record["tx_sqs"]:
            return None
        return record

    def _collect_channel(
        self,
        device: DeviceRecord,
        netdev_record: Dict[str, Any],
        channel: Object,
    ) -> Dict[str, Any]:
        channel_index = int(channel.ix)
        cpu = int(channel.cpu)
        record = _new_channel_record(channel, channel_index, cpu=cpu)

        for (
            report_field,
            queue,
            kind,
            role,
            tc,
        ) in self._iter_channel_queues(channel):
            queue_record = self._collect_queue(
                device,
                netdev_record,
                channel_index,
                queue,
                kind=kind,
                role=role,
                tc=tc,
            )
            if report_field == "rx_rq":
                record[report_field] = queue_record
            else:
                record.setdefault(report_field, []).append(queue_record)

        return record

    def _collect_queue(
        self,
        device: DeviceRecord,
        netdev_record: Dict[str, Any],
        channel_index: Union[int, str],
        queue_obj: Object,
        kind: str,
        role: str,
        tc: Optional[int] = None,
    ) -> Dict[str, Any]:
        is_rq = kind in ("rq", "xskrq", "ptp_rq")
        number_field = "rqn" if is_rq else "sqn"
        qn = int(queue_obj.member_(number_field))
        device_name = device.mdev_address
        netdev_name = netdev_record["name"]
        state = int(queue_obj.state)
        wq, wq_source = self._queue_wq(queue_obj, is_rq)
        if is_rq:
            progress = _rq_progress_detail(wq, wq_source)
        else:
            pc = int(queue_obj.pc)
            cc = int(queue_obj.cc)
            inflight = _nonnegative_delta(pc, cc)
            progress = dict(
                pc=pc,
                cc=cc,
                inflight=inflight,
                pc_source="queue.pc",
                cc_source="queue.cc",
                inflight_source="pc-cc" if inflight is not None else None,
            )
        cq = queue_obj.cq
        owner = {
            "device": device_name,
            "netdev": netdev_name,
            "channel": channel_index,
            "queue_kind": kind,
            "queue_role": role,
            "queue_number": qn,
            "tc": tc,
        }
        cq_record = self._collect_mlx5e_cq(cq, owner)

        txq = queue_obj.txq if kind in ("sq", "qos_sq", "ptp_sq") else None
        txq_state = int(txq.state) if txq else None
        state_prefix = "MLX5E_RQ_STATE_" if is_rq else "MLX5E_SQ_STATE_"
        enabled_bit = self._constant(state_prefix + "ENABLED")
        recovering_bit = self._constant(state_prefix + "RECOVERING")
        if self._txq_state_type is None:
            self._txq_state_type = self.prog.type("enum netdev_queue_state_t")

        record = {
            "kind": kind,
            "role": role,
            "tc": tc,
            "owner": _owner_string(owner),
            "device": device_name,
            "netdev": netdev_name,
            "channel": channel_index,
            "address": formatting._hex(int(queue_obj.address_of_())),
            "number": qn,
            "number_source": f"queue.{number_field}",
            **progress,
            "state": formatting._hex(state),
            "state_flags": formatting._enum_flags(
                state, enabled_bit.type_, state_prefix
            ),
            "enabled": bool(state & (1 << int(enabled_bit))),
            "recovering": bool(state & (1 << int(recovering_bit))),
            "txq": formatting._hex(int(txq) if txq else None),
            "txq_state": formatting._hex(txq_state),
            "txq_state_flags": formatting._enum_flags(
                txq_state, self._txq_state_type, "__QUEUE_STATE_"
            ),
            "txq_stopped": bool(txq_state) if txq_state is not None else None,
            "wq": self._collect_wq_summary(wq),
            "cq": cq_record,
        }
        key = (str(device_name), number_field, qn, record["owner"])
        self._mlx5e_queues[key] = _RingEntry(record, wq)
        return record

    def _queue_wq(self, queue_obj: Object, is_rq: bool) -> Tuple[Object, str]:
        if not is_rq:
            return queue_obj.wq, "queue.wq"
        linked = int(self._constant("MLX5_WQ_TYPE_LINKED_LIST_STRIDING_RQ"))
        if int(queue_obj.wq_type) == linked:
            return queue_obj.mpwqe.wq, "rq.mpwqe.wq"
        return queue_obj.wqe.wq, "rq.wqe.wq"

    def _collect_wq_summary(
        self, wq: Optional[Object], kernel_backed: bool = True
    ) -> Dict[str, Any]:
        if wq is None:
            return {"status": "unavailable"}
        type_name = wq.type_.type_name()
        supported_types = (
            "struct mlx5_cqwq",
            "struct mlx5_ib_cq_buf",
            "struct mlx5_ib_wq",
            "struct mlx5_wq_cyc",
            "struct mlx5_wq_ll",
        )
        if type_name not in supported_types:
            raise TypeError(f"unsupported mlx5 work queue type: {type_name}")

        ib_wq = type_name == "struct mlx5_ib_wq"
        ib_cq_buf = type_name == "struct mlx5_ib_cq_buf"
        size: Optional[int]
        size_source: Optional[str]
        sz_m1: Optional[int]
        log_sz: Optional[int]
        log_stride: Optional[int]
        stride_bytes: Optional[int]
        stride_source: Optional[str]
        if ib_wq:
            wqe_count = int(wq.wqe_cnt)
            wqe_shift: Optional[int] = None
            if wqe_count > 0:
                raw_wqe_shift = int(wq.wqe_shift)
                if 0 <= raw_wqe_shift < 32:
                    wqe_shift = raw_wqe_shift
            size = wqe_count
            size_source = "wq.wqe_cnt"
            sz_m1 = log_sz = log_stride = None
            stride_bytes = 1 << wqe_shift if wqe_shift is not None else None
            stride_source = "wq.wqe_shift" if wqe_shift is not None else None
            fbc = None
            if kernel_backed and wqe_count > 0:
                fbc = wq.fbc
                sz_m1 = int(fbc.sz_m1)
                log_sz = int(fbc.log_sz)
                log_stride = int(fbc.log_stride)
        else:
            fbc = wq.fbc
            field_source = "wq.fbc"
            sz_m1 = int(fbc.sz_m1)
            log_sz = int(fbc.log_sz)
            log_stride = int(fbc.log_stride)
            if ib_cq_buf:
                size = int(wq.nent)
                size_source = "wq.nent"
                stride_bytes = int(wq.cqe_size)
                stride_source = "wq.cqe_size"
            else:
                size = sz_m1 + 1
                size_source = f"{field_source}.sz_m1"
                stride_bytes = 1 << log_stride
                stride_source = f"{field_source}.log_stride"
        summary = {
            "address": formatting._hex(int(wq.address_)),
            "size": size,
            "size_source": size_source,
            "sz_m1": sz_m1,
            "log_sz": log_sz,
            "log_stride": log_stride,
            "stride_bytes": stride_bytes,
            "stride_source": stride_source,
            "pc": None,
            "cc": None,
            "head": None,
            "wqe_counter": None,
            "cur_size": None,
            "db": None,
            "fbc": formatting._hex(None if fbc is None else int(fbc.address_)),
        }
        if type_name in (
            "struct mlx5_cqwq",
            "struct mlx5_wq_cyc",
            "struct mlx5_wq_ll",
        ):
            summary["db"] = formatting._hex(int(wq.db))
        if type_name == "struct mlx5_cqwq":
            summary["cc"] = int(wq.cc)
        elif type_name in ("struct mlx5_wq_cyc", "struct mlx5_wq_ll"):
            summary["wqe_counter"] = int(wq.wqe_ctr)
            summary["cur_size"] = int(wq.cur_sz)
            if type_name == "struct mlx5_wq_ll":
                summary["head"] = int(wq.head)
        elif ib_wq:
            summary.update(
                {
                    "tail": None,
                    "wqe_count": wqe_count,
                    "cur_post": None,
                    "max_post": int(wq.max_post)
                    if kernel_backed and wqe_count > 0
                    else None,
                    "last_poll": None,
                    "offset": int(wq.offset),
                    "wqe_shift": wqe_shift,
                    "cur_edge": None,
                }
            )
            if kernel_backed and wqe_count > 0:
                summary.update(
                    {
                        "head": int(wq.head),
                        "tail": int(wq.tail),
                        "cur_post": int(wq.cur_post),
                        "last_poll": int(wq.last_poll),
                        "cur_edge": formatting._hex(int(wq.cur_edge)),
                    }
                )
        return summary

    def _collect_mlx5e_cq(
        self, cq: Object, owner: Dict[str, Any]
    ) -> Dict[str, Any]:
        mcq = cq.mcq
        cqn = int(mcq.cqn)
        wq = cq.wq
        wq_summary = self._collect_wq_summary(wq)
        consumer_index, consumer_source, core_cons_index = _cq_consumer_index(
            "struct mlx5e_cq", wq_summary, mcq
        )
        arm_sn_raw = int(mcq.arm_sn)
        owner_name = _owner_string(owner)
        record = {
            "cqn": cqn,
            "address": formatting._hex(int(cq.address_of_())),
            "address_struct": "struct mlx5e_cq",
            "core_cq": formatting._hex(int(mcq.address_of_())),
            "core_cq_struct": "struct mlx5_core_cq",
            "core_cq_source": "struct mlx5e_cq.mcq",
            "owner": owner_name,
            "owners": [owner_name],
            "device": owner.get("device"),
            "netdev": owner.get("netdev"),
            "channel": owner.get("channel"),
            "queue_kind": owner.get("queue_kind"),
            "queue_role": owner.get("queue_role"),
            "queue_number": owner.get("queue_number"),
            "consumer_index": consumer_index,
            "consumer_index_source": consumer_source,
            "core_cons_index": core_cons_index,
            "wq_cc": wq_summary.get("cc"),
            "wq_source": "struct mlx5e_cq.wq",
            "arm_sn": _cq_arm_sn(arm_sn_raw),
            "arm_sn_raw": arm_sn_raw,
            "vector": int(mcq.vector),
            "irqn": int(mcq.irqn),
            "event_ctr": int(cq.event_ctr),
            "size": wq_summary.get("size"),
            "stride_bytes": wq_summary.get("stride_bytes"),
        }
        key = (str(owner["device"]), cqn)
        entry = self._cqs.get(key)
        if entry is not None:
            existing = entry.record
            if owner_name not in existing["owners"]:
                existing["owners"].append(owner_name)
            record = existing
        else:
            self._cqs[key] = _RingEntry(record, wq)
        return record

    # Event queues and completion queues

    def _count_summary_eqs_and_cqs(
        self,
        device: DeviceRecord,
    ) -> Tuple[int, int]:
        eq_count = sum(1 for _core, _role in self._iter_eq_candidates(device))
        async_eq = device.mdev.priv.eq_table.async_eq.core
        cq_count = sum(
            1
            for _key, _cq in radix_tree_for_each(
                async_eq.cq_table.tree.address_of_()
            )
        )
        return eq_count, cq_count

    def _iter_eq_candidates(
        self, device: DeviceRecord
    ) -> Iterator[Tuple[Object, str]]:
        eq_table = device.mdev.priv.eq_table
        for field, role in (
            ("cmd_eq", "cmd"),
            ("async_eq", "async"),
            ("pages_eq", "pages"),
        ):
            yield getattr(eq_table, field).core, role

        if self._eq_table_has_xarray is None:
            self._eq_table_has_xarray = has_member(eq_table, "comp_eqs")
        if self._eq_table_has_xarray:
            for _vector, entry in xa_for_each(eq_table.comp_eqs):
                eq_comp = cast("struct mlx5_eq_comp *", entry)
                yield eq_comp.core, "completion"
            return

        objects = list_for_each_entry(
            "struct mlx5_eq_comp",
            eq_table.comp_eqs_list.address_of_(),
            "list",
        )
        for eq_comp in objects:
            yield eq_comp.core, "completion"

    def _collect_eqs_from_device(self, device: DeviceRecord) -> None:
        for core, role in self._iter_eq_candidates(device):
            self._record_eq(core, device, role)

    def _record_eq(
        self,
        core: Object,
        device: DeviceRecord,
        role: str,
    ) -> Dict[str, Any]:
        eqn = int(core.eqn)
        irqn = int(core.irqn)
        type_name = core.type_.type_name()
        if self._eq_has_cq_count is None:
            self._eq_has_cq_count = has_member(core, "cq_count")
        if self._eqe_size is None:
            self._eqe_size = self.prog.type("struct mlx5_eqe").size
        record = {
            "eqn": eqn,
            "address": formatting._hex(int(core.address_)),
            "address_struct": type_name,
            "core_eq": formatting._hex(int(core.address_)),
            "core_eq_struct": type_name,
            "device": device.mdev_address,
            "role": role,
            "irqn": irqn,
            "irq_cpu": _irq_affinity_cpus(self.prog, irqn),
            "vector": int(core.vecidx),
            "consumer_index": int(core.cons_index),
            "size": int(core.fbc.sz_m1) + 1,
            "cq_count": int(core.cq_count) if self._eq_has_cq_count else None,
            "eqe_size": self._eqe_size,
        }

        key = (device.mdev_address, eqn)
        entry = self._eqs.get(key)
        if entry is not None:
            return entry.record
        self._eqs[key] = _EqEntry(record, core)
        return record

    def _collect_cqs_from_eq_tables(self, device: DeviceRecord) -> None:
        """Collect CQs from the device-wide async EQ table.

        Channel walks find mlx5e CQs. The async EQ table also contains RDMA
        and internal CQs.
        """

        core = device.mdev.priv.eq_table.async_eq.core
        owner = f"eq_cq_table:async:eqn{int(core.eqn)}"
        for key, obj in radix_tree_for_each(core.cq_table.tree.address_of_()):
            core_cq = cast("struct mlx5_core_cq *", obj)
            self._record_core_cq(core_cq, device, owner=owner, table_key=key)

    def _record_core_cq(
        self,
        core_cq: Object,
        device: DeviceRecord,
        owner: str,
        table_key: Optional[int] = None,
    ) -> Dict[str, Any]:
        cqn = int(core_cq.cqn)
        if table_key is not None and cqn != table_key:
            raise ValueError(
                f"CQ table key {table_key} does not match CQN {cqn}"
            )
        key = (device.mdev_address, cqn)
        entry = self._cqs.get(key)
        if entry is not None:
            record = entry.record
            owners = record.setdefault("owners", [record.get("owner")])
            if owner not in owners:
                owners.append(owner)
            record["owner"] = ";".join(str(item) for item in owners if item)
            return record

        event = self._cq_event_name(core_cq.event)
        mlx5e_cq = None
        ib_cq = None
        if event == "mlx5e_cq_error_event":
            mlx5e_cq = container_of(core_cq, "struct mlx5e_cq", "mcq")
            if int(mlx5e_cq.mdev) != int(device.mdev):
                raise ValueError("mlx5e CQ belongs to a different core device")
        elif event == "mlx5_ib_cq_event":
            ib_cq = container_of(core_cq, "struct mlx5_ib_cq", "mcq")
        address_obj, address_struct = core_cq, "struct mlx5_core_cq"
        wq = None
        netdev = None
        event_ctr = None
        specific_owner = None
        size = None
        stride_bytes = None
        queue_kind: Optional[str] = "core_cq"
        queue_role: Optional[str] = "core"
        queue_number = cqn
        if ib_cq is not None:
            address_obj, address_struct = ib_cq, "struct mlx5_ib_cq"
            size = int(ib_cq.ibcq.cqe) + 1
            stride_bytes = int(ib_cq.cqe_size)
            if not ib_cq.ibcq.uobject:
                wq = ib_cq.buf
            queue_kind, queue_role = "rdma_cq", "rdma"
        elif mlx5e_cq is not None:
            address_obj, address_struct = mlx5e_cq, "struct mlx5e_cq"
            wq = mlx5e_cq.wq
            mlx5e_owner = self._mlx5e_core_cq_owner(mlx5e_cq, core_cq, device)
            netdev = mlx5e_owner.get("netdev")
            queue_kind = mlx5e_owner.get("queue_kind")
            queue_role = mlx5e_owner.get("queue_role")
            event_ctr = int(mlx5e_cq.event_ctr)
            specific_owner = _owner_string(mlx5e_owner)
        owners = (
            [specific_owner, owner]
            if specific_owner and specific_owner != owner
            else [owner]
        )
        wq_summary = self._collect_wq_summary(wq)
        consumer_index, consumer_source, core_cons_index = _cq_consumer_index(
            address_struct, wq_summary, core_cq
        )
        arm_sn_raw = int(core_cq.arm_sn)
        record = {
            "cqn": cqn,
            "address": formatting._hex(int(address_obj)),
            "address_struct": address_struct,
            "core_cq": formatting._hex(int(core_cq)),
            "core_cq_struct": "struct mlx5_core_cq",
            "owner": ";".join(str(o) for o in owners if o),
            "owners": owners,
            "device": device.mdev_address,
            "netdev": netdev,
            "channel": None,
            "queue_kind": queue_kind,
            "queue_role": queue_role,
            "queue_number": queue_number,
            "consumer_index": consumer_index,
            "consumer_index_source": consumer_source,
            "core_cons_index": core_cons_index,
            "wq_cc": wq_summary.get("cc"),
            "arm_sn": _cq_arm_sn(arm_sn_raw),
            "arm_sn_raw": arm_sn_raw,
            "vector": int(core_cq.vector),
            "irqn": int(core_cq.irqn),
            "event_ctr": event_ctr,
            "size": size or wq_summary.get("size"),
            "stride_bytes": stride_bytes
            or wq_summary.get("stride_bytes")
            or int(core_cq.cqe_sz),
        }

        self._cqs[key] = _RingEntry(record, wq)
        return record

    def _cq_event_name(self, event: Object) -> Optional[str]:
        if not event:
            return None
        address = int(event)
        if address not in self._cq_event_names:
            self._cq_event_names[address] = collect_device._symbol_for_addr(
                self.prog, address
            )
        return self._cq_event_names[address]

    def _mlx5e_core_cq_owner(
        self, cq: Object, core_cq: Object, device: DeviceRecord
    ) -> Dict[str, Any]:
        cqn = int(core_cq.cqn)
        cq_netdev = cq.netdev
        netdev_name = None
        for netdev in device.netdevs:
            priv = netdev.get("_priv_obj")
            if priv is not None and int(cq) == int(
                priv.drop_rq.cq.address_of_()
            ):
                return {
                    "device": device.mdev_address,
                    "netdev": netdev.get("name"),
                    "queue_kind": "drop_rq_cq",
                    "queue_role": "drop",
                    "queue_number": cqn,
                }
            netdev_obj = netdev.get("_netdev_obj")
            if (
                netdev_name is None
                and cq_netdev
                and netdev_obj
                and int(cq_netdev) == int(netdev_obj)
            ):
                netdev_name = netdev.get("name")
        if netdev_name is None and cq_netdev:
            netdev_name = cq_netdev.name.string_().decode("utf-8", "replace")

        return {
            "device": device.mdev_address,
            "netdev": netdev_name,
            "queue_kind": "mlx5e_cq",
            "queue_role": "mlx5e",
            "queue_number": cqn,
        }

    def _link_cqs_eqs_and_channels(
        self, devices: Sequence[DeviceRecord]
    ) -> None:
        eq_by_vector: Dict[Tuple[str, int], Dict[str, Any]] = {}
        eq_by_irqn: Dict[Tuple[str, int], Dict[str, Any]] = {}
        for eq_record in (entry.record for entry in self._eqs.values()):
            device = eq_record.get("device")
            if device is None:
                continue
            device = str(device)
            vector = eq_record.get("vector")
            irqn = eq_record.get("irqn")
            if vector is not None:
                eq_by_vector[(device, int(vector))] = eq_record
            if irqn is not None:
                eq_by_irqn[(device, int(irqn))] = eq_record

        for cq in (entry.record for entry in self._cqs.values()):
            device = cq.get("device")
            if device is None:
                continue
            device = str(device)
            vector = cq.get("vector")
            irqn = cq.get("irqn")
            eq: Optional[Dict[str, Any]] = (
                eq_by_vector.get((device, int(vector)))
                if vector is not None
                else None
            )
            if irqn is not None:
                irq_eq = eq_by_irqn.get((device, int(irqn)))
                # IRQ is the stronger match when vector and IRQ disagree.
                if irq_eq is not None and (
                    eq is None or eq.get("irqn") != irqn
                ):
                    eq = irq_eq
            for cq_field, eq_field in (
                ("eqn", "eqn"),
                ("eq_role", "role"),
                ("eq_irqn", "irqn"),
                ("eq_irq_cpu", "irq_cpu"),
                ("eq_vector", "vector"),
                ("eq_address", "address"),
            ):
                cq[cq_field] = eq.get(eq_field) if eq is not None else None

        for device in devices:
            for netdev in device.netdevs:
                for channel in netdev.get("channels", []):
                    shared_values: Dict[str, Set[int]] = {
                        field: set() for field in ("vector", "irqn", "eqn")
                    }
                    for queue in selection._channel_queues(channel):
                        queue_cq = queue.get("cq")
                        if not isinstance(queue_cq, dict) or queue_cq.get(
                            "cqn"
                        ) in (None, 0):
                            continue
                        for field, value in (
                            (
                                "vector",
                                selection._first_not_none(
                                    queue_cq.get("eq_vector"),
                                    queue_cq.get("vector"),
                                ),
                            ),
                            (
                                "irqn",
                                selection._first_not_none(
                                    queue_cq.get("eq_irqn"),
                                    queue_cq.get("irqn"),
                                ),
                            ),
                            ("eqn", queue_cq.get("eqn")),
                        ):
                            if value is not None:
                                shared_values[field].add(int(value))
                    shared = {
                        field: next(iter(values)) if len(values) == 1 else None
                        for field, values in shared_values.items()
                    }
                    for field, value in shared.items():
                        if channel.get(field) is None and value is not None:
                            channel[field] = value
                    irqn = shared["irqn"]
                    if channel.get("irq_desc") is None and irqn is not None:
                        desc = irq_to_desc(self.prog, irqn)
                        channel["irq_desc"] = formatting._hex(
                            int(desc) if desc else None
                        )

    # RDMA queue pairs

    def _count_summary_qps(self, device: DeviceRecord) -> Optional[int]:
        ibdev = self._ibdev_by_mdev.get(int(device.mdev))
        if ibdev is None:
            return 0
        return list_count_nodes(ibdev.qp_list.address_of_())

    def _report_qps(self) -> List[Dict[str, Any]]:
        if not (
            self.args.qps
            or self.args.dump_wqe
            or self.args.qpn is not None
            or self.args._full_report
        ):
            return []
        return sorted(
            (
                entry.record
                for entry in self._qps.values()
                if selection._qp_matches_filter(entry.record, self.args)
            ),
            key=lambda record: formatting._sort_key(record.get("qpn")),
        )

    def _iter_qps_from_device(self, device: DeviceRecord) -> Iterator[Object]:
        """Yield every RDMA QP owned by this mlx5 device."""

        ibdev = self._ibdev_by_mdev.get(int(device.mdev))
        if ibdev is not None:
            yield from list_for_each_entry(
                "struct mlx5_ib_qp",
                ibdev.qp_list.address_of_(),
                "qps_list",
            )

    def _qp_creator(self, qp: Object) -> Dict[str, Any]:
        resource = qp.ibqp.res
        is_user = bool(resource.user)
        subject = resource.task if is_user else resource.kern_name
        creator_type = "user" if is_user else "kernel"
        key = (creator_type, int(subject) if subject else 0)
        creator = self._qp_creators.get(key)
        if creator is not None:
            return creator

        name = None
        pid = None
        if is_user:
            if subject:
                name = subject.comm.string_().decode("utf-8", "replace")
                pid = int(subject.pid)
            display = f"user:{name}[{pid}]" if subject else "user"
            source = "struct ib_qp.res.user/task"
        else:
            if subject:
                name = subject.string_().decode("utf-8", "replace")
            display = f"kernel:{name}" if name else "kernel"
            source = "struct ib_qp.res.user/kern_name"
        creator = {
            "display": display,
            "type": creator_type,
            "name": name,
            "pid": pid,
            "source": source,
        }
        self._qp_creators[key] = creator
        return creator

    def _ib_cq_number(self, cq: Optional[Object]) -> Optional[int]:
        if cq is None or not cq:
            return None
        address = int(cq)
        if address not in self._ib_cq_numbers:
            mlx5_ib_cq = container_of(cq, "struct mlx5_ib_cq", "ibcq")
            self._ib_cq_numbers[address] = int(mlx5_ib_cq.mcq.cqn)
        return self._ib_cq_numbers[address]

    def _qp_type(self, qp: Object) -> int:
        if self._qp_has_type is None:
            self._qp_has_type = has_member(qp, "type")
        if self._qp_has_type:
            return int(qp.type)
        ib_qp_type = int(qp.ibqp.qp_type)
        if self._ib_qpt_driver is None:
            self._ib_qpt_driver = int(self.prog.constant("IB_QPT_DRIVER"))
        if ib_qp_type == self._ib_qpt_driver:
            return int(qp.qp_sub_type)
        return ib_qp_type

    def _record_qp(
        self, qp: Object, device: DeviceRecord
    ) -> Optional[Dict[str, Any]]:
        ib_qpn = int(qp.ibqp.qp_num)
        hw_qpn = int(qp.trans_qp.base.mqp.qpn)
        if self.args.qpn is not None and int(self.args.qpn) not in (
            ib_qpn,
            hw_qpn,
        ):
            return None
        aliases = sorted({ib_qpn, hw_qpn})

        send_cq = qp.ibqp.send_cq
        recv_cq = qp.ibqp.recv_cq
        qp_type = self._qp_type(qp)
        creator = self._qp_creator(qp)
        sq_wq = qp.sq
        rq_wq = qp.rq
        kernel_backed = creator.get("type") == "kernel"
        sq_summary = self._collect_wq_summary(sq_wq, kernel_backed)
        rq_summary = self._collect_wq_summary(rq_wq, kernel_backed)
        sq_pc = sq_summary.get("head")
        sq_cc = sq_summary.get("tail")
        rq_pc = rq_summary.get("head")
        rq_cc = rq_summary.get("tail")
        qp_state = int(qp.state)
        if self._qp_has_is_rss is None:
            self._qp_has_is_rss = has_member(qp, "is_rss")
        sq_size = sq_summary.get("size")
        eligible_sq_wq = (
            sq_wq
            if kernel_backed and sq_size is not None and int(sq_size) > 0
            else None
        )
        record = {
            "qpn": ib_qpn,
            "ib_qpn": ib_qpn,
            "hw_qpn": hw_qpn,
            "qpn_aliases": aliases,
            "address": formatting._hex(int(qp)),
            "address_struct": "struct mlx5_ib_qp",
            "device": device.mdev_address,
            "owner": "mlx5_ib_qp_list",
            "creator": creator.get("display"),
            "creator_type": creator.get("type"),
            "creator_name": creator.get("name"),
            "creator_pid": creator.get("pid"),
            "creator_source": creator.get("source"),
            "type": qp_type,
            "type_display": decode._enum_type_label(
                self.prog, qp_type, "enum ib_qp_type"
            ),
            "state": qp_state,
            "state_display": decode._enum_type_label(
                self.prog, qp_state, "enum ib_qp_state"
            ),
            "flags": formatting._hex(int(qp.flags)),
            "has_rq": int(qp.has_rq),
            "is_rss": int(qp.is_rss) if self._qp_has_is_rss else None,
            "max_inline_data": int(qp.max_inline_data),
            "db": formatting._hex(int(qp.db.address_)),
            "buf": formatting._hex(int(qp.buf.address_)),
            "send_cq": formatting._hex(int(send_cq) if send_cq else None),
            "recv_cq": formatting._hex(int(recv_cq) if recv_cq else None),
            "send_cqn": self._ib_cq_number(send_cq),
            "recv_cqn": self._ib_cq_number(recv_cq),
            "sq": sq_summary,
            "rq": rq_summary,
            "sq_pc": sq_pc,
            "sq_cc": sq_cc,
            "rq_pc": rq_pc,
            "rq_cc": rq_cc,
            "sq_pc_source": "qp.sq.head" if sq_pc is not None else None,
            "sq_cc_source": "qp.sq.tail" if sq_cc is not None else None,
            "rq_pc_source": "qp.rq.head" if rq_pc is not None else None,
            "rq_cc_source": "qp.rq.tail" if rq_cc is not None else None,
        }
        self._qps[int(qp)] = _QpEntry(record, eligible_sq_wq)
        return record

    # Descriptor selection and dumps

    def _collect_requested_dumps(self) -> List[Dict[str, Any]]:
        dump_reports: List[Dict[str, Any]] = []
        if self.args.dump_cqe:
            qps_by_cq: Dict[Tuple[str, int], List[_QpEntry]] = defaultdict(
                list
            )
            for qp_entry in self._qps.values():
                if qp_entry.sq_wq is None:
                    continue
                send_cqn = qp_entry.record.get("send_cqn")
                if send_cqn is not None:
                    qps_by_cq[
                        (str(qp_entry.record["device"]), int(send_cqn))
                    ].append(qp_entry)
            if self.args.cqn is None:
                if getattr(self.args, "_auto_select_cqs", False):
                    cq_keys = self._auto_cqe_dump_keys()
                else:
                    cq_keys = [
                        key
                        for key, entry in sorted(
                            self._cqs.items(), key=lambda item: item[0]
                        )
                        if selection._cq_matches_filter(
                            entry.record, self.args
                        )
                    ]
                cq_keys = selection._limit_balanced(
                    cq_keys,
                    self.args.maxcq,
                    lambda key: selection._cq_balance_bucket(
                        self._cqs[key].record
                    ),
                )
                dump_reports.extend(
                    self._dump_cqe_key(
                        key, self.args.maxcqe, qps_by_cq.get(key, [])
                    )
                    for key in cq_keys
                )
                if not dump_reports:
                    self._warn(
                        "--dump-cqe requested but no matching CQs were discovered"
                    )
            else:
                key = self._select_numbered_key(
                    self._cqs, self.args.cqn, "CQN"
                )
                dump_reports.append(
                    self._dump_cqe_key(
                        key, self.args.maxcqe, qps_by_cq.get(key, [])
                    )
                    if key is not None
                    else {
                        "kind": "cqe",
                        "selector": self.args.cqn,
                        "status": "not-found",
                        "entries": [],
                    }
                )
        if self.args.dump_eqe:
            if self.args.eqn is None:
                eq_keys = self._auto_eqe_dump_keys()
                dump_reports.extend(
                    self._dump_eqe_key(key, self.args.maxeqe)
                    for key in eq_keys
                )
                if not eq_keys:
                    self._warn(
                        "--dump-eqe requested but no dumpable EQs were discovered"
                    )
            else:
                key = self._select_numbered_key(
                    self._eqs, self.args.eqn, "EQN"
                )
                dump_reports.append(
                    self._dump_eqe_key(key, self.args.maxeqe)
                    if key is not None
                    else {
                        "kind": "eqe",
                        "selector": self.args.eqn,
                        "status": "not-found",
                        "entries": [],
                    }
                )
        if self.args.dump_wqe:
            if (
                self.args.qpn is None
                and self.args.sqn is None
                and self.args.rqn is None
            ):
                qp_keys = self._auto_wqe_qp_dump_keys()
                queue_keys = self._auto_wqe_queue_dump_keys()
                dump_reports.extend(
                    self._dump_wqe_key(key, self.args.maxwqe, auto=True)
                    for key in qp_keys
                )
                dump_reports.extend(
                    self._dump_queue_wqe_key(key, self.args.maxwqe, auto=True)
                    for key in queue_keys
                )
                if not qp_keys and not queue_keys:
                    self._warn(
                        "--dump-wqe requested but no dumpable QP or mlx5e queue WQs were discovered"
                    )
            if self.args.qpn is not None:
                selected_qp_key = self._select_qp_key(self.args.qpn)
                dump_reports.append(
                    self._dump_wqe_key(selected_qp_key, self.args.maxwqe)
                    if selected_qp_key is not None
                    else {
                        "kind": "wqe",
                        "source": "qp",
                        "selector": self.args.qpn,
                        "status": "not-found",
                        "entries": [],
                    }
                )
            for selector_name in ("sqn", "rqn"):
                number = getattr(self.args, selector_name)
                if number is None:
                    continue
                queue_key = self._select_queue_key(selector_name, number)
                dump_reports.append(
                    self._dump_queue_wqe_key(queue_key, self.args.maxwqe)
                    if queue_key is not None
                    else {
                        "kind": "wqe",
                        "source": "queue",
                        "selector_name": selector_name,
                        "selector": number,
                        "status": "not-found",
                        "entries": [],
                    }
                )
        return dump_reports

    def _auto_cqe_dump_keys(self) -> List[Tuple[str, int]]:
        candidates = [
            (key, entry.record)
            for key, entry in self._cqs.items()
            if selection._cq_matches_filter(entry.record, self.args)
        ]
        role_rank = {
            "rq": 0,
            "sq": 1,
            "icosq": 2,
            "async_icosq": 3,
            "xdp_sq": 4,
            "xdpsq": 4,
            "rdma_cq": 5,
            "drop_rq_cq": 6,
            "core_cq": 7,
        }

        def rank(
            item: Tuple[Tuple[str, int], Dict[str, Any]]
        ) -> Tuple[int, int, str, int]:
            (device_name, cqn), cq = item
            size = cq.get("size")
            return (
                1 if size is not None and size <= 1 else 0,
                role_rank.get(str(cq.get("queue_kind") or ""), len(role_rank)),
                device_name,
                cqn,
            )

        candidates.sort(key=rank)
        return [key for key, _cq in candidates]

    def _auto_eqe_dump_keys(self) -> List[Tuple[str, int]]:
        candidates = [(key, entry.record) for key, entry in self._eqs.items()]
        candidates.sort(key=selection._eq_item_auto_dump_key)
        return [
            key
            for key, _eq in selection._limit_balanced(
                candidates,
                self.args.maxeq,
                lambda item: selection._eq_balance_bucket(item[1]),
            )
        ]

    def _auto_wqe_qp_dump_keys(self) -> List[int]:
        candidates = [
            (key, entry.record)
            for key, entry in self._qps.items()
            if entry.sq_wq is not None
            and selection._qp_matches_filter(entry.record, self.args)
        ]

        def rank(
            item: Tuple[int, Dict[str, Any]]
        ) -> Tuple[int, int, str, int]:
            _key, qp = item
            sq = qp.get("sq")
            sq_size = sq.get("size") if isinstance(sq, dict) else None
            inflight = _nonnegative_delta(qp.get("sq_pc"), qp.get("sq_cc"))
            return (
                1 if sq_size in (None, 0) else 0,
                1 if inflight == 0 else 0,
                str(qp.get("device") or ""),
                qp.get("qpn") or 0,
            )

        candidates.sort(key=rank)
        return [
            key
            for key, _qp in selection._limit_items(candidates, self.args.maxqp)
        ]

    def _auto_wqe_queue_dump_keys(self) -> List[Tuple[str, str, int, str]]:
        candidates = [
            (key, entry.record)
            for key, entry in self._mlx5e_queues.items()
            if entry.wq is not None
        ]
        role_rank = {
            "sq": 0,
            "rq": 1,
            "icosq": 2,
            "async_icosq": 3,
            "xdpsq": 4,
            "xskrq": 5,
        }

        def rank(
            item: Tuple[Tuple[str, str, int, str], Dict[str, Any]]
        ) -> Tuple[int, int, str, int, str]:
            (device_name, _selector_name, queue_number, owner), queue = item
            wq = queue.get("wq", {})
            size = wq.get("size") if isinstance(wq, dict) else None
            return (
                1 if size in (None, 0) else 0,
                role_rank.get(str(queue.get("kind") or ""), len(role_rank)),
                device_name,
                queue_number,
                owner,
            )

        candidates.sort(key=rank)
        return [
            key
            for key, _queue in selection._limit_balanced(
                candidates,
                self.args.maxqueues,
                lambda item: selection._queue_balance_bucket(item[1]),
            )
        ]

    def _select_numbered_key(
        self,
        records: Dict[Tuple[str, int], Any],
        number: int,
        label: str,
    ) -> Optional[Tuple[str, int]]:
        matches = [key for key in records if key[1] == number]
        return self._select_match(
            matches,
            f"{label} {number} exists on multiple mlx5 devices: "
            + ", ".join(f"{dev}:{num}" for dev, num in matches)
            + "; use --dev to disambiguate",
        )

    def _select_qp_key(self, qpn: int) -> Optional[int]:
        matches = [
            key
            for key, entry in self._qps.items()
            if selection._qp_record_matches_qpn(entry.record, qpn)
            and selection._qp_matches_filter(entry.record, self.args)
        ]
        descriptions = []
        for key in matches:
            qp = self._qps[key].record
            descriptions.append(
                f"{qp.get('device')} QPN {qp.get('qpn')} "
                f"(HW {qp.get('hw_qpn')}, {qp.get('address')})"
            )
        return self._select_match(
            matches,
            f"QPN {qpn} matches multiple mlx5 QPs: "
            + ", ".join(descriptions)
            + "; use --dev when devices differ, or use a hardware QPN",
        )

    def _select_queue_key(
        self, selector_name: str, number: int
    ) -> Optional[Tuple[str, str, int, str]]:
        matches = [
            key
            for key in self._mlx5e_queues
            if key[1] == selector_name and key[2] == number
        ]
        return self._select_match(
            matches,
            f"{selector_name.upper()} {number} exists on multiple mlx5 queues: "
            + ", ".join(
                f"{dev}:{selector}:{num}:{owner}"
                for dev, selector, num, owner in matches
            )
            + "; use --dev or --netdev to disambiguate",
        )

    def _select_match(
        self,
        matches: List[_KeyT],
        warning: str,
    ) -> Optional[_KeyT]:
        if not matches:
            return None
        if len(matches) == 1:
            return matches[0]
        self._warn(warning)
        return matches[0]

    def _dump_cqe_key(
        self,
        key: Tuple[str, int],
        max_entries: int,
        qp_candidates: List[_QpEntry],
    ) -> Dict[str, Any]:
        device_name, cqn = key
        entry = self._cqs.get(key)
        record, wq = entry if entry is not None else ({}, None)
        if wq is None:
            return {
                "kind": "cqe",
                "selector_name": "cqn",
                "selector": cqn,
                "device": device_name,
                "status": "not-found",
                "cq": _jsonable(record),
                "entries": [],
            }
        entries = self._dump_ring(
            wq,
            max_entries,
            decode=lambda raw: _decode_cqe(self.prog, raw),
            ring_size=record.get("size"),
            consumer_index=record.get("consumer_index"),
            descriptor_kind="cqe",
        )
        notes = (
            ["WR_ID is read from matching struct mlx5_ib_qp.sq.wrid[] entries"]
            if self._annotate_ib_cqe_wr_ids(record, entries, qp_candidates)
            else []
        )
        status, bad_statuses = _descriptor_dump_summary(entries)
        wq_layout = dumps._wq_layout_summary(wq)
        if bad_statuses:
            self._warn(
                f"CQN {cqn} on {device_name} dump status {status}; "
                f"wq_layout={wq_layout}"
            )
        return {
            "kind": "cqe",
            "selector_name": "cqn",
            "selector": cqn,
            "device": device_name,
            "status": status,
            "cq": _jsonable(record),
            "wq": wq_layout,
            "consumer_index": record.get("consumer_index"),
            "window": dumps._dump_window_summary(
                max_entries, record.get("size")
            ),
            "notes": notes,
            "entries": entries,
        }

    def _annotate_ib_cqe_wr_ids(
        self,
        cq_record: Dict[str, Any],
        entries: List[Dict[str, Any]],
        qp_candidates: List[_QpEntry],
    ) -> int:
        if not entries or (
            formatting._short_struct(cq_record.get("address_struct"))
            != "mlx5_ib_cq"
        ):
            return 0
        request_opcodes = self.prog.cache.get("_mlx5_cqe_request_opcodes")
        if request_opcodes is None:
            request_opcodes = (
                int(self.prog.constant("MLX5_CQE_REQ")),
                int(self.prog.constant("MLX5_CQE_REQ_ERR")),
            )
            self.prog.cache["_mlx5_cqe_request_opcodes"] = request_opcodes
        qp_index_by_qpn: Dict[int, Optional[int]] = {}
        for index, qp_entry in enumerate(qp_candidates):
            record = qp_entry.record
            aliases = record.get("qpn_aliases")
            if not isinstance(aliases, list):
                aliases = (
                    record.get("qpn"),
                    record.get("ib_qpn"),
                    record.get("hw_qpn"),
                )
            for alias in {
                int(value) for value in aliases if value is not None
            }:
                if alias in qp_index_by_qpn:
                    qp_index_by_qpn[alias] = None
                else:
                    qp_index_by_qpn[alias] = index
        wrid_sources: Dict[int, Tuple[int, Any]] = {}
        gsi_wr_ids: Dict[int, Optional[int]] = {}
        count = 0
        for entry in entries:
            if entry.get("status") not in ("ok", "ready"):
                continue
            # mlx5_ib_poll_one() uses wqe_counter directly for send completions
            # and errors. Receive/SRQ completions use different cursor rules.
            if entry.get("opcode_value") not in request_opcodes:
                continue
            wqe_ctr = entry.get("wqe_counter")
            if wqe_ctr is None:
                continue
            cqe_qpn = entry.get("qpn")
            if cqe_qpn is None or cqe_qpn == 0:
                continue
            qp_index = qp_index_by_qpn.get(int(cqe_qpn))
            if qp_index is None:
                continue
            qp_entry = qp_candidates[qp_index]
            if qp_index not in wrid_sources:
                wq = qp_entry.sq_wq
                if wq is None:
                    wrid_sources[qp_index] = (0, None)
                else:
                    wqe_cnt = int(wq.wqe_cnt)
                    wrid = wq.wrid if wqe_cnt > 0 else None
                    wrid_sources[qp_index] = (
                        wqe_cnt,
                        wrid if wrid else None,
                    )
            wqe_cnt, wrid = wrid_sources[qp_index]
            if wqe_cnt <= 0 or wrid is None:
                continue
            wr_idx = wqe_ctr & (wqe_cnt - 1)
            wr_id = int(wrid[wr_idx])
            qp_record = qp_entry.record
            if qp_record.get(
                "creator_type"
            ) == "kernel" and _looks_like_kernel_pointer_value(wr_id):
                if wr_id not in gsi_wr_ids:
                    gsi_wr_ids[wr_id] = _mlx5_ib_gsi_saved_wr_id(
                        self.prog, wr_id
                    )
                gsi_wr_id = gsi_wr_ids[wr_id]
                if gsi_wr_id is None or _looks_like_kernel_pointer_value(
                    gsi_wr_id
                ):
                    continue
                wr_id = gsi_wr_id
                wr_id_kind = "gsi_numeric_wr_id"
                wr_id_source = (
                    "struct mlx5_ib_gsi_wr.wc.wr_id via sq.wrid[] wr_cqe"
                )
            else:
                wr_id_kind = "numeric_wr_id"
                wr_id_source = (
                    "struct mlx5_ib_qp.sq.wrid[wqe_ctr & (wqe_cnt - 1)]"
                )
            entry.update(
                {
                    "wr_id": wr_id,
                    "wr_id_kind": wr_id_kind,
                    "wr_id_index": wr_idx,
                    "wr_id_queue": "sq",
                    "wr_id_source": wr_id_source,
                }
            )
            count += 1
        return count

    def _dump_eqe_key(
        self, key: Tuple[str, int], max_entries: int
    ) -> Dict[str, Any]:
        device_name, eqn = key
        entry = self._eqs.get(key)
        record, wq = entry if entry is not None else ({}, None)
        if wq is None:
            return {
                "kind": "eqe",
                "selector_name": "eqn",
                "selector": eqn,
                "device": device_name,
                "status": "not-found",
                "eq": _jsonable(record),
                "entries": [],
            }
        entries = self._dump_ring(
            wq,
            max_entries,
            decode=lambda raw: _decode_eqe(self.prog, raw),
            ring_size=record.get("size"),
            consumer_index=record.get("consumer_index"),
            descriptor_kind="eqe",
        )
        status, bad_statuses = _descriptor_dump_summary(entries)
        wq_layout = dumps._wq_layout_summary(wq)
        if bad_statuses:
            self._warn(
                f"EQN {eqn} on {device_name} dump status {status}; "
                f"wq_layout={wq_layout}"
            )
        return {
            "kind": "eqe",
            "selector_name": "eqn",
            "selector": eqn,
            "device": device_name,
            "status": status,
            "eq": _jsonable(record),
            "wq": wq_layout,
            "consumer_index": record.get("consumer_index"),
            "window": dumps._dump_window_summary(
                max_entries, record.get("size")
            ),
            "entries": entries,
        }

    def _dump_wqe_key(
        self, key: int, max_entries: int, auto: bool = False
    ) -> Dict[str, Any]:
        entry = self._qps.get(key)
        record = entry.record if entry is not None else {}
        device_name = str(record.get("device") or "")
        qpn = record.get("qpn")
        wq = entry.sq_wq if entry is not None else None
        owner = record.get("owner")
        wq_summary = record.get("sq", {})
        if wq is None:
            notes = []
            status = "not-found"
            if entry is not None:
                status = "unavailable"
                if record.get("creator_type") == "user":
                    notes.append(
                        "User-backed QP WQEs are not available through the "
                        "kernel work-queue layout"
                    )
                elif (
                    isinstance(wq_summary, dict)
                    and wq_summary.get("size") == 0
                ):
                    notes.append("QP has no send queue to dump")
                else:
                    notes.append(
                        "QP send queue is not available for a kernel WQE dump"
                    )
            return {
                "kind": "wqe",
                "source": "qp",
                "selector_name": "qpn",
                "selector": qpn,
                "device": device_name,
                "owner": owner,
                "status": status,
                "qp": _jsonable(record),
                "notes": notes,
                "entries": [],
            }
        entries = self._dump_ring(
            wq,
            max_entries,
            decode=lambda raw: _decode_wqe(self.prog, raw),
            ring_size=wq_summary.get("size")
            if isinstance(wq_summary, dict)
            else None,
            consumer_index=wq_summary.get("last_poll")
            if isinstance(wq_summary, dict)
            else None,
            variable_wqe_stride=True,
        )
        status, bad_statuses = _descriptor_dump_summary(entries)
        wq_layout = dumps._wq_layout_summary(wq)
        notes = (
            [
                "SQ head/tail show no outstanding WQEs; entries may be old ring contents"
            ]
            if _nonnegative_delta(record.get("sq_pc"), record.get("sq_cc"))
            == 0
            else []
        )
        if bad_statuses:
            self._warn_wqe_dump_error(
                selector_name="QPN",
                selector=qpn,
                device=device_name,
                status=status,
                bad_statuses=bad_statuses,
                wq_layout=wq_layout,
                auto=auto,
            )
        return {
            "kind": "wqe",
            "source": "qp",
            "selector_name": "qpn",
            "selector": qpn,
            "device": device_name,
            "owner": owner,
            "status": status,
            "qp": _jsonable(record),
            "wq": wq_layout,
            "wqe_kind": "ctrl",
            "notes": notes,
            "entries": entries,
        }

    def _dump_queue_wqe_key(
        self,
        key: Tuple[str, str, int, str],
        max_entries: int,
        auto: bool = False,
    ) -> Dict[str, Any]:
        device_name, selector_name, number, key_owner = key
        entry = self._mlx5e_queues.get(key)
        record, wq = entry if entry is not None else ({}, None)
        owner = record.get("owner") or key_owner
        if wq is None:
            return {
                "kind": "wqe",
                "source": "queue",
                "selector_name": selector_name,
                "selector": number,
                "device": device_name,
                "owner": owner,
                "status": "not-found",
                "queue": _jsonable(record),
                "entries": [],
            }
        wq_summary = record.get("wq", {})
        is_rq = record.get("kind") in ("rq", "xskrq", "ptp_rq")
        linked_rq = is_rq and wq.type_.type_name() == "struct mlx5_wq_ll"
        decode_wqe = (
            (lambda raw: _decode_rq_wqe(raw, linked=linked_rq))
            if is_rq
            else lambda raw: _decode_wqe(self.prog, raw)
        )
        entries = self._dump_ring(
            wq,
            max_entries,
            decode=decode_wqe,
            ring_size=wq_summary.get("size")
            if isinstance(wq_summary, dict)
            else None,
            consumer_index=selection._first_not_none(
                record.get("cc"), record.get("pc")
            ),
            variable_wqe_stride=not is_rq,
        )
        status, bad_statuses = _descriptor_dump_summary(entries)
        wq_layout = dumps._wq_layout_summary(wq)
        notes = (
            [
                "queue progress shows no outstanding WQEs; entries may be old ring contents"
            ]
            if record.get("inflight") == 0
            else []
        )
        if bad_statuses:
            self._warn_wqe_dump_error(
                selector_name=selector_name.upper(),
                selector=number,
                device=device_name,
                status=status,
                bad_statuses=bad_statuses,
                wq_layout=wq_layout,
                auto=auto,
            )
        return {
            "kind": "wqe",
            "source": "queue",
            "selector_name": selector_name,
            "selector": number,
            "device": device_name,
            "owner": owner,
            "status": status,
            "queue": _jsonable(record),
            "wq": wq_layout,
            "wqe_kind": "rq" if is_rq else "ctrl",
            "notes": notes,
            "entries": entries,
        }

    def _warn_wqe_dump_error(
        self,
        *,
        selector_name: str,
        selector: Any,
        device: str,
        status: str,
        bad_statuses: Dict[str, int],
        wq_layout: Dict[str, Any],
        auto: bool,
    ) -> None:
        if not auto:
            summary = f"statuses={bad_statuses}; {_wq_warning_shape(wq_layout, include_wq=True)}"
            self._warn(
                f"{selector_name} {selector} on {device} WQE dump status {status}; {summary}"
            )
            return

        shape = _wq_warning_shape(wq_layout)
        group_key = (selector_name, status, shape)
        group = self._wqe_warning_groups.setdefault(
            group_key, {"count": 0, "examples": []}
        )
        group["count"] += 1
        examples = group["examples"]
        if len(examples) < 5:
            examples.append(f"{device}:{selector_name.lower()}={selector}")

    def _flush_wqe_warning_groups(self) -> None:
        for (
            selector_name,
            status,
            shape,
        ), group in self._wqe_warning_groups.items():
            examples = ", ".join(group.get("examples") or [])
            suffix = f"; examples: {examples}" if examples else ""
            self._warn(
                f"{group.get('count')} automatic {selector_name} WQE dumps had status "
                f"{status} ({shape}){suffix}"
            )
        self._wqe_warning_groups.clear()

    def _dump_ring(
        self,
        wq: Object,
        max_entries: int,
        decode: Callable[[bytes], Dict[str, Any]],
        ring_size: Optional[Any],
        consumer_index: Optional[Any],
        variable_wqe_stride: bool = False,
        descriptor_kind: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if ring_size is None:
            return [{"index": None, "status": "size-unavailable"}]
        size = int(ring_size)
        if size <= 0:
            return [{"index": None, "status": "size-unavailable"}]
        if consumer_index is None:
            return [{"index": None, "status": "consumer-index-unavailable"}]
        consumer = int(consumer_index)

        _fbc_ref, fbc = dumps._read_fbc(wq)
        if fbc is None:
            return [{"index": None, "status": "layout-unavailable"}]
        frags = fbc.frags
        log_stride = int(fbc.log_stride)
        log_size = int(fbc.log_sz)
        log_frag_strides = int(fbc.log_frag_strides)
        frag_sz_m1 = int(fbc.frag_sz_m1)
        strides_offset = int(fbc.strides_offset)
        fbc_size = int(fbc.sz_m1) + 1
        if (
            not 0 <= log_stride < 32
            or not 0 <= log_size < 32
            or not 0 <= log_frag_strides < 32
            or fbc_size != 1 << log_size
            or frag_sz_m1 != (1 << log_frag_strides) - 1
            or strides_offset < 0
        ):
            return [{"index": None, "status": "layout-unavailable"}]

        stride = 1 << log_stride
        frag_strides = 1 << log_frag_strides
        if frag_strides * stride != int(self.prog["PAGE_SIZE"]):
            return [{"index": None, "status": "layout-unavailable"}]
        if wq.type_.type_name() == "struct mlx5_ib_cq_buf":
            if (
                size != int(wq.nent)
                or stride != int(wq.cqe_size)
                or size * stride != int(wq.frag_buf.size)
            ):
                return [{"index": None, "status": "layout-unavailable"}]
        elif size != fbc_size:
            return [{"index": None, "status": "layout-unavailable"}]
        read_len = min(defs.DEFAULT_DESCRIPTOR_ENTRY_BYTES, stride)
        cqe_offset = (
            defs.DEFAULT_DESCRIPTOR_ENTRY_BYTES
            if descriptor_kind == "cqe" and stride == 128
            else 0
        )
        fragment_cache: Dict[
            int, Tuple[Optional[int], Optional[int], Optional[bytes]]
        ] = {}
        entry_count = min(max_entries, size)
        around_consumer = descriptor_kind in ("cqe", "eqe")
        cursor = consumer - (entry_count // 2 if around_consumer else 0)
        entries: List[Dict[str, Any]] = []
        traversed = 0

        for _ in range(entry_count):
            if variable_wqe_stride and traversed >= size:
                break
            index = cursor % size
            adjusted_index = index + strides_offset
            frag_index = adjusted_index >> log_frag_strides
            if frag_index not in fragment_cache:
                base = dumps._fragment_base(frags, frag_index)
                if base is None:
                    fragment_cache[frag_index] = (None, None, None)
                else:
                    frag_first = frag_index * frag_strides
                    first = max(strides_offset, frag_first)
                    end = min(strides_offset + size, frag_first + frag_strides)
                    byte_offset = (first - frag_first) << log_stride
                    byte_len = (end - first) << log_stride
                    read_address = base + byte_offset
                    try:
                        fragment = self.prog.read(read_address, byte_len)
                    except FaultError:
                        fragment = None
                    fragment_cache[frag_index] = (
                        base,
                        read_address,
                        fragment,
                    )
            cached_base, cached_read_address, cached_fragment = fragment_cache[
                frag_index
            ]
            if cached_fragment is None:
                entry: Dict[str, Any] = {
                    "index": index,
                    "_absolute_index": cursor,
                    "status": (
                        "address-unavailable"
                        if cached_base is None
                        else "read-unavailable"
                    ),
                }
                if around_consumer and cursor == consumer:
                    entry["consumer_marker"] = "cons_index"
                entries.append(entry)
                cursor += 1
                traversed += 1
                continue

            assert cached_base is not None and cached_read_address is not None
            addr = (
                cached_base
                + ((adjusted_index & frag_sz_m1) << log_stride)
                + cqe_offset
            )
            offset = addr - cached_read_address
            raw = cached_fragment[offset : offset + read_len]
            decoded = decode(raw)
            step = (
                _wqe_ctrl_wqebbs(decoded, stride) if variable_wqe_stride else 1
            )
            if variable_wqe_stride:
                decoded["wqebbs"] = step
            decoded.setdefault("status", "ok")
            if around_consumer and cursor == consumer:
                decoded["consumer_marker"] = "cons_index"
            if descriptor_kind is not None:
                dumps._annotate_owner_status(
                    decoded,
                    cursor,
                    size,
                    descriptor_kind,
                    consumer_index=consumer,
                )
            decoded.update(
                {
                    "index": index,
                    "_absolute_index": cursor,
                    "address": formatting._hex(addr),
                }
            )
            entries.append(decoded)
            cursor += step
            traversed += step
        return entries

    # Findings and warnings

    def _analyze_findings(
        self,
        devices: List[DeviceRecord],
        dump_reports: Sequence[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []

        def add(severity: str, scope: str, message: str) -> None:
            findings.append(
                {"severity": severity, "scope": scope, "message": message}
            )

        for device in devices:
            health = device.health
            scope = device.rdma_name or device.mdev_address
            for severity, present, message in (
                (
                    "HIGH",
                    health.get("fatal_error") not in (None, 0),
                    "mlx5 health fatal_error is non-zero",
                ),
                (
                    "MED",
                    health.get("miss_counter") not in (None, 0),
                    "mlx5 health miss_counter is non-zero",
                ),
                (
                    "HIGH",
                    device.summary.get("device_state") == "INTERNAL_ERROR",
                    "mlx5_core_dev state is INTERNAL_ERROR",
                ),
            ):
                if present:
                    add(severity, scope, message)
            for netdev in device.netdevs:
                netdev_summary = netdev.get("summary", {})
                stats = netdev_summary.get("stats", {})
                scope = netdev.get("name", "netdev")
                if netdev_summary.get("carrier") == "down":
                    add("LOW", scope, "netdev carrier appears down")
                if any(
                    stats.get(name) not in (None, 0)
                    for name in ("tx_errors", "rx_errors")
                ):
                    add("HIGH", scope, "rx/tx error counters are non-zero")
                for channel in netdev.get("channels", []):
                    for queue in selection._channel_queues(channel):
                        queue_name = str(queue["owner"])
                        wq = queue.get("wq")
                        size = wq.get("size") if isinstance(wq, dict) else None
                        pc = queue.get("pc")
                        cc = queue.get("cc")
                        inflight = queue.get("inflight")
                        for severity, present, message in (
                            (
                                "MED",
                                bool(queue.get("recovering")),
                                f"{queue_name} is marked recovering",
                            ),
                            (
                                "LOW",
                                _queue_should_warn_disabled(queue),
                                f"{queue_name} is not marked enabled",
                            ),
                            (
                                "MED",
                                bool(queue.get("txq_stopped")),
                                f"{queue_name} netdev TX queue is stopped/frozen",
                            ),
                            (
                                "MED",
                                pc is not None and cc is not None and pc < cc,
                                f"{queue_name} producer counter is behind consumer counter",
                            ),
                            (
                                "HIGH",
                                inflight is not None
                                and size is not None
                                and 0 < size <= inflight,
                                f"{queue_name} in-flight work is at or above WQ size",
                            ),
                        ):
                            if present:
                                add(severity, scope, message)
        findings.extend(self._cq_linkage_findings())
        findings.extend(self._descriptor_findings(dump_reports))
        return findings

    def _cq_linkage_findings(self) -> List[Dict[str, str]]:
        by_device: Dict[str, List[Any]] = defaultdict(list)
        for cq in (entry.record for entry in self._cqs.values()):
            if cq.get("eqn") is not None:
                continue
            if all(
                cq.get(name) is None
                for name in ("vector", "irqn", "eq_vector", "eq_irqn")
            ):
                continue
            by_device[str(cq.get("device") or "mlx5")].append(cq.get("cqn"))
        findings = []
        for device, cqns in sorted(by_device.items()):
            examples = ", ".join(str(cqn) for cqn in cqns[:5])
            message = f"{len(cqns)} CQs with vector/IRQ data have no matching EQ linkage (examples: {examples})"
            findings.append(
                {"severity": "MED", "scope": device, "message": message}
            )
        return findings

    def _descriptor_findings(
        self, dump_reports: Sequence[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        if not dump_reports:
            return []
        findings = []
        cqe_errors: Tuple[int, ...] = ()
        cq_error = None

        def add(scope: str, message: str) -> None:
            findings.append(
                {"severity": "HIGH", "scope": scope, "message": message}
            )

        for dump in dump_reports:
            kind = dump.get("kind")
            if kind == "cqe" and not cqe_errors:
                cqe_errors = tuple(
                    int(self.prog.constant(name))
                    for name in (
                        "MLX5_CQE_SIG_ERR",
                        "MLX5_CQE_REQ_ERR",
                        "MLX5_CQE_RESP_ERR",
                    )
                )
            elif kind == "eqe" and cq_error is None:
                cq_error = int(self.prog.constant("MLX5_EVENT_TYPE_CQ_ERROR"))
            selector_name = dump.get("selector_name") or "id"
            selector = dump.get("selector")
            scope = dump.get("device") or "mlx5"
            for entry in dump.get("entries", []) or []:
                if entry.get("status", "ok") not in ("ok", "ready"):
                    continue
                if kind == "cqe" and entry.get("opcode_value") in cqe_errors:
                    syndrome = entry.get("syndrome_display") or entry.get(
                        "syndrome"
                    )
                    add(
                        scope,
                        f"CQE error on {selector_name}={selector} index {entry.get('index')}"
                        f" syndrome={syndrome}",
                    )
                elif kind == "eqe" and entry.get("type_value") == cq_error:
                    syndrome = entry.get("syndrome_display") or entry.get(
                        "syndrome"
                    )
                    add(
                        scope,
                        f"EQE reports CQ error on {selector_name}={selector} index {entry.get('index')}"
                        f" cqn={entry.get('cqn')} syndrome={syndrome}",
                    )
        return findings

    def _warn(self, msg: str) -> None:
        self.warnings.append(msg)


# Core helper functions


def _validate_args(args: argparse.Namespace) -> None:
    if args.summary and args.full:
        raise ValueError("--summary and --full cannot be used together")
    invalid_qp_creators = sorted(
        set(args.qp_creators or ()) - {"kernel", "user"}
    )
    if invalid_qp_creators:
        raise ValueError(
            "--qp-creator must be 'kernel' or 'user', got: "
            + ", ".join(invalid_qp_creators)
        )
    for option, value, hard_limit in (
        ("--maxqueues", args.maxqueues, defs.MAX_REPORT_ROWS),
        ("--maxcq", args.maxcq, defs.MAX_REPORT_ROWS),
        ("--maxeq", args.maxeq, defs.MAX_REPORT_ROWS),
        ("--maxqp", args.maxqp, defs.MAX_REPORT_ROWS),
        ("--maxcqe", args.maxcqe, defs.MAX_DESCRIPTOR_ENTRIES),
        ("--maxeqe", args.maxeqe, defs.MAX_DESCRIPTOR_ENTRIES),
        ("--maxwqe", args.maxwqe, defs.MAX_DESCRIPTOR_ENTRIES),
    ):
        if value is not None or option in {"--maxcqe", "--maxeqe", "--maxwqe"}:
            if value < 1:
                raise ValueError(f"{option} must be >= 1")
            if value > hard_limit:
                raise ValueError(f"{option} must be <= {hard_limit}")
    if args.dev and ":" in args.dev and "." in args.dev:
        if not defs._PCI_BDF_RE.match(args.dev):
            raise ValueError("invalid --dev BDF value, expected DDDD:BB:DD.F")
    for name in ("cqn", "eqn", "qpn", "sqn", "rqn"):
        value = getattr(args, name)
        if value is not None and value < 0:
            raise ValueError(f"--{name} must be >= 0")


def _cq_arm_sn(raw: Optional[int]) -> Optional[int]:
    return None if raw is None else int(raw) & 0x3


def _irq_affinity_cpus(prog: Program, irqn: Optional[int]) -> Optional[str]:
    if irqn is None:
        return None
    desc = irq_to_desc(prog, irqn)
    if not desc:
        return None
    irq_data = desc.irq_common_data
    mask = (
        irq_data.effective_affinity
        if has_member(irq_data, "effective_affinity")
        else irq_data.affinity
    )
    return cpumask_to_cpulist(mask) or None


def _mlx5_ib_gsi_saved_wr_id(prog: Program, wr_cqe: Any) -> Optional[int]:
    if wr_cqe is None:
        return None
    addr = int(wr_cqe)
    if not _looks_like_kernel_pointer_value(addr):
        return None
    # Unused WR-ID slots can contain the all-ones sentinel. It resembles a
    # kernel pointer but must not be dereferenced.
    if addr == 0xFFFFFFFFFFFFFFFF:
        return None
    try:
        cqe = Object(prog, "struct ib_cqe *", value=addr)
        done = int(cqe.done)
        symbol_name = prog.symbol(done).name
        if symbol_name != "handle_single_completion":
            return None
        gsi_wr = container_of(cqe, "struct mlx5_ib_gsi_wr", "cqe")
        return int(gsi_wr.wc.wr_id)
    except (FaultError, LookupError):
        return None


def _looks_like_kernel_pointer_value(value: Any) -> bool:
    # Supported 64-bit vmcores use high canonical kernel addresses. Apply this
    # only to kernel QPs because userspace may choose any u64 WR_ID.
    return int(value) >= (1 << 63)


def _cq_consumer_index(
    address_struct: str,
    wq_summary: Dict[str, Any],
    core_cq: Object,
) -> Tuple[Optional[int], str, int]:
    """Choose the CQ consumer counter for its owner.

    mlx5_ib polls mlx5_core_cq.cons_index. mlx5e polls through mlx5_cqwq,
    so use wq.cc; its mcq.cons_index may remain zero.
    """

    core_cons_index = int(core_cq.cons_index)
    wq_cc = wq_summary.get("cc")
    if address_struct == "struct mlx5e_cq" and wq_cc is not None:
        return wq_cc, f"{address_struct}.wq.cc", core_cons_index
    return core_cons_index, "struct mlx5_core_cq.cons_index", core_cons_index


def _wqe_ctrl_wqebbs(decoded: Dict[str, Any], stride_bytes: int) -> int:
    ds = decoded.get("ds")
    if ds is None or ds <= 0:
        return 1
    return max(1, (ds * 16 + stride_bytes - 1) // stride_bytes)


def _nonnegative_delta(pc: Optional[int], cc: Optional[int]) -> Optional[int]:
    if pc is None or cc is None or pc < cc:
        return None
    return pc - cc


def _rq_progress_detail(
    active_wq: Object,
    active_source: str,
) -> Dict[str, Any]:
    linked_rq = active_source == "rq.mpwqe.wq"
    pc = int(active_wq.wqe_ctr)
    cc = int(active_wq.head) if linked_rq else None
    inflight = int(active_wq.cur_sz) if linked_rq else None
    return {
        "pc": pc,
        "cc": cc,
        "inflight": inflight,
        "pc_source": f"{active_source}.wqe_ctr",
        "cc_source": f"{active_source}.head" if linked_rq else None,
        "inflight_source": f"{active_source}.cur_sz" if linked_rq else None,
    }


# Linux/netdev/mlx5 object helpers


def _queue_should_warn_disabled(queue: Dict[str, Any]) -> bool:
    number = queue.get("number")
    # Ignore disabled findings for placeholder XDP RQs (queue 0 with a dummy CQ).
    return (
        queue.get("enabled") is False
        and number is not None
        and (int(number) != 0 or str(queue.get("kind")) != "rq_xdpsq")
    )


def _owner_string(owner: Dict[str, Any]) -> str:
    parts = []
    if owner.get("netdev"):
        parts.append(str(owner["netdev"]))
    if owner.get("channel") is not None:
        parts.append(f"ch{owner['channel']}")
    if owner.get("queue_kind"):
        queue_name = owner.get("queue_kind")
        if owner.get("queue_number") is not None:
            queue_name = f"{queue_name}{owner.get('queue_number')}"
        parts.append(str(queue_name))
    return "/".join(parts) or str(owner.get("device") or "unknown")


# Descriptor/ring helpers


def _descriptor_dump_summary(
    entries: List[Dict[str, Any]],
) -> Tuple[str, Dict[str, int]]:
    statuses = Counter(str(entry.get("status", "ok")) for entry in entries)
    status = next(iter(statuses), "empty") if len(statuses) < 2 else "partial"
    return status, {
        name: count
        for name, count in statuses.items()
        if name not in dumps._BENIGN_DESCRIPTOR_STATUSES
    }


def _wq_warning_shape(layout: Dict[str, Any], include_wq: bool = False) -> str:
    fields: Tuple[Tuple[str, str], ...] = (
        ("wq", "wq"),
        ("frags", "frags"),
        ("fbc_sz_m1", "sz_m1"),
        ("stride", "stride_bytes"),
    )
    if not include_wq:
        fields = fields[1:]
    return "; ".join(
        f"{label}={selection._first_not_none(layout.get(key), '-')}"
        for label, key in fields
    )
