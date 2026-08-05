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
import ipaddress
import json
from collections import Counter
from collections import OrderedDict
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterator
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Sequence
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


def mlx5_iter_channels(dev: Object) -> Iterator[Object]:
    """Iterate over the Ethernet channels for an mlx5 core device."""

    netdev = dev.mlx5e_res.uplink_netdev
    if not netdev:
        return
    channels = netdev_priv(netdev, "struct mlx5e_priv").channels
    for index in range(int(channels.num)):
        yield channels.c[index]


def mlx5_iter_channel_queues(
    channel: Object,
) -> Iterator[Tuple[str, Object, str, Optional[int]]]:
    """Iterate over the queues belonging to an mlx5 Ethernet channel.

    Each tuple contains the report field, queue object, queue kind, and traffic
    class or queue index.
    """

    yield "rx_rq", channel.rq, "rq", None

    for tc in range(int(channel.num_tc)):
        yield "tx_sqs", channel.sq[tc], "sq", tc

    qos_sqs = channel.qos_sqs
    if qos_sqs:
        for index in range(int(channel.qos_sqs_size)):
            sq = qos_sqs[index]
            if sq:
                yield "tx_sqs", sq, "qos_sq", index

    if int(channel.xdp):
        yield "xdp_sqs", channel.rq_xdpsq, "rq_xdpsq", None

    xdpsq = channel.xdpsq
    if (xdpsq.type_.kind != TypeKind.POINTER or xdpsq) and int(xdpsq.sqn):
        yield "xdp_sqs", xdpsq, "xdpsq", None

    xsk_bit = int(channel.prog_.constant("MLX5E_CHANNEL_STATE_XSK"))
    if int(channel.state[0]) & (1 << xsk_bit):
        yield "xsk_rqs", channel.xskrq, "xskrq", None
        yield "xdp_sqs", channel.xsksq, "xsksq", None

    yield "icosqs", channel.icosq, "icosq", None
    yield "icosqs", channel.async_icosq, "async_icosq", None


def mlx5_iter_core_cqs(mdev: Object) -> Iterator[Object]:
    """Iterate over the ``struct mlx5_core_cq`` objects for a device."""

    async_eq = mdev.priv.eq_table.async_eq.core
    for _key, obj in radix_tree_for_each(async_eq.cq_table.tree.address_of_()):
        yield cast("struct mlx5_core_cq *", obj)


def mlx5_iter_eqs(mdev: Object) -> Iterator[Tuple[Object, str]]:
    """Iterate over a device's EQs as ``(EQ, role)`` tuples."""

    eq_table = mdev.priv.eq_table
    for field, role in (
        ("cmd_eq", "cmd"),
        ("async_eq", "async"),
        ("pages_eq", "pages"),
    ):
        yield getattr(eq_table, field).core, role

    if has_member(eq_table, "comp_eqs"):
        for _vector, entry in xa_for_each(eq_table.comp_eqs):
            eq_comp = cast("struct mlx5_eq_comp *", entry)
            yield eq_comp.core, "completion"
        return

    for eq_comp in list_for_each_entry(
        "struct mlx5_eq_comp",
        eq_table.comp_eqs_list.address_of_(),
        "list",
    ):
        yield eq_comp.core, "completion"


def mlx5_ib_iter_qps(ibdev: Object) -> Iterator[Object]:
    """Iterate over the ``struct mlx5_ib_qp`` objects for an RDMA device."""

    yield from list_for_each_entry(
        "struct mlx5_ib_qp",
        ibdev.qp_list.address_of_(),
        "qps_list",
    )


def _mlx5_fw_version(mdev: Object, ibdev: Optional[Object]) -> str:
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
        ):
            parser.add_argument(f"--{option}", help=help_text)
        parser.add_argument(
            "--ip",
            type=ipaddress.ip_address,
            help="Restrict to devices with this netdev IP address",
        )
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
        selection._resolve_report_sections(args)
        _validate_args(args)

        report = Mlx5Collector(prog, args).collect()
        if args.json:
            print(json.dumps(_jsonable(report), indent=2, sort_keys=True))
        else:
            render.render_report(report, args)


def _new_channel_record(
    channel: Object,
    index: Union[int, str],
    cpu: Optional[int] = None,
) -> Dict[str, Any]:
    napi = channel.napi
    return {
        "index": index,
        "cpu": cpu,
        "napi_id": int(napi.napi_id),
        "napi_state": formatting._hex(int(napi.state)),
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
    """Report record plus the SQ used for WQE dumps."""

    record: Dict[str, Any]
    sq_wq: Optional[Object]


class Mlx5Collector:
    """Collect one mlx5 report."""

    def __init__(self, prog: Program, args: argparse.Namespace) -> None:
        self.prog = prog
        self.args = args
        self.warnings: List[str] = []
        self._want_cqs = bool(args.cqs)
        self._want_qps = bool(args.qps or args.dump_wqe)
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
        self._qp_creators: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self._ib_cq_numbers: Dict[int, int] = {}
        self._cq_event_names: Dict[int, Optional[str]] = {}
        self._wqe_warning_groups: "OrderedDict[Tuple[str, str, str], Dict[str, Any]]" = (
            OrderedDict()
        )

    def _discover_devices(self) -> List[DeviceRecord]:
        devices: List[DeviceRecord] = []
        saw_netdev = False

        for mdev in collect_device.for_each_mlx5_core_dev(self.prog):
            netdev = mdev.mlx5e_res.uplink_netdev
            device = DeviceRecord(mdev)
            ibdev = collect_device.mlx5_core_ib_device(mdev)
            if ibdev:
                device.rdma_name = ibdev.ib_dev.name.string_().decode(
                    "utf-8", "replace"
                )
                device.ibdev = ibdev

            if netdev:
                name = escape_ascii_string(netdev.name.string_())
                saw_netdev = True
                priv = netdev_priv(netdev, "struct mlx5e_priv")
                device.netdev = {
                    "name": name,
                    "summary": {},
                    "channels": [],
                    "_priv_obj": priv,
                }
            devices.append(device)

        if not saw_netdev:
            self._warn("no mlx5 uplink netdevs were found")
        if not devices:
            self._warn("no devices found in the mlx5 core drivers")

        return devices

    def _filter_devices(
        self, devices: List[DeviceRecord]
    ) -> List[DeviceRecord]:
        filtered = devices
        if self.args.dev:
            selector = str(self.args.dev).lower()
            filtered = [
                dev
                for dev in filtered
                if selector
                in {
                    dev.mdev_address.lower(),
                    str(dev.rdma_name or "").lower(),
                    dev.pci_bdf.lower(),
                }
            ]
            if not filtered:
                self._warn(
                    f"--dev {self.args.dev!r} did not match a discovered mlx5 device"
                )

        if self.args.netdev:
            filtered = [
                dev
                for dev in filtered
                if dev.netdev is not None
                and dev.netdev["name"] == self.args.netdev
            ]
            if not filtered:
                self._warn(
                    f"--netdev {self.args.netdev!r} did not match a discovered mlx5 netdev"
                )

        for device in filtered:
            netdev = device.netdev
            if netdev is not None:
                priv = netdev["_priv_obj"]
                netdev["summary"] = collect_device.collect_netdev_summary(
                    priv.netdev
                )

        if self.args.ip:
            wanted_ip = str(self.args.ip)
            filtered = [
                dev
                for dev in filtered
                if dev.netdev is not None
                and wanted_ip in dev.netdev["summary"]["ip_addresses"]
            ]
            if not filtered:
                self._warn(
                    f"--ip {wanted_ip!r} did not match a discovered mlx5 netdev address"
                )
        return filtered

    def collect(self) -> Dict[str, Any]:
        devices = self._discover_devices()
        devices = self._filter_devices(devices)

        for device in devices:
            device.summary = {
                "mdev": device.mdev_address,
                "rdma_name": device.rdma_name,
                "rdma_port": 1 if device.ibdev is not None else None,
                "pci_bdf": device.pci_bdf,
                "device_state": formatting._enum_name(
                    device.mdev.state, "MLX5_DEVICE_STATE_"
                ),
                "fw_version": _mlx5_fw_version(device.mdev, device.ibdev),
            }
            device.health = collect_device.collect_health(device.mdev)

        if self._summary_counts_only:
            for device in devices:
                self._collect_summary_counts(device)
        else:
            for device in devices:
                cq_start = len(self._cqs)
                eq_start = len(self._eqs)
                qp_start = len(self._qps)
                if self._want_eqs:
                    for core, role in mlx5_iter_eqs(device.mdev):
                        self._record_eq(core, device, role)
                netdev = device.netdev
                if self._want_channels and netdev is not None:
                    netdev["channels"] = self._collect_channels(device, netdev)
                if self._want_cqs:
                    for core_cq in mlx5_iter_core_cqs(device.mdev):
                        self._record_core_cq(core_cq, device)
                if self._want_qps:
                    ibdev = device.ibdev
                    if ibdev is not None:
                        for qp in mlx5_ib_iter_qps(ibdev):
                            self._record_qp(qp, device)

                channels = (
                    device.netdev["channels"]
                    if self._want_channels and device.netdev is not None
                    else []
                )
                device.counts = {
                    "netdevs": int(device.netdev is not None),
                    "channels": len(channels) if self._want_channels else None,
                    "queues": sum(
                        1
                        for channel in channels
                        for _queue in selection._channel_queues(channel)
                    )
                    if self._want_channels
                    else None,
                    "cqs": len(self._cqs) - cq_start
                    if self._want_cqs
                    else None,
                    "eqs": len(self._eqs) - eq_start
                    if self._want_eqs
                    else None,
                    "qps": len(self._qps) - qp_start
                    if self._want_qps
                    else None,
                }

        dump_reports = self._collect_requested_dumps()
        self._flush_wqe_warning_groups()

        def device_count(name: str) -> Optional[int]:
            total = 0
            for device in devices:
                value = device.counts.get(name)
                if value is None:
                    return None
                total += value
            return total

        def object_count(
            name: str, records: Dict[Any, Any], collected: bool
        ) -> Optional[int]:
            if self._summary_counts_only:
                return device_count(name)
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
                "netdevs": sum(d.netdev is not None for d in devices),
                "channels": device_count("channels"),
                "queues": device_count("queues"),
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
                "netdevs": int(device.netdev is not None),
                "channels": channels,
                "queues": queues,
                "cqs": cqs,
                "eqs": eqs,
                "qps": self._count_summary_qps(device),
            }
        )

    # Channels, Ethernet queues, and their CQs

    def _count_summary_channels_and_queues(
        self,
        device: DeviceRecord,
    ) -> Tuple[int, int]:
        channel_total = 0
        queue_total = 0
        if device.netdev is not None:
            netdev = device.netdev
            priv = netdev["_priv_obj"]
            channels_obj = priv.channels
            for channel in mlx5_iter_channels(device.mdev):
                channel_total += 1
                queue_total += sum(
                    1 for _queue in mlx5_iter_channel_queues(channel)
                )

            ptp, state = self._ptp_object(channels_obj)
            if ptp is not None:
                ptp_queues = sum(
                    1 for _queue in self._iter_ptp_queues(ptp, state)
                )
                channel_total += 1
                queue_total += ptp_queues
        return channel_total, queue_total

    def _ptp_object(
        self, channels_obj: Object
    ) -> Tuple[Optional[Object], int]:
        ptp = channels_obj.ptp
        if not ptp:
            return None, 0
        state = int(ptp.state[0])
        return (None, state) if state == 0 else (ptp, state)

    def _iter_ptp_queues(
        self, ptp: Object, state: int
    ) -> Iterator[Tuple[str, Object, str, Optional[int], Optional[Object],]]:
        rx_bit = int(self.prog.constant("MLX5E_PTP_STATE_RX"))
        if state & (1 << rx_bit):
            yield "rx_rq", ptp.rq, "ptp_rq", None, None

        tx_bit = int(self.prog.constant("MLX5E_PTP_STATE_TX"))
        if not state & (1 << tx_bit):
            return
        for tc in range(int(ptp.num_tc)):
            ptpsq = ptp.ptpsq[tc]
            yield (
                "tx_sqs",
                ptpsq.txqsq,
                "ptp_sq",
                tc,
                ptpsq.ts_cq,
            )

    def _collect_channels(
        self,
        device: DeviceRecord,
        netdev_record: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        result = []
        for channel in mlx5_iter_channels(device.mdev):
            result.append(
                self._collect_channel(
                    device,
                    netdev_record,
                    channel,
                )
            )
        ptp_record = self._collect_ptp_channel(
            device, netdev_record, netdev_record["_priv_obj"].channels
        )
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

        for (
            report_field,
            queue,
            kind,
            tc,
            timestamp_cq,
        ) in self._iter_ptp_queues(ptp, state):
            queue_record = self._collect_queue(
                device,
                netdev_record,
                "ptp",
                queue,
                kind=kind,
                tc=tc,
            )
            if report_field == "rx_rq":
                record[report_field] = queue_record
            else:
                record[report_field].append(queue_record)
            if timestamp_cq is None:
                continue
            self._collect_mlx5e_cq(
                timestamp_cq,
                {
                    "device": device.mdev_address,
                    "netdev": netdev_record["name"],
                    "channel": "ptp",
                    "queue_kind": "ptp_ts_cq",
                    "queue_number": int(timestamp_cq.mcq.cqn),
                },
            )

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
            tc,
        ) in mlx5_iter_channel_queues(channel):
            queue_record = self._collect_queue(
                device,
                netdev_record,
                channel_index,
                queue,
                kind=kind,
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
        tc: Optional[int] = None,
    ) -> Dict[str, Any]:
        is_rq = kind in ("rq", "xskrq", "ptp_rq")
        number_field = "rqn" if is_rq else "sqn"
        qn = int(queue_obj.member_(number_field))
        device_name = device.mdev_address
        netdev_name = netdev_record["name"]
        state = int(queue_obj.state)
        linked_rq = False
        if is_rq:
            linked_type = int(
                self.prog.constant("MLX5_WQ_TYPE_LINKED_LIST_STRIDING_RQ")
            )
            linked_rq = int(queue_obj.wq_type) == linked_type
            wq = queue_obj.mpwqe.wq if linked_rq else queue_obj.wqe.wq
        else:
            wq = queue_obj.wq
        wq_summary = self._collect_wq_summary(wq)
        if is_rq:
            progress = {
                "pc": wq_summary.get("wqe_counter"),
                "cc": wq_summary.get("head") if linked_rq else None,
                "inflight": wq_summary.get("cur_size") if linked_rq else None,
            }
        else:
            pc = int(queue_obj.pc)
            cc = int(queue_obj.cc)
            inflight = _nonnegative_delta(pc, cc)
            progress = dict(
                pc=pc,
                cc=cc,
                inflight=inflight,
            )
        cq = queue_obj.cq
        owner = {
            "device": device_name,
            "netdev": netdev_name,
            "channel": channel_index,
            "queue_kind": kind,
            "queue_number": qn,
        }
        cq_record = self._collect_mlx5e_cq(cq, owner)

        txq = queue_obj.txq if kind in ("sq", "qos_sq", "ptp_sq") else None
        txq_state = int(txq.state) if txq else None
        state_prefix = "MLX5E_RQ_STATE_" if is_rq else "MLX5E_SQ_STATE_"
        enabled_bit = self.prog.constant(state_prefix + "ENABLED")
        recovering_bit = self.prog.constant(state_prefix + "RECOVERING")

        record = {
            "kind": kind,
            "tc": tc,
            "owner": _owner_string(owner),
            "device": device_name,
            "netdev": netdev_name,
            "channel": channel_index,
            "number": qn,
            **progress,
            "state": formatting._hex(state),
            "state_flags": formatting._enum_flags(
                state, enabled_bit.type_, state_prefix
            ),
            "enabled": bool(state & (1 << int(enabled_bit))),
            "recovering": bool(state & (1 << int(recovering_bit))),
            "txq_state_flags": formatting._enum_flags(
                txq_state,
                self.prog.type("enum netdev_queue_state_t"),
                "__QUEUE_STATE_",
            ),
            "txq_stopped": bool(txq_state) if txq_state is not None else None,
            "wq": wq_summary,
            "cq": cq_record,
        }
        key = (str(device_name), number_field, qn, record["owner"])
        if self.args.dump_wqe:
            self._mlx5e_queues[key] = _RingEntry(record, wq)
        return record

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

        if type_name == "struct mlx5_ib_wq":
            size = int(wq.wqe_cnt)
            summary = {
                "size": size,
                "head": None,
                "tail": None,
                "last_poll": None,
            }
            if kernel_backed and size > 0:
                summary.update(
                    {
                        "head": int(wq.head),
                        "tail": int(wq.tail),
                        "last_poll": int(wq.last_poll),
                    }
                )
            return summary

        if type_name == "struct mlx5_ib_cq_buf":
            return {
                "size": int(wq.nent),
                "stride_bytes": int(wq.cqe_size),
            }

        fbc = wq.fbc
        summary = {
            "size": int(fbc.sz_m1) + 1,
            "stride_bytes": 1 << int(fbc.log_stride),
        }
        if type_name == "struct mlx5_cqwq":
            summary["cc"] = int(wq.cc)
        else:
            summary["wqe_counter"] = int(wq.wqe_ctr)
            summary["cur_size"] = int(wq.cur_sz)
            if type_name == "struct mlx5_wq_ll":
                summary["head"] = int(wq.head)
        return summary

    def _collect_mlx5e_cq(
        self, cq: Object, owner: Dict[str, Any]
    ) -> Dict[str, Any]:
        mcq = cq.mcq
        cqn = int(mcq.cqn)
        owner_name = _owner_string(owner)
        key = (str(owner["device"]), cqn)
        entry = self._cqs.get(key)
        if entry is not None:
            record = entry.record
            if owner_name not in record["owners"]:
                record["owners"].append(owner_name)
            return record

        wq = cq.wq
        wq_summary = self._collect_wq_summary(wq)
        consumer_index = _cq_consumer_index("struct mlx5e_cq", wq_summary, mcq)
        record = {
            "cqn": cqn,
            "address": formatting._hex(int(cq.address_of_())),
            "address_struct": "struct mlx5e_cq",
            "owners": [owner_name],
            "device": owner["device"],
            "netdev": owner["netdev"],
            "queue_kind": owner["queue_kind"],
            "consumer_index": consumer_index,
            "arm_sn": int(mcq.arm_sn) & 0x3,
            "event_ctr": int(cq.event_ctr),
            "size": wq_summary.get("size"),
            "stride_bytes": wq_summary.get("stride_bytes"),
            **self._cq_eq_fields(mcq, str(owner["device"])),
        }
        self._cqs[key] = _RingEntry(record, wq)
        return record

    # Event queues and completion queues

    def _count_summary_eqs_and_cqs(
        self,
        device: DeviceRecord,
    ) -> Tuple[int, int]:
        eq_count = sum(1 for _core, _role in mlx5_iter_eqs(device.mdev))
        cq_count = sum(1 for _cq in mlx5_iter_core_cqs(device.mdev))
        return eq_count, cq_count

    def _cq_eq_fields(
        self, core_cq: Object, device_name: str
    ) -> Dict[str, Any]:
        core = core_cq.eq.core
        eqn = int(core.eqn)
        record = self._eqs[(device_name, eqn)].record
        return {
            field: record[field]
            for field in ("eqn", "irqn", "irq_cpu", "vector")
        }

    def _record_eq(
        self,
        core: Object,
        device: DeviceRecord,
        role: str,
    ) -> None:
        eqn = int(core.eqn)
        key = (device.mdev_address, eqn)
        if key in self._eqs:
            return
        irqn = int(core.irqn)
        record = {
            "eqn": eqn,
            "address": formatting._hex(int(core.address_)),
            "address_struct": "struct mlx5_eq",
            "device": device.mdev_address,
            "role": role,
            "irqn": irqn,
            "irq_cpu": _irq_affinity_cpus(self.prog, irqn),
            "vector": int(core.vecidx),
            "consumer_index": int(core.cons_index),
            "size": int(core.fbc.sz_m1) + 1,
            "cq_count": int(core.cq_count)
            if has_member(core, "cq_count")
            else None,
            "eqe_size": self.prog.type("struct mlx5_eqe").size,
        }
        self._eqs[key] = _EqEntry(record, core)

    def _record_core_cq(
        self,
        core_cq: Object,
        device: DeviceRecord,
    ) -> None:
        cqn = int(core_cq.cqn)
        key = (device.mdev_address, cqn)
        if key in self._cqs:
            return

        event = self._cq_event_name(core_cq.event)
        mlx5e_cq = None
        ib_cq = None
        if event == "mlx5e_cq_error_event":
            mlx5e_cq = container_of(core_cq, "struct mlx5e_cq", "mcq")
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
        if ib_cq is not None:
            address_obj, address_struct = ib_cq, "struct mlx5_ib_cq"
            size = int(ib_cq.ibcq.cqe) + 1
            stride_bytes = int(ib_cq.cqe_size)
            if not ib_cq.ibcq.uobject:
                wq = ib_cq.buf
            queue_kind = "rdma_cq"
        elif mlx5e_cq is not None:
            address_obj, address_struct = mlx5e_cq, "struct mlx5e_cq"
            wq = mlx5e_cq.wq
            mlx5e_owner = self._mlx5e_core_cq_owner(mlx5e_cq, core_cq, device)
            netdev = mlx5e_owner.get("netdev")
            queue_kind = mlx5e_owner.get("queue_kind")
            event_ctr = int(mlx5e_cq.event_ctr)
            specific_owner = _owner_string(mlx5e_owner)
        owners = [specific_owner] if specific_owner else []
        wq_summary = self._collect_wq_summary(wq)
        consumer_index = _cq_consumer_index(
            address_struct, wq_summary, core_cq
        )
        record = {
            "cqn": cqn,
            "address": formatting._hex(int(address_obj)),
            "address_struct": address_struct,
            "owners": owners,
            "device": device.mdev_address,
            "netdev": netdev,
            "queue_kind": queue_kind,
            "consumer_index": consumer_index,
            "arm_sn": int(core_cq.arm_sn) & 0x3,
            "event_ctr": event_ctr,
            "size": size or wq_summary.get("size"),
            "stride_bytes": stride_bytes
            or wq_summary.get("stride_bytes")
            or int(core_cq.cqe_sz),
            **self._cq_eq_fields(core_cq, device.mdev_address),
        }

        self._cqs[key] = _RingEntry(record, wq)

    def _cq_event_name(self, event: Object) -> Optional[str]:
        if not event:
            return None
        address = int(event)
        if address not in self._cq_event_names:
            self._cq_event_names[address] = self.prog.symbol(address).name
        return self._cq_event_names[address]

    def _mlx5e_core_cq_owner(
        self, cq: Object, core_cq: Object, device: DeviceRecord
    ) -> Dict[str, Any]:
        cqn = int(core_cq.cqn)
        cq_netdev = cq.netdev
        netdev_name = None
        netdev = device.netdev
        if netdev is not None:
            priv = netdev["_priv_obj"]
            if int(cq) == int(priv.drop_rq.cq.address_of_()):
                return {
                    "device": device.mdev_address,
                    "netdev": netdev["name"],
                    "queue_kind": "drop_rq_cq",
                    "queue_number": cqn,
                }
            if cq_netdev and int(cq_netdev) == int(priv.netdev):
                netdev_name = netdev["name"]
        if netdev_name is None and cq_netdev:
            netdev_name = cq_netdev.name.string_().decode("utf-8", "replace")

        return {
            "device": device.mdev_address,
            "netdev": netdev_name,
            "queue_kind": "mlx5e_cq",
            "queue_number": cqn,
        }

    # RDMA queue pairs

    def _count_summary_qps(self, device: DeviceRecord) -> int:
        ibdev = device.ibdev
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
            key=lambda record: formatting._sort_key(record["qpn"]),
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
        else:
            if subject:
                name = subject.string_().decode("utf-8", "replace")
            display = f"kernel:{name}" if name else "kernel"
        creator = {
            "display": display,
            "type": creator_type,
        }
        self._qp_creators[key] = creator
        return creator

    def _ib_cq_number(self, cq: Optional[Object]) -> Optional[int]:
        if not cq:
            return None
        address = int(cq)
        if address not in self._ib_cq_numbers:
            mlx5_ib_cq = container_of(cq, "struct mlx5_ib_cq", "ibcq")
            self._ib_cq_numbers[address] = int(mlx5_ib_cq.mcq.cqn)
        return self._ib_cq_numbers[address]

    def _qp_type(self, qp: Object) -> int:
        if has_member(qp, "type"):
            return int(qp.type)
        ib_qp_type = int(qp.ibqp.qp_type)
        if ib_qp_type == int(self.prog.constant("IB_QPT_DRIVER")):
            return int(qp.qp_sub_type)
        return ib_qp_type

    def _record_qp(self, qp: Object, device: DeviceRecord) -> None:
        qpn = int(qp.ibqp.qp_num)
        hw_qpn = int(qp.trans_qp.base.mqp.qpn)
        if self.args.qpn is not None and int(self.args.qpn) not in (
            qpn,
            hw_qpn,
        ):
            return

        send_cq = qp.ibqp.send_cq
        recv_cq = qp.ibqp.recv_cq
        qp_type = self._qp_type(qp)
        creator = self._qp_creator(qp)
        sq_wq = qp.sq
        rq_wq = qp.rq
        kernel_backed = creator["type"] == "kernel"
        sq_summary = self._collect_wq_summary(sq_wq, kernel_backed)
        rq_summary = self._collect_wq_summary(rq_wq, kernel_backed)
        qp_state = int(qp.state)
        eligible_sq_wq = (
            sq_wq if kernel_backed and int(sq_summary["size"]) > 0 else None
        )
        record = {
            "qpn": qpn,
            "hw_qpn": hw_qpn,
            "address": formatting._hex(int(qp)),
            "address_struct": "struct mlx5_ib_qp",
            "device": device.mdev_address,
            "owner": "mlx5_ib_qp_list",
            "creator": creator["display"],
            "creator_type": creator["type"],
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
            "is_rss": int(qp.is_rss) if has_member(qp, "is_rss") else None,
            "max_inline_data": int(qp.max_inline_data),
            "db": formatting._hex(int(qp.db.address_)),
            "buf": formatting._hex(int(qp.buf.address_)),
            "send_cq": formatting._hex(int(send_cq) if send_cq else None),
            "recv_cq": formatting._hex(int(recv_cq) if recv_cq else None),
            "send_cqn": self._ib_cq_number(send_cq),
            "recv_cqn": self._ib_cq_number(recv_cq),
            "sq": sq_summary,
            "rq": rq_summary,
        }
        self._qps[int(qp)] = _QpEntry(record, eligible_sq_wq)

    # Descriptor selection and dumps

    def _collect_requested_dumps(self) -> List[Dict[str, Any]]:
        dump_reports: List[Dict[str, Any]] = []
        if self.args.dump_cqe:
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
                    self._dump_cqe_key(key, self.args.maxcqe)
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
                    self._dump_cqe_key(key, self.args.maxcqe)
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
            sq_pc = sq.get("head") if isinstance(sq, dict) else None
            sq_cc = sq.get("tail") if isinstance(sq, dict) else None
            inflight = _nonnegative_delta(sq_pc, sq_cc)
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
            "notes": [],
            "entries": entries,
        }

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
            if isinstance(wq_summary, dict)
            and _nonnegative_delta(
                wq_summary.get("head"), wq_summary.get("tail")
            )
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

        fbc = wq.fbc.read_()
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
        fragment_cache: Dict[int, Tuple[int, int, Optional[bytes]]] = {}
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
                    "status": "read-unavailable",
                }
                if around_consumer and cursor == consumer:
                    entry["consumer_marker"] = "cons_index"
                entries.append(entry)
                cursor += 1
                traversed += 1
                continue

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
            netdev = device.netdev
            if netdev is not None:
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
        findings.extend(self._descriptor_findings(dump_reports))
        return findings

    def _descriptor_findings(
        self, dump_reports: Sequence[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        if not dump_reports:
            return []
        findings = []
        cqe_errors: Tuple[int, ...] = ()

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
            selector_name = dump.get("selector_name") or "id"
            selector = dump.get("selector")
            scope = dump.get("device") or "mlx5"
            for entry in dump.get("entries", []) or []:
                if entry.get("status", "ok") not in ("ok", "ready"):
                    continue
                if kind == "cqe" and entry.get("opcode_value") in cqe_errors:
                    add(
                        scope,
                        f"CQE error on {selector_name}={selector} index {entry.get('index')}"
                        f" syndrome={entry.get('syndrome_display')}",
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


def _cq_consumer_index(
    address_struct: str,
    wq_summary: Dict[str, Any],
    core_cq: Object,
) -> Optional[int]:
    """Choose the CQ consumer counter for its owner.

    mlx5_ib polls mlx5_core_cq.cons_index. mlx5e polls through mlx5_cqwq,
    so use wq.cc; its mcq.cons_index may remain zero.
    """

    wq_cc = wq_summary.get("cc")
    if address_struct == "struct mlx5e_cq" and wq_cc is not None:
        return wq_cc
    return int(core_cq.cons_index)


def _wqe_ctrl_wqebbs(decoded: Dict[str, Any], stride_bytes: int) -> int:
    ds = decoded.get("ds")
    if ds is None or ds <= 0:
        return 1
    return max(1, (ds * 16 + stride_bytes - 1) // stride_bytes)


def _nonnegative_delta(pc: Optional[int], cc: Optional[int]) -> Optional[int]:
    if pc is None or cc is None or pc < cc:
        return None
    return pc - cc


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
