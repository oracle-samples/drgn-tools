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
import logging
from collections import Counter
from collections import defaultdict
from collections import OrderedDict
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
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
from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn import ProgramFlags

from .mlx5_support import collect_device
from .mlx5_support import compat
from .mlx5_support import decode
from .mlx5_support import defs
from .mlx5_support import dumps
from .mlx5_support import format as formatting
from .mlx5_support import render
from .mlx5_support import selection
from drgn_tools.corelens import CorelensModule


# Short aliases used throughout this module.
MAX_DEFAULT_DESCRIPTOR_ENTRIES = defs.MAX_DEFAULT_DESCRIPTOR_ENTRIES
MAX_DEFAULT_WALK_LIMIT = defs.MAX_DEFAULT_WALK_LIMIT
_decode_cqe = decode._decode_cqe
_decode_eqe = decode._decode_eqe
_decode_rq_wqe = decode._decode_rq_wqe
_decode_wqe = decode._decode_wqe
_jsonable = formatting._jsonable

LOG = logging.getLogger("drgn_tools.mlx5")
_KeyT = TypeVar("_KeyT", bound=Tuple[Any, ...])
_REPORT_ARGUMENTS = (
    "dev",
    "netdev",
    "ip",
    "summary",
    "full",
    "queues",
    "cqs",
    "ib_cqs",
    "eth_cqs",
    "eqs",
    "qps",
    "qp_creators",
    "dump_cqe",
    "dump_eqe",
    "dump_wqe",
    "cqn",
    "eqn",
    "qpn",
    "sqn",
    "rqn",
    "maxqueues",
    "maxcq",
    "maxeq",
    "maxqp",
    "maxcqe",
    "maxeqe",
    "maxwqe",
    "walk_limit",
    "json",
    "strict",
)
_SELECTION_ARGUMENTS = tuple(
    name for name in _REPORT_ARGUMENTS if name not in {"json", "strict"}
)
_SELECTION_BOOLS = frozenset(
    (
        "summary",
        "full",
        "queues",
        "cqs",
        "ib_cqs",
        "eth_cqs",
        "eqs",
        "qps",
        "dump_cqe",
        "dump_eqe",
        "dump_wqe",
    )
)


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
            "--walk-limit",
            type=int,
            default=MAX_DEFAULT_WALK_LIMIT,
            help="Maximum objects to walk per kernel table/list, default: no cap",
        )
        parser.add_argument(
            "--json", action="store_true", help="Emit machine-readable JSON"
        )
        parser.add_argument(
            "--strict",
            action="store_true",
            help="Raise if a collector recorded warnings",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        kwargs = {name: getattr(args, name) for name in _REPORT_ARGUMENTS}
        kwargs["json_output"] = kwargs.pop("json")
        mlx5_report(prog, **kwargs)


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
    walk_limit: Optional[int] = MAX_DEFAULT_WALK_LIMIT,
    json_output: bool = False,
    strict: bool = False,
) -> Dict[str, Any]:
    """Collect, render, and return an mlx5 report."""

    values = locals().copy()
    values.pop("prog")
    values["json"] = values.pop("json_output")
    values["qp_creators"] = list(values["qp_creators"] or [])
    args = argparse.Namespace(**values)
    selection._resolve_report_sections(args)
    _validate_args(args)

    collector = Mlx5Collector(prog, args)
    try:
        report = collector.collect()
    except Exception as err:  # pylint: disable=broad-except
        msg = f"mlx5 collection failed: {type(err).__name__}: {err}"
        LOG.exception(msg)
        report = _minimal_error_report(prog, args, msg)

    if args.json:
        print(json.dumps(_jsonable(report), indent=2, sort_keys=True))
    else:
        render.render_report(report, args)

    if args.strict and report.get("warnings"):
        raise RuntimeError(
            "mlx5 strict mode warnings: " + "; ".join(report["warnings"])
        )
    return report


def _new_channel_record(
    channel: Object,
    index: Any,
    cpu: Optional[int] = None,
    irq_desc: Optional[Object] = None,
    irqn: Optional[int] = None,
    vector: Optional[int] = None,
) -> Dict[str, Any]:
    napi = compat._safe_member(channel, "napi")
    return {
        "index": index,
        "address": formatting._hex(compat._addr(channel)),
        "cpu": cpu,
        "napi": formatting._hex(compat._addr(napi)),
        "napi_id": compat._safe_int(compat._safe_member(napi, "napi_id")),
        "napi_state": formatting._hex(
            compat._safe_int(compat._safe_member(napi, "state"))
        ),
        "napi_weight": compat._safe_int(compat._safe_member(napi, "weight")),
        "napi_poll_owner": compat._safe_int(
            compat._safe_member(napi, "poll_owner")
        ),
        "irq_desc": formatting._hex(compat._addr(irq_desc)),
        "irqn": irqn,
        "eqn": None,
        "vector": vector,
        "tx_sqs": [],
        "xdp_sqs": [],
        "icosqs": [],
        "rx_rq": None,
    }


def _program_mode(prog: Program) -> str:
    try:
        return "live" if (prog.flags & ProgramFlags.IS_LIVE) else "vmcore"
    except Exception:
        return "unknown"


def _report_selection(args: argparse.Namespace) -> Dict[str, Any]:
    report_selection = {
        name: getattr(args, name, None) for name in _SELECTION_ARGUMENTS
    }
    for name in _SELECTION_BOOLS:
        report_selection[name] = bool(report_selection[name])
    report_selection["qp_creators"] = list(
        report_selection["qp_creators"] or []
    )
    return report_selection


def _minimal_error_report(
    prog: Program, args: argparse.Namespace, warning: str
) -> Dict[str, Any]:
    return {
        "module": "mlx5",
        "mode": _program_mode(prog),
        "selection": _report_selection(args),
        "devices": [],
        "cqs": [],
        "eqs": [],
        "qps": [],
        "qp_creator_resolution": None,
        "dumps": [],
        "findings": [],
        "warnings": [warning],
        "truncated_walks": False,
        "counts": {
            "devices": 0,
            "netdevs": 0,
            "channels": None,
            "queues": None,
            "cqs": 0,
            "eqs": 0,
            "qps": 0,
        },
    }


def _collection_plan(args: argparse.Namespace) -> Dict[str, bool]:
    """Return the kernel walks required by the selected sections."""

    full_report = bool(getattr(args, "_full_report", False))

    def requested(*names: str) -> bool:
        return any(bool(getattr(args, name, False)) for name in names)

    def selected(*names: str) -> bool:
        return any(getattr(args, name, None) is not None for name in names)

    wants_cqs = (
        full_report
        or requested("cqs", "ib_cqs", "eth_cqs", "dump_cqe")
        or selected("cqn")
    )
    # Resolving IB CQE WR_IDs needs the QP-to-CQ indexes.
    wants_qps = (
        full_report
        or requested("qps", "dump_wqe", "dump_cqe")
        or selected("qpn")
    )
    # Ethernet and queue-owned CQs are found through mlx5e channels.
    wants_channels = (
        full_report
        or requested("queues", "dump_wqe", "eth_cqs", "dump_cqe")
        or selected("sqn", "rqn")
        or (wants_cqs and not getattr(args, "ib_cqs", False))
    )
    wants_eqs = (
        full_report
        or requested("eqs", "dump_eqe")
        or wants_cqs
        or wants_channels
        or selected("eqn")
    )
    return {
        "channels": wants_channels,
        "eqs": wants_eqs,
        "cqs": wants_cqs,
        "qps": wants_qps,
    }


def _summary_counts_only(args: argparse.Namespace) -> bool:
    """Whether --summary needs only count walks."""

    detail_flags = (
        "queues cqs ib_cqs eth_cqs eqs qps dump_cqe dump_eqe dump_wqe".split()
    )
    selectors = "cqn eqn qpn sqn rqn".split()
    return bool(
        getattr(args, "summary", False)
        and not getattr(args, "full", False)
        and not getattr(args, "_full_report", False)
        and not any(bool(getattr(args, name, False)) for name in detail_flags)
        and not any(
            getattr(args, name, None) is not None for name in selectors
        )
    )


class _RingEntry(NamedTuple):
    """Report record and WQ used for later dumps."""

    record: Dict[str, Any]
    wq: Optional[Object]


class _EqEntry(NamedTuple):
    """Report record plus EQ and WQ objects used by CQ/EQE walks."""

    record: Dict[str, Any]
    eq: Object
    wq: Optional[Object]


class _QpEntry(NamedTuple):
    """Report record plus queue objects used for WQE and WR-ID reads."""

    record: Dict[str, Any]
    dump_wq: Optional[Object]
    sq_wq: Optional[Object]
    rq_wq: Optional[Object]


class _QpKey(NamedTuple):
    """Stable internal identity for one mlx5 QP object."""

    device: str
    kind: str
    value: int


class _QpIdentity(NamedTuple):
    """QP numbers and the key shared by summary and full collection."""

    key: Optional[_QpKey]
    qpn: Optional[int]
    ib_qpn: Optional[int]
    hw_qpn: Optional[int]
    aliases: Tuple[int, ...]


class Mlx5Collector(collect_device.DeviceCollectorMixin):
    """Collect one mlx5 report."""

    def __init__(self, prog: Program, args: argparse.Namespace) -> None:
        self.prog = prog
        self.args = args
        self.warnings: List[str] = []
        self._plan = _collection_plan(args)
        self._summary_counts_only = _summary_counts_only(args)
        self._cqs: Dict[Tuple[str, int], _RingEntry] = {}
        self._eqs: Dict[Tuple[str, int], _EqEntry] = {}
        self._qps: Dict[_QpKey, _QpEntry] = {}
        self._mlx5e_queues: Dict[Tuple[str, str, int, str], _RingEntry] = {}
        self._qp_keys_by_send_cqn: Dict[Tuple[str, int], List[_QpKey]] = {}
        self._qp_keys_by_alias: Dict[Tuple[str, int], List[_QpKey]] = {}
        self._selected_device_names: Set[str] = set()
        self._mlx5_ib_devices_cache: Optional[List[Object]] = None
        self._wqe_warning_groups: "OrderedDict[Tuple[str, str, str], Dict[str, Any]]" = (
            OrderedDict()
        )
        self._truncated_walks = False

    def collect(self) -> Dict[str, Any]:
        devices = self._discover_devices()
        devices = self._filter_devices(devices)
        self._selected_device_names = {str(d.get("name")) for d in devices}

        for device in devices:
            self._collect_device_details(device)

        if self._summary_counts_only:
            for device in devices:
                self._collect_summary_counts(device)
        else:
            for device in devices:
                if self._plan["eqs"]:
                    self._collect_eqs_from_device(device)
                if self._plan["cqs"]:
                    self._collect_cqs_from_eq_tables(device)
                if self._plan["qps"]:
                    for qp, owner, table_qpn in self._iter_qps_from_device(
                        device, summary=False
                    ):
                        self._record_selected_qp(qp, device, owner, table_qpn)

            self._correlate_cqs_to_eqs()
            self._annotate_channels_from_cqs(devices)
            for device in devices:
                device["counts"] = self._device_counts(device)
        if self._plan["qps"]:
            self._rebuild_qp_indexes()

        dump_reports = self._collect_requested_dumps()
        self._flush_wqe_warning_groups()

        def object_count(name: str, records: Dict[Any, Any]) -> Optional[int]:
            if self._summary_counts_only:
                return collect_device._sum_known(
                    d.get("counts", {}).get(name) for d in devices
                )
            return len(records) if self._plan[name] else None

        return {
            "module": "mlx5",
            "mode": _program_mode(self.prog),
            "selection": _report_selection(self.args),
            "devices": devices,
            "cqs": sorted(
                (e.record for e in self._cqs.values()),
                key=lambda r: formatting._sort_key(r.get("cqn")),
            ),
            "eqs": sorted(
                (e.record for e in self._eqs.values()),
                key=lambda r: formatting._sort_key(r.get("eqn")),
            ),
            "qps": self._report_qps(),
            "qp_creator_resolution": (
                _qp_creator_resolution(
                    entry.record for entry in self._qps.values()
                )
                if self._plan["qps"]
                else None
            ),
            "dumps": dump_reports,
            "findings": self._analyze_findings(devices, dump_reports),
            "warnings": self.warnings,
            "truncated_walks": self._truncated_walks,
            "counts": {
                "devices": len(devices),
                "netdevs": sum(len(d.get("netdevs", [])) for d in devices),
                "channels": collect_device._sum_known(
                    d.get("counts", {}).get("channels") for d in devices
                ),
                "queues": collect_device._sum_known(
                    d.get("counts", {}).get("queues") for d in devices
                ),
                "cqs": object_count("cqs", self._cqs),
                "eqs": object_count("eqs", self._eqs),
                "qps": object_count("qps", self._qps),
            },
        }

    def _collect_summary_counts(self, device: Dict[str, Any]) -> None:
        """Collect counts without building detailed records."""

        channels, queues, queue_cqns = self._count_summary_channels_and_queues(
            device
        )
        eqs, cqs = self._count_summary_eqs_and_cqs(device, queue_cqns)
        device.setdefault("counts", {}).update(
            {
                "netdevs": len(device.get("netdevs", [])),
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

    def _count_summary_channels_and_queues(
        self,
        device: Dict[str, Any],
    ) -> Tuple[Optional[int], Optional[int], Set[int]]:
        channel_total = 0
        queue_total = 0
        cqns: Set[int] = set()
        for netdev in device.get("netdevs", []):
            priv = netdev.get("_priv_obj")
            layout = self._channel_layout(netdev, priv)
            if layout is None or priv is None:
                return None, None, cqns
            channels_obj, count, channel_array, *_sources = layout
            for index in range(count):
                channel = compat._safe_index(channel_array, index)
                if channel is None or compat._is_null(channel):
                    continue
                channel_total += 1
                for (
                    _field,
                    queue,
                    _kind,
                    _role,
                    _tc,
                    _source,
                ) in self._iter_channel_queues(
                    channel, priv, "summary qos_sq count"
                ):
                    queue_total += 1
                    self._add_summary_queue_cqn(queue, cqns)

            ptp_queues = self._count_summary_ptp_queues(
                channels_obj, priv, cqns
            )
            if ptp_queues:
                channel_total += 1
                queue_total += ptp_queues
        return channel_total, queue_total, cqns

    def _channel_layout(
        self,
        netdev: Dict[str, Any],
        priv: Optional[Object],
        detailed: bool = False,
    ) -> Optional[
        Tuple[Object, int, Object, Optional[str], Optional[str], Optional[str]]
    ]:
        name = netdev.get("name")

        def missing(message: str) -> None:
            if detailed:
                self._warn(f"{name}: {message}; queue walk skipped")

        if priv is None:
            missing("mlx5e_priv unavailable")
            return None
        channels, channels_source = compat._first_member_path_with_source(
            priv, defs._MLX5E_CHANNELS_OBJECT_PATHS
        )
        if channels is None:
            missing("mlx5e channel container unavailable")
            return None
        count, count_source = compat._first_int_path_with_source(
            channels, defs._MLX5E_CHANNEL_COUNT_PATHS
        )
        if count is None:
            count, count_source = compat._first_int_path_with_source(
                priv,
                (
                    ("struct mlx5e_priv.stats_nch", ["stats_nch"]),
                    ("struct mlx5e_priv.max_nch", ["max_nch"]),
                    ("struct mlx5e_priv.channels_num", ["channels_num"]),
                ),
            )
        if count is None:
            count = compat._safe_int(
                compat._safe_member(
                    compat._safe_member(
                        netdev.get("_netdev_obj"), "real_num_rx_queues"
                    ),
                    "counter",
                )
            )
            if count is not None:
                count_source = "struct net_device.real_num_rx_queues.counter"
        if count is None:
            missing("channel count unavailable")
            return None
        scope = "channel walk" if detailed else "summary channel count"
        count = self._walk_count(
            count, f"{name}: {scope}", hard_limit=defs.MAX_CHANNELS
        )
        array, array_source = compat._first_member_path_with_source(
            channels, defs._MLX5E_CHANNEL_ARRAY_PATHS
        )
        if array is None:
            missing("channel array unavailable")
            return None
        return (
            channels,
            count,
            array,
            channels_source,
            count_source,
            array_source,
        )

    def _iter_channel_queues(
        self, channel: Object, priv: Object, qos_scope: str
    ) -> Iterator[Tuple[str, Object, str, str, Optional[int], Optional[str]]]:
        def present(
            queue: Optional[Object],
            kind: str = "sq",
            require_activity: bool = False,
        ) -> bool:
            if queue is None:
                return False
            if require_activity:
                number, _source = _queue_number_with_source(queue, kind)
                return (
                    number not in (None, 0)
                    or compat._safe_int(compat._safe_member(queue, "state"))
                    not in (None, 0)
                    or compat._first_int_path(
                        queue,
                        (["pc"], ["wq", "pc"], ["wqe_ctr"], ["wq", "wqe_ctr"]),
                    )
                    not in (None, 0)
                    or compat._first_int_path(
                        queue, (["cc"], ["wq", "cc"], ["wq", "head"])
                    )
                    not in (None, 0)
                )
            return self._queue_object_has_identity(queue, kind)

        rq, source = compat._first_member_path_with_source(
            channel, defs._MLX5E_CHANNEL_RQ_PATHS
        )
        if rq is not None:
            yield "rx_rq", rq, "rq", "rx", None, source

        num_tc = compat._safe_int(compat._safe_member(channel, "num_tc"))
        if num_tc is None or num_tc <= 0:
            num_tc = _num_tc_from_priv(priv)
        sq_base, source = compat._first_member_path_with_source(
            channel, defs._MLX5E_CHANNEL_SQ_PATHS
        )
        if num_tc is not None and num_tc > 0:
            for tc in range(min(num_tc, defs.MAX_TC)):
                sq = compat._safe_index_or_self(sq_base, tc)
                if present(sq):
                    yield "tx_sqs", sq, "sq", "tx", tc, source

        qos_sqs = compat._safe_member(channel, "qos_sqs")
        qos_sqs_size = compat._safe_int(
            compat._safe_member(channel, "qos_sqs_size")
        )
        if qos_sqs is not None and qos_sqs_size is not None:
            for index in range(self._walk_count(qos_sqs_size, qos_scope)):
                sq = compat._safe_index(qos_sqs, index)
                if present(sq):
                    yield "tx_sqs", sq, "qos_sq", "tx", index, None

        xskrq = compat._safe_member(channel, "xskrq")
        if present(xskrq, "rq", require_activity=True):
            yield "xsk_rqs", xskrq, "xskrq", "rx", None, None

        for field in ("xdp_sq", "xdpsq", "rq_xdpsq", "xsksq"):
            sq = compat._safe_member(channel, field)
            if present(sq, require_activity=field in ("rq_xdpsq", "xsksq")):
                yield "xdp_sqs", sq, field, "xdp", None, None

        for field in ("icosq", "async_icosq"):
            sq = compat._safe_member(channel, field)
            if present(sq):
                yield "icosqs", sq, field, "internal", None, None

    def _count_summary_ptp_queues(
        self, channels_obj: Object, priv: Object, cqns: Set[int]
    ) -> int:
        ptp, _state = self._ptp_object(channels_obj)
        if ptp is None:
            return 0
        count = 0
        rq = compat._safe_member(ptp, "rq")
        if self._queue_object_has_identity(rq, "rq"):
            count += 1
            self._add_summary_queue_cqn(rq, cqns)
        for _tc, ptpsq in self._iter_ptp_sqs(ptp, priv):
            txqsq = compat._safe_member(ptpsq, "txqsq")
            if self._queue_object_has_identity(txqsq, "sq"):
                count += 1
                self._add_summary_queue_cqn(txqsq, cqns)
            ts_cq = compat._safe_member(ptpsq, "ts_cq")
            cqn = compat._first_int_path(
                ts_cq, (["mcq", "cqn"], ["core", "cqn"], ["cqn"])
            )
            if cqn is not None:
                cqns.add(cqn)
        return count

    def _ptp_object(
        self, channels_obj: Object
    ) -> Tuple[Optional[Object], Optional[int]]:
        ptp = compat._safe_member(channels_obj, "ptp")
        if ptp is None or compat._is_null(ptp):
            return None, None
        state = compat._safe_array_int(compat._safe_member(ptp, "state"), 0)
        return (None, state) if state == 0 else (ptp, state)

    def _iter_ptp_sqs(
        self, ptp: Object, priv: Object
    ) -> Iterator[Tuple[int, Object]]:
        num_tc = compat._first_int_path(ptp, (["num_tc"],))
        if num_tc is None:
            num_tc = _num_tc_from_priv(priv)
        if num_tc is None or num_tc <= 0:
            return
        ptpsq_base = compat._safe_member(ptp, "ptpsq")
        for tc in range(min(num_tc, defs.MAX_TC)):
            ptpsq = compat._safe_index_or_self(ptpsq_base, tc)
            if ptpsq is not None:
                yield tc, ptpsq

    def _queue_object_has_identity(
        self, queue: Optional[Object], kind: str
    ) -> bool:
        if queue is None:
            return False
        qn, _source = _queue_number_with_source(queue, kind)
        return qn is not None or compat._addr(queue) not in (None, 0)

    def _add_summary_queue_cqn(self, queue: Object, cqns: Set[int]) -> None:
        cq = compat._safe_member(queue, "cq")
        cqn = compat._first_int_path(
            cq, (["mcq", "cqn"], ["core", "cqn"], ["cqn"])
        )
        if cqn is not None:
            cqns.add(cqn)

    def _collect_channels(
        self,
        device: Dict[str, Any],
        netdev_record: Dict[str, Any],
        priv: Optional[Object],
    ) -> List[Dict[str, Any]]:
        layout = self._channel_layout(netdev_record, priv, detailed=True)
        if layout is None or priv is None:
            return []
        (
            channels_obj,
            num,
            ch_array,
            channels_source,
            num_source,
            ch_array_source,
        ) = layout

        result = []
        for ix in range(num):
            ch = compat._safe_index(ch_array, ix)
            if ch is None or compat._is_null(ch):
                continue
            ch_record = self._collect_channel(
                device, netdev_record, priv, ch, ix
            )
            ch_record["channels_source"] = channels_source
            ch_record["channel_count_source"] = num_source
            ch_record["channel_array_source"] = ch_array_source
            result.append(ch_record)
        ptp_record = self._collect_ptp_channel(
            device, netdev_record, priv, channels_obj
        )
        if ptp_record is not None:
            result.append(ptp_record)
        return result

    def _collect_ptp_channel(
        self,
        device: Dict[str, Any],
        netdev_record: Dict[str, Any],
        priv: Object,
        channels_obj: Object,
    ) -> Optional[Dict[str, Any]]:
        ptp, state = self._ptp_object(channels_obj)
        if ptp is None:
            return None
        record = _new_channel_record(ptp, "ptp")
        record.update({"ptp": True, "state": formatting._hex(state)})

        rq = compat._safe_member(ptp, "rq")
        if rq is not None:
            rq_record = self._collect_queue(
                device,
                netdev_record,
                "ptp",
                rq,
                kind="ptp_rq",
                role="rx",
                state_bits=defs._MLX5E_RQ_STATE_BITS,
            )
            if _queue_record_has_identity(rq_record):
                record["rx_rq"] = rq_record

        for tc, ptpsq in self._iter_ptp_sqs(ptp, priv):
            txqsq = compat._safe_member(ptpsq, "txqsq")
            if txqsq is not None:
                sq_record = self._collect_queue(
                    device,
                    netdev_record,
                    "ptp",
                    txqsq,
                    kind="ptp_sq",
                    role="tx",
                    state_bits=defs._MLX5E_SQ_STATE_BITS,
                    tc=tc,
                )
                if _queue_record_has_identity(sq_record):
                    record["tx_sqs"].append(sq_record)
            ts_cq = compat._safe_member(ptpsq, "ts_cq")
            if ts_cq is not None:
                self._collect_mlx5e_cq(
                    ts_cq,
                    {
                        "device": device.get("name"),
                        "netdev": netdev_record.get("name"),
                        "channel": "ptp",
                        "queue_kind": "ptp_ts_cq",
                        "queue_role": "timestamp",
                        "queue_number": compat._safe_int(
                            compat._safe_member_path(ts_cq, ["mcq", "cqn"])
                        ),
                        "tc": tc,
                    },
                )

        if record["rx_rq"] is None and not record["tx_sqs"]:
            return None
        return record

    def _collect_channel(
        self,
        device: Dict[str, Any],
        netdev_record: Dict[str, Any],
        priv: Object,
        ch: Object,
        fallback_ix: int,
    ) -> Dict[str, Any]:
        ch_ix = compat._safe_int(compat._safe_member(ch, "ix"))
        if ch_ix is None:
            ch_ix = fallback_ix
        cpu = compat._safe_int(compat._safe_member(ch, "cpu"))
        irq_desc = compat._first_member_path(
            ch, (["irq_desc"], ["irq", "desc"])
        )
        irqn = compat._first_int_path(ch, (["irqn"], ["irq", "irqn"]))
        vector = compat._first_int_path(ch, (["vec_ix"], ["vector"]))

        record = _new_channel_record(
            ch, ch_ix, cpu=cpu, irq_desc=irq_desc, irqn=irqn, vector=vector
        )

        qos_scope = f"{netdev_record.get('name')}: channel {ch_ix} qos_sq walk"
        for (
            report_field,
            queue,
            kind,
            role,
            tc,
            source,
        ) in self._iter_channel_queues(ch, priv, qos_scope):
            if kind in ("rq", "xskrq"):
                state_bits = defs._MLX5E_RQ_STATE_BITS
            elif report_field == "icosqs":
                state_bits = defs._MLX5E_ICOSQ_STATE_BITS
            else:
                state_bits = defs._MLX5E_SQ_STATE_BITS
            queue_record = self._collect_queue(
                device,
                netdev_record,
                ch_ix,
                queue,
                kind=kind,
                role=role,
                state_bits=state_bits,
                tc=tc,
            )
            if source is not None:
                queue_record["queue_container_source"] = source
            if report_field == "rx_rq":
                record[report_field] = queue_record
            elif report_field == "xsk_rqs":
                if (
                    queue_record.get("number") not in (None, 0)
                    or bool(queue_record.get("enabled"))
                    or queue_record.get("pc") not in (None, 0)
                    or queue_record.get("cc") not in (None, 0)
                ):
                    record.setdefault(report_field, []).append(queue_record)
            elif _queue_record_has_identity(queue_record):
                record[report_field].append(queue_record)

        return record

    def _collect_queue(
        self,
        device: Dict[str, Any],
        netdev_record: Dict[str, Any],
        channel_index: Union[int, str],
        queue_obj: Object,
        kind: str,
        role: str,
        state_bits: Dict[int, str],
        tc: Optional[int] = None,
    ) -> Dict[str, Any]:
        qn, qn_source = _queue_number_with_source(queue_obj, kind)
        state = compat._safe_int(compat._safe_member(queue_obj, "state"))
        wq, wq_source = self._queue_wq_with_source(queue_obj, kind)
        if kind in ("rq", "xskrq", "ptp_rq"):
            progress = _rq_progress_detail(queue_obj, wq, wq_source)
        else:
            pc, pc_source = compat._first_int_path_with_source(
                queue_obj,
                (
                    ("queue.pc", ["pc"]),
                    ("queue.wq.pc", ["wq", "pc"]),
                    ("queue.wqe_ctr", ["wqe_ctr"]),
                    ("queue.wq.wqe_ctr", ["wq", "wqe_ctr"]),
                ),
            )
            cc, cc_source = compat._first_int_path_with_source(
                queue_obj,
                (
                    ("queue.cc", ["cc"]),
                    ("queue.wq.cc", ["wq", "cc"]),
                    ("queue.wq.head", ["wq", "head"]),
                ),
            )
            inflight = _nonnegative_delta(pc, cc)
            inflight_source = "pc-cc" if inflight is not None else None
            progress = dict(
                pc=pc,
                cc=cc,
                inflight=inflight,
                pc_source=pc_source,
                cc_source=cc_source,
                inflight_source=inflight_source,
            )
        cq = compat._safe_member(queue_obj, "cq")
        owner = {
            "device": device.get("name"),
            "netdev": netdev_record.get("name"),
            "channel": channel_index,
            "queue_kind": kind,
            "queue_role": role,
            "queue_number": qn,
            "tc": tc,
        }
        cq_record = (
            self._collect_mlx5e_cq(cq, owner) if cq is not None else None
        )

        txq = compat._safe_member(queue_obj, "txq")
        txq_state = (
            compat._safe_int(compat._safe_member(txq, "state"))
            if txq is not None
            else None
        )

        record = {
            "kind": kind,
            "role": role,
            "tc": tc,
            "owner": _owner_string(owner),
            "device": device.get("name"),
            "netdev": netdev_record.get("name"),
            "channel": channel_index,
            "address": formatting._hex(compat._addr(queue_obj)),
            "number": qn,
            "number_source": qn_source,
            **progress,
            "state": formatting._hex(state),
            "state_flags": _decode_state_bits(state, state_bits),
            "enabled": _bit_is_set(state, 0),
            "recovering": _bit_is_set(state, 1 if kind == "rq" else 2),
            "txq": formatting._hex(compat._addr(txq)),
            "txq_state": formatting._hex(txq_state),
            "txq_state_flags": _decode_state_bits(
                txq_state, defs._NETDEV_QUEUE_STATE_BITS
            ),
            "txq_stopped": bool(txq_state & 0x7)
            if txq_state is not None
            else None,
            "wq": self._collect_wq_summary(wq),
            "cq": cq_record,
        }
        self._record_queue_wq(record, wq)
        return record

    def _queue_wq_with_source(
        self, queue_obj: Object, kind: str
    ) -> Tuple[Optional[Object], Optional[str]]:
        direct = compat._safe_member(queue_obj, "wq")
        if kind not in ("rq", "xskrq", "ptp_rq"):
            return direct, None
        if direct is not None and compat._addr(direct) is not None:
            return direct, "rq.wq"

        # CTF and DWARF may expose both union arms. wq_type 1 selects cyclic WQ.
        cyclic_wq = ("rq.wqe.wq", ["wqe", "wq"])
        linked_wq = ("rq.mpwqe.wq", ["mpwqe", "wq"])
        wq_type = compat._safe_int(compat._safe_member(queue_obj, "wq_type"))
        paths = (
            (cyclic_wq, linked_wq) if wq_type == 1 else (linked_wq, cyclic_wq)
        )
        candidates = []
        selected = None
        for source, path in paths:
            candidate = compat._safe_member_path(queue_obj, path)
            if candidate is None:
                continue
            if direct is not None:
                return direct, source
            candidates.append((source, candidate))
            if selected is None:
                selected = candidate
            if dumps._ring_size(candidate) is not None:
                selected = candidate
                break
        if selected is None:
            return direct, None
        for source, candidate in candidates:
            if dumps._same_address(candidate, selected):
                return candidate, source
        return selected, candidates[0][0]

    def _record_queue_wq(
        self, record: Dict[str, Any], wq: Optional[Object]
    ) -> None:
        qn = compat._safe_int(record.get("number"))
        device = record.get("device")
        if qn is None or device is None:
            return
        selector = (
            "rqn" if record.get("kind") in ("rq", "xskrq", "ptp_rq") else "sqn"
        )
        owner = str(record.get("owner") or "")
        key = (str(device), selector, qn, owner)
        previous = self._mlx5e_queues.get(key)
        if wq is None and previous is not None:
            wq = previous.wq
        self._mlx5e_queues[key] = _RingEntry(record, wq)

    def _collect_wq_summary(self, wq: Optional[Object]) -> Dict[str, Any]:
        if wq is None:
            return {"status": "unavailable"}
        fbc = compat._safe_member(wq, "fbc")
        log_sz, log_sz_source = compat._first_int_path_with_source(
            wq,
            (
                ("wq.fbc.log_sz", ["fbc", "log_sz"]),
                ("wq.log_sz", ["log_sz"]),
            ),
        )
        log_stride, log_stride_source = compat._first_int_path_with_source(
            wq,
            (
                ("wq.fbc.log_stride", ["fbc", "log_stride"]),
                ("wq.log_stride", ["log_stride"]),
            ),
        )
        sz_m1, sz_m1_source = compat._first_int_path_with_source(
            wq,
            (
                ("wq.sz_m1", ["sz_m1"]),
                ("wq.fbc.sz_m1", ["fbc", "sz_m1"]),
            ),
        )
        size: Optional[int]
        size_source: Optional[str]
        if sz_m1 is not None:
            size = sz_m1 + 1
            size_source = sz_m1_source
        elif log_sz is not None:
            size = 1 << log_sz
            size_source = log_sz_source
        else:
            size, size_source = compat._first_int_path_with_source(
                wq,
                (
                    ("wq.wqe_cnt", ["wqe_cnt"]),
                    ("wq.nentries", ["nentries"]),
                    ("wq.num_entries", ["num_entries"]),
                ),
            )
        stride_bytes = (
            (1 << log_stride)
            if log_stride is not None and 0 <= log_stride < 32
            else None
        )
        stride_source = log_stride_source if stride_bytes is not None else None
        if stride_bytes is None:
            stride_bytes, stride_source = compat._first_int_path_with_source(
                wq,
                (
                    ("wq.stride", ["stride"]),
                    ("wq.stride_bytes", ["stride_bytes"]),
                ),
            )
        summary = {
            "address": formatting._hex(compat._addr(wq)),
            "size": size,
            "size_source": size_source,
            "sz_m1": sz_m1,
            "log_sz": log_sz,
            "log_stride": log_stride,
            "stride_bytes": stride_bytes,
            "stride_source": stride_source,
            "pc": compat._safe_int(compat._safe_member(wq, "pc")),
            "cc": compat._safe_int(compat._safe_member(wq, "cc")),
            "head": compat._safe_int(compat._safe_member(wq, "head")),
            "wqe_counter": compat._safe_int(
                compat._safe_member(wq, "wqe_ctr")
            ),
            "cur_size": compat._safe_int(compat._safe_member(wq, "cur_sz")),
            "db": formatting._hex(compat._addr(compat._safe_member(wq, "db"))),
            "fbc": formatting._hex(compat._addr(fbc)),
        }
        for key, value in (
            ("tail", compat._safe_int(compat._safe_member(wq, "tail"))),
            (
                "wqe_count",
                compat._safe_int(compat._safe_member(wq, "wqe_cnt")),
            ),
            (
                "cur_post",
                compat._safe_int(compat._safe_member(wq, "cur_post")),
            ),
            (
                "max_post",
                compat._safe_int(compat._safe_member(wq, "max_post")),
            ),
            (
                "last_poll",
                compat._safe_int(compat._safe_member(wq, "last_poll")),
            ),
            (
                "cur_edge",
                formatting._hex(
                    compat._addr(compat._safe_member(wq, "cur_edge"))
                ),
            ),
            ("offset", compat._safe_int(compat._safe_member(wq, "offset"))),
            (
                "wqe_shift",
                compat._safe_int(compat._safe_member(wq, "wqe_shift")),
            ),
        ):
            if value is not None:
                summary[key] = value
        return summary

    def _collect_mlx5e_cq(
        self, cq: Object, owner: Dict[str, Any]
    ) -> Dict[str, Any]:
        mcq, mcq_source = compat._first_member_path_with_source(
            cq, defs._MLX5E_CQ_CORE_PATHS
        )
        cqn = compat._safe_int(compat._safe_member(mcq, "cqn"))
        if cqn is None:
            cqn = compat._safe_int(compat._safe_member(cq, "cqn"))
        wq, wq_source = compat._first_member_path_with_source(
            cq, defs._MLX5E_CQ_WQ_PATHS
        )
        wq_summary = self._collect_wq_summary(wq)
        consumer_index, consumer_source, core_cons_index = _cq_consumer_index(
            "struct mlx5e_cq", wq_summary, mcq
        )
        arm_sn_raw = compat._safe_int(compat._safe_member(mcq, "arm_sn"))
        owner_name = _owner_string(owner)
        record = {
            "cqn": cqn,
            "address": formatting._hex(compat._addr(cq)),
            "address_struct": "struct mlx5e_cq",
            "core_cq": formatting._hex(compat._addr(mcq)),
            "core_cq_struct": "struct mlx5_core_cq",
            "core_cq_source": mcq_source,
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
            "wq_source": wq_source,
            "arm_sn": _cq_arm_sn(arm_sn_raw),
            "arm_sn_raw": arm_sn_raw,
            "vector": compat._first_int_path(
                mcq, (["vector"], ["comp", "vector"])
            ),
            "irqn": compat._safe_int(compat._safe_member(mcq, "irqn")),
            "event_ctr": compat._safe_int(
                compat._safe_member(cq, "event_ctr")
            ),
            "size": wq_summary.get("size"),
            "stride_bytes": wq_summary.get("stride_bytes"),
        }
        key = _record_key(owner.get("device"), cqn)
        if key is not None:
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
        device: Dict[str, Any],
        queue_cqns: Set[int],
    ) -> Tuple[Optional[int], Optional[int]]:
        eq_table = compat._safe_member_path(
            device.get("_mdev_obj"), ["priv", "eq_table"]
        )
        if eq_table is None or compat._is_null(eq_table):
            return None, None
        eqs: Dict[Tuple[str, int], Object] = {}
        for eq, _role, _meta, _vector, _source in self._iter_eq_candidates(
            device, summary=True
        ):
            if eq is None or compat._is_null(eq):
                continue
            core = compat._safe_member(eq, "core")
            core_or_eq = core if core is not None else eq
            eqn = compat._first_int_path(eq, (["eqn"], ["core", "eqn"]))
            address = compat._addr(core_or_eq)
            if eqn is not None:
                key = ("eqn", eqn)
            elif address is not None:
                key = ("addr", address)
            else:
                continue
            eqs.setdefault(key, core_or_eq)

        cqns = set(queue_cqns)
        cq_table_seen = False
        for eq in eqs.values():
            tree = compat._safe_member_path(eq, ["cq_table", "tree"])
            if tree is None:
                continue
            cq_table_seen = True
            for cq_key, cq in self._iter_bounded_table(
                tree,
                ["eq", "cq_table", "tree"],
                f"{device.get('name')}: summary CQ count",
            ):
                cqn = compat._safe_int(cq_key)
                if cqn is None:
                    cqn = compat._safe_int(compat._safe_member(cq, "cqn"))
                if cqn is not None:
                    cqns.add(cqn)
        return len(eqs), (len(cqns) if cq_table_seen or cqns else None)

    def _iter_eq_candidates(
        self, device: Dict[str, Any], summary: bool = False
    ) -> Iterator[Tuple[Object, str, Optional[Object], Optional[int], str]]:
        eq_table = compat._safe_member_path(
            device.get("_mdev_obj"), ["priv", "eq_table"]
        )
        if eq_table is None or compat._is_null(eq_table):
            return
        name = device.get("name")
        for field, role in (
            ("cmd_eq", "cmd"),
            ("async_eq", "async"),
            ("pages_eq", "pages"),
            ("pcie_core_clock_eq", "pcie_core_clock"),
            ("general_event_eq", "general_event"),
        ):
            eq = compat._safe_member(eq_table, field)
            if eq is not None and not compat._is_null(eq):
                yield eq, role, None, None, "direct"

        comp_eqs = compat._safe_member(eq_table, "comp_eqs")
        xarray_yielded = False
        xarray_error = None
        if comp_eqs is not None and compat.xa_for_each is not None:
            try:
                scope = (
                    f"{name} summary comp_eq count"
                    if summary
                    else f"{name} comp_eqs xarray"
                )
                for vector, eq_comp in self._iter_limited(
                    compat.xa_for_each(comp_eqs), scope
                ):
                    xarray_yielded = True
                    eq_comp = self._coerce_eq_comp(eq_comp)
                    if eq_comp is None:
                        continue
                    core = compat._safe_member(eq_comp, "core")
                    yield (
                        core if core is not None else eq_comp,
                        "completion",
                        eq_comp,
                        compat._safe_int(vector),
                        "xarray",
                    )
            except Exception as err:
                xarray_yielded = False
                xarray_error = err

        comp_count, _source = compat._first_int_path_with_source(
            eq_table, defs._MLX5_EQ_TABLE_COMP_ARRAY_COUNT_PATHS
        )
        array_yielded = False
        if (
            (not summary or not xarray_yielded)
            and comp_eqs is not None
            and comp_count is not None
        ):
            scope = (
                f"{name} summary comp_eq array count"
                if summary
                else f"{name} comp_eqs array"
            )
            for vector in range(
                self._walk_count(comp_count, scope, hard_limit=defs.MAX_EQS)
            ):
                eq_comp = self._coerce_eq_comp(
                    compat._safe_index(comp_eqs, vector)
                )
                if eq_comp is None:
                    continue
                array_yielded = True
                core = compat._safe_member(eq_comp, "core")
                yield core if core is not None else eq_comp, "completion", eq_comp, vector, "array"
        if not summary and xarray_error is not None and not array_yielded:
            self._warn(
                f"failed while walking {name} comp_eqs xarray: {xarray_error}"
            )

        if summary and xarray_yielded:
            return
        for field, type_name, member in (
            ("comp_eqs_list", "struct mlx5_eq_comp", "list"),
            ("eqs_list", "struct mlx5_eq", "list"),
        ):
            head = compat._safe_member(eq_table, field)
            if head is None or compat.list_for_each_entry is None:
                continue
            what = f"walking {name} {field}" + (
                " for summary counts" if summary else ""
            )
            scope = (
                f"{name} summary {field} count"
                if summary
                else f"{name} {field}"
            )
            for obj in self._iter_limited(
                compat._safe_iter(
                    lambda h=head, t=type_name, m=member: compat.list_for_each_entry(  # type: ignore[misc]
                        t, h.address_of_(), m
                    ),
                    self._warn,
                    what,
                ),
                scope,
            ):
                core = compat._safe_member(obj, "core")
                yield core if core is not None else obj, "completion", obj, None, "list"

    def _collect_eqs_from_device(self, device: Dict[str, Any]) -> None:
        for eq, role, meta, vector, source in self._iter_eq_candidates(device):
            record = self._record_eq(eq, device, role, eq_meta=meta)
            if source == "xarray":
                record["vector"] = vector
                record["comp_eq"] = formatting._hex(compat._addr(meta))
            elif source == "array" and record.get("vector") is None:
                record["vector"] = vector

    def _coerce_eq_comp(self, obj: Object) -> Optional[Object]:
        if obj is None or compat._is_null(obj):
            return None
        if (
            compat._safe_member(obj, "core") is not None
            or compat._safe_member(obj, "eqn") is not None
        ):
            return obj
        addr = compat._addr(obj)
        if addr is None:
            return None
        for type_name in ("struct mlx5_eq_comp *", "struct mlx5_eq *"):
            try:
                candidate = cast(type_name, obj)
            except Exception:
                candidate = compat._safe_pointer(self.prog, type_name, addr)
            if candidate is not None and (
                compat._safe_member(candidate, "core") is not None
                or compat._safe_member(candidate, "eqn") is not None
            ):
                return candidate
        return None

    def _record_eq(
        self,
        eq: Object,
        device: Dict[str, Any],
        role: str,
        eq_meta: Optional[Object] = None,
    ) -> Dict[str, Any]:
        core = compat._safe_member(eq, "core")
        core_or_eq = core if core is not None else eq
        eq_fields = eq_meta if eq_meta is not None else eq
        eqn = compat._first_int_path(eq, (["eqn"], ["core", "eqn"]))

        wq = compat._first_member_path(
            eq, (["wq"], ["core", "wq"], ["buf"], ["frag_buf"], ["core"])
        )
        if wq is None and (
            compat._safe_member(core_or_eq, "fbc") is not None
            or compat._safe_member(core_or_eq, "frag_buf") is not None
        ):
            wq = core_or_eq

        size = compat._first_int_path(
            eq, (["nent"], ["core", "nent"], ["eqe_cnt"])
        )
        if size is None:
            sz_m1 = compat._first_int_path(
                core_or_eq, (["fbc", "sz_m1"], ["sz_m1"])
            )
            if sz_m1 is not None:
                size = sz_m1 + 1

        eqe_size = compat._first_int_path(
            eq, (["eqe_size"], ["core", "eqe_size"])
        )
        if eqe_size is None:
            eqe_size = compat._sizeof_type(self.prog, "struct mlx5_eqe")

        irqn = compat._first_int_path(
            eq, (["irqn"], ["core", "irqn"], ["irq", "irqn"])
        )
        record = {
            "eqn": eqn,
            "address": formatting._hex(compat._addr(eq)),
            "address_struct": compat._struct_type_name(eq),
            "core_eq": formatting._hex(compat._addr(core_or_eq)),
            "core_eq_struct": compat._struct_type_name(core_or_eq),
            "device": device.get("name"),
            "role": role,
            "irqn": irqn,
            "irq_cpu": _irq_affinity_cpus(self.prog, irqn),
            "vector": compat._first_int_path(
                eq, (["vecidx"], ["vector"], ["comp_vec"], ["core", "vecidx"])
            ),
            "consumer_index": compat._first_int_path(
                eq, (["cons_index"], ["core", "cons_index"])
            ),
            "size": size,
            "cq_count": compat._first_int_path(
                eq_fields, (["cq_count"], ["core", "cq_count"])
            ),
            "eqe_size": eqe_size,
            "mask": formatting._hex(
                compat._first_int_path(eq, (["mask"], ["core", "mask"]))
            ),
        }

        key = _record_key(device.get("name"), eqn)
        if key is None:
            return record
        entry = self._eqs.get(key)
        if entry is None:
            self._eqs[key] = _EqEntry(record, eq, wq)
            return record

        existing = entry.record
        if role and role not in str(existing.get("role", "")):
            existing["role"] = str(existing.get("role")) + "," + role
        _merge_missing_fields(existing, record)
        return existing

    def _collect_cqs_from_eq_tables(self, device: Dict[str, Any]) -> None:
        """Collect CQs registered in each EQ's CQ table.

        Channel walks find mlx5e CQs. RDMA and internal CQs may exist only in
        the EQ-local cq_table.
        """

        for (dev_name, eqn), entry in self._eqs.items():
            if dev_name != device.get("name"):
                continue
            eq = entry.eq
            core = compat._safe_member(eq, "core")
            core_or_eq = core if core is not None else eq
            tree = compat._safe_member_path(core_or_eq, ["cq_table", "tree"])
            if tree is None:
                continue
            role = entry.record.get("role") or "eq"
            owner = f"eq_cq_table:{role}:eqn{eqn}"
            for key, obj in self._iter_bounded_table(
                tree,
                ["eq", "cq_table", "tree"],
                f"{device.get('name')}: EQ {eqn} CQ table walk",
            ):
                core_cq = compat._safe_pointer(
                    self.prog, "struct mlx5_core_cq *", compat._addr(obj)
                )
                if core_cq is None:
                    continue
                self._record_core_cq(
                    core_cq, device, owner=owner, table_key=key
                )

    def _record_core_cq(
        self,
        core_cq: Object,
        device: Dict[str, Any],
        owner: str,
        table_key: Optional[int] = None,
    ) -> Dict[str, Any]:
        cqn = compat._safe_int(compat._safe_member(core_cq, "cqn"))
        if cqn is None:
            cqn = table_key
        mlx5e_cq = self._mlx5e_cq_from_core_cq(core_cq, device)
        ibcq = (
            None
            if mlx5e_cq is not None
            else self._mlx5_ib_cq_from_core_cq(core_cq)
        )
        aso_cq = (
            None
            if ibcq is not None or mlx5e_cq is not None
            else self._mlx5_aso_cq_from_core_cq(core_cq, device)
        )
        address_obj, address_struct = core_cq, "struct mlx5_core_cq"
        wq = netdev = event_ctr = owner_hint = None
        queue_kind: Optional[str] = "core_cq"
        queue_role: Optional[str] = "core"
        queue_number = cqn
        if ibcq is not None:
            address_obj, address_struct = ibcq, "struct mlx5_ib_cq"
            wq = compat._first_member_path(
                ibcq,
                (
                    ["buf", "fbc"],
                    ["buf", "frag_buf"],
                    ["resize_buf", "fbc"],
                    ["resize_buf", "frag_buf"],
                ),
            )
            queue_kind, queue_role = "rdma_cq", "rdma"
        elif mlx5e_cq is not None:
            address_obj, address_struct = mlx5e_cq, "struct mlx5e_cq"
            wq, _ = compat._first_member_path_with_source(
                mlx5e_cq, defs._MLX5E_CQ_WQ_PATHS
            )
            mlx5e_owner = self._mlx5e_core_cq_owner(mlx5e_cq, core_cq, device)
            netdev = mlx5e_owner.get("netdev")
            queue_kind = mlx5e_owner.get("queue_kind")
            queue_role = mlx5e_owner.get("queue_role")
            queue_number = mlx5e_owner.get("queue_number")
            event_ctr = compat._safe_int(
                compat._safe_member(mlx5e_cq, "event_ctr")
            )
            owner_hint = _owner_string(mlx5e_owner)
        elif aso_cq is not None:
            address_obj, address_struct = aso_cq, "struct mlx5_aso_cq"
            wq = compat._safe_member(aso_cq, "wq")
            queue_kind, queue_role = "aso_cq", "internal"
            owner_hint = f"aso_cq{cqn}" if cqn is not None else "aso_cq"
        owners = (
            [owner_hint, owner]
            if owner_hint and owner_hint != owner
            else [owner]
        )
        wq_summary = self._collect_wq_summary(wq)
        consumer_index, consumer_source, core_cons_index = _cq_consumer_index(
            address_struct, wq_summary, core_cq
        )
        arm_sn_raw = compat._safe_int(compat._safe_member(core_cq, "arm_sn"))
        record = {
            "cqn": cqn,
            "address": formatting._hex(compat._addr(address_obj)),
            "address_struct": address_struct,
            "core_cq": formatting._hex(compat._addr(core_cq)),
            "core_cq_struct": "struct mlx5_core_cq",
            "owner": ";".join(str(o) for o in owners if o),
            "owners": owners,
            "device": device.get("name"),
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
            "vector": compat._safe_int(compat._safe_member(core_cq, "vector")),
            "irqn": compat._safe_int(compat._safe_member(core_cq, "irqn")),
            "event_ctr": event_ctr,
            "size": wq_summary.get("size"),
            "stride_bytes": wq_summary.get("stride_bytes")
            or compat._safe_int(compat._safe_member(core_cq, "cqe_sz")),
        }

        key = _record_key(device.get("name"), cqn)
        if key is None:
            return record
        entry = self._cqs.get(key)
        if entry is None:
            self._cqs[key] = _RingEntry(record, wq)
            return record

        existing = entry.record
        owners = existing.setdefault("owners", [existing.get("owner")])
        if owner not in owners:
            owners.append(owner)
        existing["owner"] = ";".join(str(item) for item in owners if item)
        _merge_missing_fields(existing, record)
        if wq is not None and entry.wq is None:
            self._cqs[key] = _RingEntry(existing, wq)
        return existing

    def _mlx5e_cq_from_core_cq(
        self, core_cq: Object, device: Dict[str, Any]
    ) -> Optional[Object]:
        comp = collect_device._symbol_for_addr(
            self.prog, compat._addr(compat._safe_member(core_cq, "comp"))
        )
        event = collect_device._symbol_for_addr(
            self.prog, compat._addr(compat._safe_member(core_cq, "event"))
        )
        if (
            (comp is not None or event is not None)
            and comp != "mlx5e_completion_event"
            and event != "mlx5e_cq_error_event"
        ):
            return None
        cq = compat._safe_container_of(core_cq, "struct mlx5e_cq", "mcq")
        if cq is None or compat._is_null(cq):
            return None
        cq_core, _ = compat._first_member_path_with_source(
            cq, defs._MLX5E_CQ_CORE_PATHS
        )
        if not dumps._same_address(cq_core, core_cq):
            return None
        mdev = compat._safe_member(cq, "mdev")
        if not dumps._same_address(mdev, device.get("_mdev_obj")):
            return None
        if not dumps._plausible_cq_wq(compat._safe_member(cq, "wq")):
            return None
        return cq

    def _mlx5e_core_cq_owner(
        self, cq: Object, core_cq: Object, device: Dict[str, Any]
    ) -> Dict[str, Any]:
        cqn = compat._safe_int(compat._safe_member(core_cq, "cqn"))
        cq_netdev = compat._safe_member(cq, "netdev")
        netdev_name = None
        for netdev in device.get("netdevs", []):
            priv = netdev.get("_priv_obj")
            if dumps._same_address(
                cq, compat._safe_member_path(priv, ["drop_rq", "cq"])
            ):
                return {
                    "device": device.get("name"),
                    "netdev": netdev.get("name"),
                    "queue_kind": "drop_rq_cq",
                    "queue_role": "drop",
                    "queue_number": cqn,
                }
            if netdev_name is None and dumps._same_address(
                cq_netdev, netdev.get("_netdev_obj")
            ):
                netdev_name = netdev.get("name")
        if (
            netdev_name is None
            and cq_netdev is not None
            and not compat._is_null(cq_netdev)
        ):
            netdev_name = collect_device._netdev_name(cq_netdev)

        return {
            "device": device.get("name"),
            "netdev": netdev_name,
            "queue_kind": "mlx5e_cq",
            "queue_role": "mlx5e",
            "queue_number": cqn,
        }

    def _mlx5_aso_cq_from_core_cq(
        self, core_cq: Object, device: Dict[str, Any]
    ) -> Optional[Object]:
        cq = compat._safe_container_of(core_cq, "struct mlx5_aso_cq", "mcq")
        if cq is None or compat._is_null(cq):
            return None
        if not dumps._same_address(compat._safe_member(cq, "mcq"), core_cq):
            return None
        if not dumps._same_address(
            compat._safe_member(cq, "mdev"), device.get("_mdev_obj")
        ):
            return None
        wq = compat._safe_member(cq, "wq")
        if not dumps._plausible_cq_wq(wq):
            return None

        size = dumps._ring_size(wq, defs.DEFAULT_DESCRIPTOR_ENTRY_BYTES)
        stride = (
            dumps._ring_stride_bytes(wq) or defs.DEFAULT_DESCRIPTOR_ENTRY_BYTES
        )
        buf_size = compat._safe_int(
            compat._safe_member_path(cq, ["wq_ctrl", "buf", "size"])
        )
        if (
            buf_size is not None
            and size is not None
            and buf_size < size * stride
        ):
            return None
        return cq

    def _mlx5_ib_cq_from_core_cq(self, core_cq: Object) -> Optional[Object]:
        if compat._addr(core_cq) is None:
            return None
        cq = compat._safe_container_of(core_cq, "struct mlx5_ib_cq", "mcq")
        if cq is None or compat._is_null(cq):
            return None
        if (
            compat._safe_member(cq, "ibcq") is None
            or compat._safe_member(cq, "buf") is None
        ):
            return None
        cqe_size = compat._safe_int(compat._safe_member(cq, "cqe_size"))
        buf_cqe_size = compat._safe_int(
            compat._safe_member_path(cq, ["buf", "cqe_size"])
        )
        nent = compat._safe_int(compat._safe_member_path(cq, ["buf", "nent"]))
        log_sz = compat._safe_int(
            compat._safe_member_path(cq, ["buf", "fbc", "log_sz"])
        )
        sz_m1 = compat._safe_int(
            compat._safe_member_path(cq, ["buf", "fbc", "sz_m1"])
        )
        plausible_cqe_size = cqe_size in (64, 128) or buf_cqe_size in (64, 128)
        plausible_size = (
            (nent is None or 0 < nent <= defs.MAX_PLAUSIBLE_RING_ENTRIES)
            and (log_sz is None or 0 <= log_sz < 32)
            and (sz_m1 is None or 0 <= sz_m1 < defs.MAX_PLAUSIBLE_RING_ENTRIES)
        )
        return cq if plausible_cqe_size and plausible_size else None

    def _correlate_cqs_to_eqs(self) -> None:
        eq_by_device_vector: Dict[Tuple[str, int], Dict[str, Any]] = {}
        eq_by_device_irqn: Dict[Tuple[str, int], Dict[str, Any]] = {}

        for eq_record in (entry.record for entry in self._eqs.values()):
            device = eq_record.get("device")
            vector = eq_record.get("vector")
            irqn = eq_record.get("irqn")
            if device is not None and vector is not None:
                eq_by_device_vector[(str(device), int(vector))] = eq_record
            if device is not None and irqn is not None:
                eq_by_device_irqn[(str(device), int(irqn))] = eq_record

        for cq in (entry.record for entry in self._cqs.values()):
            device = cq.get("device")
            if device is None:
                continue
            vector = cq.get("vector")
            irqn = cq.get("irqn")
            eq: Optional[Dict[str, Any]] = (
                eq_by_device_vector.get((str(device), int(vector)))
                if vector is not None
                else None
            )
            if irqn is not None:
                eq_by_irq = eq_by_device_irqn.get((str(device), int(irqn)))
                if eq_by_irq is not None and (
                    eq is None or eq.get("irqn") != irqn
                ):
                    eq = eq_by_irq
            for cq_field, eq_field in (
                ("eqn", "eqn"),
                ("eq_role", "role"),
                ("eq_irqn", "irqn"),
                ("eq_irq_cpu", "irq_cpu"),
                ("eq_vector", "vector"),
                ("eq_address", "address"),
            ):
                cq[cq_field] = eq.get(eq_field) if eq is not None else None

    def _annotate_channels_from_cqs(
        self, devices: List[Dict[str, Any]]
    ) -> None:
        for device in devices:
            for netdev in device.get("netdevs", []):
                for ch in netdev.get("channels", []):
                    cqs: List[Dict[str, Any]] = []
                    for queue in selection._channel_queues(ch):
                        cq = queue.get("cq")
                        if isinstance(cq, dict) and cq.get("cqn") not in (
                            None,
                            0,
                        ):
                            cqs.append(cq)
                    if not cqs:
                        continue
                    vector = _shared_known_value(
                        selection._first_present(
                            cq.get("eq_vector"), cq.get("vector")
                        )
                        for cq in cqs
                    )
                    irqn = _shared_known_value(
                        selection._first_present(
                            cq.get("eq_irqn"), cq.get("irqn")
                        )
                        for cq in cqs
                    )
                    eqn = _shared_known_value(cq.get("eqn") for cq in cqs)
                    for field, value in (
                        ("vector", vector),
                        ("irqn", irqn),
                        ("eqn", eqn),
                    ):
                        if ch.get(field) is None and value is not None:
                            ch[field] = value
                    if ch.get("irq_desc") is None and irqn is not None:
                        ch["irq_desc"] = formatting._hex(
                            compat._addr(_irq_desc(self.prog, irqn))
                        )

    # RDMA queue pairs

    def _count_summary_qps(self, device: Dict[str, Any]) -> Optional[int]:
        if device.get("_mdev_obj") is None:
            return None
        keys = set()
        for qp, _owner, table_qpn in self._iter_qps_from_device(
            device, summary=True
        ):
            key = _qp_identity(qp, device.get("name"), table_qpn).key
            if key is not None:
                keys.add(key)
        return len(keys)

    def _iter_core_qp_tables(
        self, mdev: Object
    ) -> Iterator[Tuple[Sequence[str], Object]]:
        for path in defs._MLX5_CORE_QP_TABLE_PATHS:
            root = compat._safe_member_path(mdev, path)
            if root is not None:
                yield path, root

    def _mlx5_ib_qp_tree(self, ibdev: Object) -> Optional[Tuple[str, Object]]:
        for table_name in ("qp_table", "qb_table"):
            root = compat._safe_member_path(ibdev, [table_name, "tree"])
            if root is not None:
                return table_name, root
        return None

    def _iter_mlx5_ib_qp_list(
        self, qp_head: Object, device_name: str, *, summary: bool
    ) -> Iterator[Object]:
        purpose = " for summary counts" if summary else ""
        qps = compat._safe_iter(
            lambda: compat.list_for_each_entry(
                "struct mlx5_ib_qp", qp_head.address_of_(), "qps_list"
            ),
            self._warn,
            f"walking {device_name} mlx5_ib qp_list{purpose}",
        )
        truncation_scope = (
            f"{device_name}: summary mlx5_ib qp_list count"
            if summary
            else f"{device_name}: mlx5_ib qp_list walk"
        )
        yield from self._iter_walk_limited(qps, truncation_scope)

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

    def _rebuild_qp_indexes(self) -> None:
        self._qp_keys_by_send_cqn.clear()
        self._qp_keys_by_alias.clear()

        def add(
            index: Dict[Tuple[str, int], List[_QpKey]],
            qp_key: _QpKey,
            value: Any,
        ) -> None:
            number = compat._safe_int(value)
            if number is None:
                return
            index.setdefault((qp_key.device, number), []).append(qp_key)

        for qp_key, entry in self._qps.items():
            record = entry.record
            add(self._qp_keys_by_send_cqn, qp_key, record.get("send_cqn"))
            for alias in record.get("qpn_aliases") or ():
                add(self._qp_keys_by_alias, qp_key, alias)

    def _iter_qps_from_device(
        self, device: Dict[str, Any], *, summary: bool
    ) -> Iterator[Tuple[Object, str, Optional[int]]]:
        """Yield QPs from every source used by summary and full reports."""

        mdev = device.get("_mdev_obj")
        mdev_addr = compat._addr(mdev)
        device_name = str(device.get("name"))
        source_found = False
        ibdevs = (
            self._iter_mlx5_ib_devices(mdev_addr)
            if mdev_addr is not None
            else ()
        )
        for ibdev in ibdevs:
            qp_head = compat._safe_member(ibdev, "qp_list")
            if qp_head is not None and compat.list_for_each_entry is not None:
                source_found = True
                for qp in self._iter_mlx5_ib_qp_list(
                    qp_head, device_name, summary=summary
                ):
                    yield qp, "mlx5_ib_qp_list", None

            qp_tree = self._mlx5_ib_qp_tree(ibdev)
            if qp_tree is None:
                continue
            source_found = True
            table_name, root = qp_tree
            ib_path = ["mlx5_ib", table_name, "tree"]
            scope = f"{device_name}: mlx5_ib {table_name} walk"
            for table_qpn, obj in self._iter_bounded_table(
                root, ib_path, scope
            ):
                qp = self._qp_candidate_from_table_entry(obj)
                if qp is not None:
                    yield qp, f"mlx5_ib_{table_name}", table_qpn

        if mdev is not None:
            for path, root in self._iter_core_qp_tables(mdev):
                source_found = True
                scope = f"{device_name}: core QP table {'.'.join(path)} walk"
                for table_qpn, obj in self._iter_bounded_table(
                    root, path, scope
                ):
                    qp = self._qp_candidate_from_table_entry(obj)
                    if qp is not None:
                        yield qp, "core_table", table_qpn

        if (
            not source_found
            and not summary
            and (self.args.qps or self.args.dump_wqe)
        ):
            self._warn(f"{device_name}: no readable mlx5 QP table was found")

    def _record_selected_qp(
        self,
        qp: Object,
        device: Dict[str, Any],
        owner: str,
        table_key: Optional[int] = None,
    ) -> None:
        identity = _qp_identity(qp, device.get("name"), table_key)
        record = self._record_qp(qp, device, owner, table_key, identity)
        if self.args.qpn is not None and not selection._qp_record_matches_qpn(
            record, self.args.qpn
        ):
            if identity.key is not None:
                self._qps.pop(identity.key, None)

    def _iter_bounded_table(
        self,
        root: Object,
        path: Sequence[str],
        truncation_scope: str,
    ) -> Iterator[Tuple[Optional[int], Object]]:
        return self._iter_walk_limited(
            self._walk_index_table(root, path), truncation_scope
        )

    def _iter_walk_limited(
        self, iterable: Iterable[Any], truncation_scope: str
    ) -> Iterator[Any]:
        for index, item in enumerate(iterable):
            if (
                self.args.walk_limit is not None
                and index >= self.args.walk_limit
            ):
                self._warn_truncated(
                    f"{truncation_scope} truncated at --walk-limit={self.args.walk_limit}"
                )
                break
            yield item

    def _walk_index_table(
        self,
        root: Object,
        path: Sequence[str],
        depth: int = 0,
        seen: Optional[set] = None,
    ) -> Iterator[Tuple[Optional[int], Object]]:
        """Walk an mlx5 table stored as an xarray, IDR, or radix tree."""

        if seen is None:
            seen = set()
        if depth > 8:
            return
        root_addr = compat._addr(root)
        if root_addr is not None:
            marker = (
                root.type_.type_name() if hasattr(root, "type_") else "object",
                root_addr,
            )
            if marker in seen:
                return
            seen.add(marker)

        helper_failures = []
        helper_success = False
        for helper_name, helper in (
            ("xarray", compat.xa_for_each),
            ("idr", compat.idr_for_each),
            ("radix_tree", compat.radix_tree_for_each),
        ):
            if helper is None:
                continue
            try:
                yielded = False
                for index, entry in helper(root):
                    yielded = True
                    yield compat._safe_int(index), entry
                helper_success = True
                if yielded:
                    return
            except Exception as err:
                helper_failures.append(
                    f"{helper_name}: {type(err).__name__}: {err}"
                )

        child_seen = False
        for member in ("xa", "xarray", "idr", "tree"):
            child = compat._safe_member(root, member)
            if child is None:
                continue
            if child is root:
                continue
            child_seen = True
            for item in self._walk_index_table(
                child, [*path, member], depth + 1, seen
            ):
                yield item
        if not child_seen and helper_failures and not helper_success:
            self._warn(
                f"could not walk {'.'.join(str(p) for p in path)} with xarray/IDR/radix helpers: "
                + "; ".join(helper_failures[:3])
            )

    def _qp_candidate_from_table_entry(self, obj: Object) -> Optional[Object]:
        if obj is None or compat._is_null(obj):
            return None

        if compat._object_type_name(obj) == "struct mlx5_ib_qp *":
            return obj

        qp_from_core = self._mlx5_ib_qp_from_core_qp(obj)
        if qp_from_core is not None:
            return qp_from_core

        for target_type in (
            "struct mlx5_ib_qp *",
            "struct mlx5_core_qp *",
            "struct mlx5_qp *",
        ):
            try:
                qp = cast(target_type, obj)
                if compat._addr(qp) is not None:
                    if target_type == "struct mlx5_core_qp *":
                        qp_from_core = self._mlx5_ib_qp_from_core_qp(qp)
                        if qp_from_core is not None:
                            return qp_from_core
                    return qp
            except Exception:
                continue
        return obj

    def _mlx5_ib_qp_from_core_qp(self, obj: Object) -> Optional[Object]:
        """Find mlx5_ib_qp when a table points to its embedded core QP.

        UEK QP tables are keyed by hardware QPN and may point to
        mlx5_ib_qp_base.mqp. container_mibqp leads to the outer mlx5_ib_qp.
        """

        addr = compat._addr(obj)
        if addr is None:
            return None
        core = compat._safe_pointer(self.prog, "struct mlx5_core_qp *", addr)
        base = compat._safe_container_of(core, "struct mlx5_ib_qp_base", "mqp")
        qp = compat._safe_member(base, "container_mibqp")
        return (
            qp
            if _plausible_mlx5_ib_qp(qp)
            else self._mlx5_ib_qp_from_base_fallback(base)
        )

    def _mlx5_ib_qp_from_base_fallback(
        self, base: Optional[Object]
    ) -> Optional[Object]:
        if base is None or compat._is_null(base):
            return None
        for type_name, member in (
            ("struct mlx5_ib_qp_trans", "base"),
            ("struct mlx5_ib_sq", "base"),
            ("struct mlx5_ib_rq", "base"),
        ):
            candidate = compat._safe_container_of(base, type_name, member)
            if candidate is None or compat._is_null(candidate):
                continue
            for outer_type, outer_member in (
                ("struct mlx5_ib_qp", "trans_qp"),
                ("struct mlx5_ib_raw_packet_qp", "sq"),
                ("struct mlx5_ib_raw_packet_qp", "rq"),
            ):
                qp = compat._safe_container_of(
                    candidate, outer_type, outer_member
                )
                if _plausible_mlx5_ib_qp(qp):
                    return qp
        return None

    def _record_qp(
        self,
        qp: Object,
        device: Dict[str, Any],
        owner: str,
        table_key: Optional[int] = None,
        identity: Optional[_QpIdentity] = None,
    ) -> Dict[str, Any]:
        identity = identity or _qp_identity(qp, device.get("name"), table_key)
        qpn = identity.qpn
        ib_qpn = identity.ib_qpn
        hw_qpn = identity.hw_qpn
        send_cq = compat._first_member_path(
            qp,
            (
                ["send_cq"],
                ["scq"],
                ["ibqp", "send_cq"],
                ["sq", "cq"],
                ["mqp", "send_cq"],
            ),
        )
        recv_cq = compat._first_member_path(
            qp,
            (
                ["recv_cq"],
                ["rcq"],
                ["ibqp", "recv_cq"],
                ["rq", "cq"],
                ["mqp", "recv_cq"],
            ),
        )
        sq_wq = compat._first_member_path(
            qp,
            (
                ["sq", "wq"],
                ["sq", "base", "wq"],
                ["sq"],
                ["raw_packet_qp", "sq", "sq"],
            ),
        )
        rq_wq = compat._first_member_path(
            qp,
            (
                ["rq", "wq"],
                ["rq", "base", "wq"],
                ["rq"],
                ["raw_packet_qp", "rq", "rq"],
            ),
        )
        qp_type = _qp_type(qp)
        qp_state = compat._first_int_path(
            qp, (["state"], ["ibqp", "state"], ["mqp", "state"])
        )
        sq_pc, sq_cc, sq_pc_source, sq_cc_source = _qp_queue_progress(qp, "sq")
        rq_pc, rq_cc, rq_pc_source, rq_cc_source = _qp_queue_progress(qp, "rq")
        creator = _qp_creator(qp)
        record = {
            "qpn": qpn,
            "ib_qpn": ib_qpn,
            "hw_qpn": hw_qpn,
            "table_qpn": table_key,
            "qpn_aliases": list(identity.aliases),
            "address": formatting._hex(compat._addr(qp)),
            "address_struct": compat._struct_type_name(qp),
            "device": device.get("name"),
            "owner": owner,
            "owners": [owner],
            "creator": creator.get("display"),
            "creator_type": creator.get("type"),
            "creator_name": creator.get("name"),
            "creator_pid": creator.get("pid"),
            "creator_source": creator.get("source"),
            "type": qp_type,
            "type_display": decode._enum_table_label(
                qp_type, defs._IB_QP_TYPE
            ),
            "state": qp_state,
            "state_display": decode._enum_table_label(
                qp_state, defs._IB_QP_STATE
            ),
            "flags": formatting._hex(
                compat._safe_int(compat._safe_member(qp, "flags"))
            ),
            "has_rq": compat._safe_int(compat._safe_member(qp, "has_rq")),
            "is_rss": compat._safe_int(compat._safe_member(qp, "is_rss")),
            "max_inline_data": compat._safe_int(
                compat._safe_member(qp, "max_inline_data")
            ),
            "db": formatting._hex(compat._addr(compat._safe_member(qp, "db"))),
            "buf": formatting._hex(
                compat._addr(compat._safe_member(qp, "buf"))
            ),
            "send_cq": formatting._hex(compat._addr(send_cq)),
            "recv_cq": formatting._hex(compat._addr(recv_cq)),
            "send_cqn": _cq_number_from_cq(send_cq),
            "recv_cqn": _cq_number_from_cq(recv_cq),
            "sq": self._collect_wq_summary(sq_wq),
            "rq": self._collect_wq_summary(rq_wq),
            "sq_pc": sq_pc,
            "sq_cc": sq_cc,
            "rq_pc": rq_pc,
            "rq_cc": rq_cc,
            "sq_pc_source": sq_pc_source,
            "sq_cc_source": sq_cc_source,
            "rq_pc_source": rq_pc_source,
            "rq_cc_source": rq_cc_source,
        }
        key = identity.key
        if key is not None:
            entry = self._qps.get(key)
            if entry is not None:
                existing = entry.record
                owners = existing.setdefault("owners", [existing.get("owner")])
                if owner not in owners:
                    owners.append(owner)
                existing["owner"] = ",".join(str(o) for o in owners if o)
                existing_aliases: Any = existing.get("qpn_aliases")
                record_aliases: Any = record.get("qpn_aliases")
                existing["qpn_aliases"] = selection._qp_aliases(
                    *(
                        list(existing_aliases or [])
                        + list(record_aliases or [])
                    )
                )
                _merge_missing_fields(existing, record)
                record = existing
            else:
                entry = _QpEntry(record, None, None, None)

            dump_wq, stored_sq_wq, stored_rq_wq = (
                entry.dump_wq,
                entry.sq_wq,
                entry.rq_wq,
            )
            if sq_wq is not None:
                dump_wq = stored_sq_wq = sq_wq
            elif rq_wq is not None:
                dump_wq = rq_wq
            if rq_wq is not None:
                stored_rq_wq = rq_wq
            self._qps[key] = _QpEntry(
                record, dump_wq, stored_sq_wq, stored_rq_wq
            )
        return record

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
                dump_reports.append(
                    self._dump_cqe(self.args.cqn, self.args.maxcqe)
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
                dump_reports.append(
                    self._dump_eqe(self.args.eqn, self.args.maxeqe)
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
                dump_reports.append(
                    self._dump_wqe(self.args.qpn, self.args.maxwqe)
                )
            if self.args.sqn is not None:
                dump_reports.append(
                    self._dump_queue_wqe(
                        "sqn", self.args.sqn, self.args.maxwqe
                    )
                )
            if self.args.rqn is not None:
                dump_reports.append(
                    self._dump_queue_wqe(
                        "rqn", self.args.rqn, self.args.maxwqe
                    )
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
            "aso_cq": 6,
            "drop_rq_cq": 7,
            "core_cq": 8,
        }

        def rank(
            item: Tuple[Tuple[str, int], Dict[str, Any]]
        ) -> Tuple[int, int, str, int]:
            (device_name, cqn), cq = item
            size = compat._safe_int(cq.get("size"))
            return (
                1 if size is not None and size <= 1 else 0,
                role_rank.get(str(cq.get("queue_kind") or ""), len(role_rank)),
                device_name,
                cqn,
            )

        candidates.sort(key=rank)
        return [
            key
            for key, _cq in selection._limit_balanced(
                candidates,
                self.args.maxcq,
                lambda item: selection._cq_balance_bucket(item[1]),
            )
        ]

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

    def _auto_wqe_qp_dump_keys(self) -> List[_QpKey]:
        candidates = [
            (key, entry.record)
            for key, entry in self._qps.items()
            if entry.dump_wq is not None
            and selection._qp_matches_filter(entry.record, self.args)
        ]

        def rank(
            item: Tuple[_QpKey, Dict[str, Any]]
        ) -> Tuple[int, int, str, int]:
            _key, qp = item
            sq = qp.get("sq")
            sq_size = (
                compat._safe_int(sq.get("size"))
                if isinstance(sq, dict)
                else None
            )
            inflight = _nonnegative_delta(qp.get("sq_pc"), qp.get("sq_cc"))
            return (
                1 if sq_size in (None, 0) else 0,
                1 if inflight == 0 else 0,
                str(qp.get("device") or ""),
                compat._safe_int(qp.get("qpn")) or 0,
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
            size = (
                compat._safe_int(wq.get("size"))
                if isinstance(wq, dict)
                else None
            )
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
            prefer_filtered=False,
        )

    def _select_qp_key(self, qpn: int) -> Optional[_QpKey]:
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
        prefer_filtered: bool = True,
    ) -> Optional[_KeyT]:
        if not matches:
            return None
        if len(matches) == 1:
            return matches[0]
        filtered = [
            key for key in matches if key[0] in self._selected_device_names
        ]
        if len(filtered) == 1:
            return filtered[0]
        self._warn(warning)
        return filtered[0] if prefer_filtered and filtered else matches[0]

    def _dump_cqe(self, cqn: int, max_entries: int) -> Dict[str, Any]:
        key = self._select_numbered_key(self._cqs, cqn, "CQN")
        if key is None:
            return {
                "kind": "cqe",
                "selector": cqn,
                "status": "not-found",
                "entries": [],
            }
        return self._dump_cqe_key(key, max_entries)

    def _dump_cqe_key(
        self, key: Tuple[str, int], max_entries: int
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
            defs.DEFAULT_DESCRIPTOR_ENTRY_BYTES,
            decode=_decode_cqe,
            known_size=record.get("size"),
            known_consumer_index=record.get("consumer_index"),
            cqe_mode=True,
            owner_mode="cqe",
            around_consumer=True,
        )
        notes = []
        if self._annotate_ib_cqe_wr_ids(key, record, entries):
            notes.append(
                "WR_ID is read from matching struct mlx5_ib_qp.sq.wrid[] entries"
            )
        status = _descriptor_dump_status(entries)
        if _descriptor_dump_has_errors(entries):
            self._warn(
                f"CQN {cqn} on {device_name} dump status {status}; "
                f"wq_layout={dumps._wq_layout_summary(wq)}"
            )
        return {
            "kind": "cqe",
            "selector_name": "cqn",
            "selector": cqn,
            "device": device_name,
            "status": status,
            "cq": _jsonable(record),
            "wq": dumps._wq_layout_summary(wq),
            "consumer_index": record.get("consumer_index"),
            "window": dumps._dump_window_summary(
                max_entries, record.get("size")
            ),
            "notes": notes,
            "entries": entries,
        }

    def _annotate_ib_cqe_wr_ids(
        self,
        cq_key: Tuple[str, int],
        cq_record: Dict[str, Any],
        entries: List[Dict[str, Any]],
    ) -> int:
        if (
            formatting._short_struct(cq_record.get("address_struct"))
            != "mlx5_ib_cq"
        ):
            return 0
        count = 0
        for entry in entries:
            if entry.get("status") not in ("ok", "ready"):
                continue
            # mlx5_ib_poll_one() uses wqe_counter directly for send completions
            # and errors. Receive/SRQ completions use different cursor rules.
            if compat._safe_int(entry.get("opcode_value")) not in (0x0, 0xD):
                continue
            wqe_ctr = compat._safe_int(entry.get("wqe_counter"))
            if wqe_ctr is None:
                continue
            qp_key = self._find_ib_qp_for_cqe(cq_key, entry)
            if qp_key is None:
                continue
            qp_entry = self._qps.get(qp_key)
            wr_id, wr_idx = _mlx5_ib_wq_wrid_at_counter(
                qp_entry.sq_wq if qp_entry is not None else None, wqe_ctr
            )
            if wr_id is None:
                continue
            qp_record = qp_entry.record if qp_entry is not None else {}
            if qp_record.get(
                "creator_type"
            ) == "kernel" and _looks_like_kernel_pointer_value(wr_id):
                gsi_wr_id = _mlx5_ib_gsi_saved_wr_id(self.prog, wr_id)
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

    def _find_ib_qp_for_cqe(
        self, cq_key: Tuple[str, int], entry: Dict[str, Any]
    ) -> Optional[_QpKey]:
        if self._qps and not (
            self._qp_keys_by_send_cqn or self._qp_keys_by_alias
        ):
            self._rebuild_qp_indexes()
        device_name, cqn = cq_key
        cqe_qpn = compat._safe_int(entry.get("qpn"))
        matches = list(self._qp_keys_by_send_cqn.get((device_name, cqn), []))
        if len(matches) == 1:
            return matches[0]
        if cqe_qpn is not None and cqe_qpn != 0:
            qpn_keys = set(
                self._qp_keys_by_alias.get((device_name, cqe_qpn), [])
            )
            qpn_matches = [key for key in matches if key in qpn_keys]
            if len(qpn_matches) == 1:
                return qpn_matches[0]
        return None

    def _dump_eqe(self, eqn: int, max_entries: int) -> Dict[str, Any]:
        key = self._select_numbered_key(self._eqs, eqn, "EQN")
        if key is None:
            return {
                "kind": "eqe",
                "selector": eqn,
                "status": "not-found",
                "entries": [],
            }
        return self._dump_eqe_key(key, max_entries)

    def _dump_eqe_key(
        self, key: Tuple[str, int], max_entries: int
    ) -> Dict[str, Any]:
        device_name, eqn = key
        entry = self._eqs.get(key)
        record, eq, wq = entry if entry is not None else ({}, None, None)
        if wq is None and eq is not None:
            wq = compat._first_member_path(
                eq, (["wq"], ["core", "wq"], ["buf"], ["frag_buf"], ["core"])
            )
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
            defs.DEFAULT_DESCRIPTOR_ENTRY_BYTES,
            decode=_decode_eqe,
            known_size=record.get("size"),
            known_consumer_index=record.get("consumer_index"),
            owner_mode="eqe",
            around_consumer=True,
        )
        status = _descriptor_dump_status(entries)
        if _descriptor_dump_has_errors(entries):
            self._warn(
                f"EQN {eqn} on {device_name} dump status {status}; "
                f"wq_layout={dumps._wq_layout_summary(wq)}"
            )
        return {
            "kind": "eqe",
            "selector_name": "eqn",
            "selector": eqn,
            "device": device_name,
            "status": status,
            "eq": _jsonable(record),
            "wq": dumps._wq_layout_summary(wq),
            "consumer_index": record.get("consumer_index"),
            "window": dumps._dump_window_summary(
                max_entries, record.get("size")
            ),
            "entries": entries,
        }

    def _dump_wqe(self, qpn: int, max_entries: int) -> Dict[str, Any]:
        key = self._select_qp_key(qpn)
        if key is None:
            return {
                "kind": "wqe",
                "source": "qp",
                "selector": qpn,
                "status": "not-found",
                "entries": [],
            }
        return self._dump_wqe_key(key, max_entries)

    def _dump_wqe_key(
        self, key: _QpKey, max_entries: int, auto: bool = False
    ) -> Dict[str, Any]:
        entry = self._qps.get(key)
        record = entry.record if entry is not None else {}
        device_name = str(record.get("device") or key.device)
        qpn = compat._safe_int(record.get("qpn"))
        wq = entry.dump_wq if entry is not None else None
        owner = record.get("owner")
        wq_summary = record.get("sq", {})
        if wq is None:
            return {
                "kind": "wqe",
                "source": "qp",
                "selector_name": "qpn",
                "selector": qpn,
                "device": device_name,
                "owner": owner,
                "status": "not-found",
                "qp": _jsonable(record),
                "entries": [],
            }
        entries = self._dump_ring(
            wq,
            max_entries,
            defs.DEFAULT_DESCRIPTOR_ENTRY_BYTES,
            decode=_decode_wqe,
            known_size=wq_summary.get("size")
            if isinstance(wq_summary, dict)
            else None,
            known_consumer_index=record.get("sq_cc"),
            variable_wqe_stride=True,
        )
        status = _descriptor_dump_status(entries)
        notes = []
        if _nonnegative_delta(record.get("sq_pc"), record.get("sq_cc")) == 0:
            notes.append(
                "SQ head/tail show no outstanding WQEs; entries may be old ring contents"
            )
        if _descriptor_dump_has_errors(entries):
            self._warn_wqe_dump_error(
                "QPN", qpn, device_name, status, entries, wq, auto
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
            "wq": dumps._wq_layout_summary(wq),
            "wqe_kind": "ctrl",
            "notes": notes,
            "entries": entries,
        }

    def _dump_queue_wqe(
        self, selector_name: str, number: int, max_entries: int
    ) -> Dict[str, Any]:
        key = self._select_queue_key(selector_name, number)
        if key is None:
            return {
                "kind": "wqe",
                "source": "queue",
                "selector_name": selector_name,
                "selector": number,
                "status": "not-found",
                "entries": [],
            }
        return self._dump_queue_wqe_key(key, max_entries)

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
        linked_rq = is_rq and "mlx5_wq_ll" in str(
            compat._object_type_name(wq) or ""
        )
        decode_wqe = (
            (lambda raw: _decode_rq_wqe(raw, linked=linked_rq))
            if is_rq
            else _decode_wqe
        )
        entries = self._dump_ring(
            wq,
            max_entries,
            defs.DEFAULT_DESCRIPTOR_ENTRY_BYTES,
            decode=decode_wqe,
            known_size=wq_summary.get("size")
            if isinstance(wq_summary, dict)
            else None,
            known_consumer_index=record.get("cc"),
            variable_wqe_stride=not is_rq,
        )
        status = _descriptor_dump_status(entries)
        notes = []
        if compat._safe_int(record.get("inflight")) == 0:
            notes.append(
                "queue progress shows no outstanding WQEs; entries may be old ring contents"
            )
        if _descriptor_dump_has_errors(entries):
            self._warn_wqe_dump_error(
                selector_name.upper(),
                number,
                device_name,
                status,
                entries,
                wq,
                auto,
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
            "wq": dumps._wq_layout_summary(wq),
            "wqe_kind": "rq" if is_rq else "ctrl",
            "notes": notes,
            "entries": entries,
        }

    def _warn_wqe_dump_error(
        self,
        selector_name: str,
        selector: Any,
        device: str,
        status: str,
        entries: List[Dict[str, Any]],
        wq: Object,
        auto: bool,
    ) -> None:
        if not auto:
            statuses = Counter(
                str(entry.get("status", "ok")) for entry in entries
            )
            bad_statuses = {
                status: count
                for status, count in statuses.items()
                if status not in dumps._BENIGN_DESCRIPTOR_STATUSES
            }
            summary = f"statuses={bad_statuses}; {_wq_warning_shape(wq, include_wq=True)}"
            self._warn(
                f"{selector_name} {selector} on {device} WQE dump status {status}; {summary}"
            )
            return

        shape = _wq_warning_shape(wq)
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
        default_len: int,
        decode: Callable[[bytes], Dict[str, Any]],
        known_size: Optional[Any] = None,
        known_consumer_index: Optional[Any] = None,
        cqe_mode: bool = False,
        variable_wqe_stride: bool = False,
        owner_mode: Optional[str] = None,
        around_consumer: bool = False,
    ) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        size = compat._safe_int(known_size)
        if size is None:
            size = dumps._ring_size(wq, default_len)
        if size is not None and size <= 0:
            return [{"index": None, "status": "size-unavailable"}]
        consumer_index = compat._safe_int(known_consumer_index)
        if consumer_index is None:
            consumer_index = compat._first_int_path(
                wq, (["cc"], ["cons_index"], ["wqe_ctr"])
            )
        if consumer_index is None:
            return [{"index": None, "status": "consumer-index-unavailable"}]
        stride = dumps._ring_stride_bytes(wq)
        read_len = (
            min(default_len, stride)
            if stride is not None and stride > 0
            else default_len
        )
        entry_count = min(max_entries, defs.MAX_DESCRIPTOR_ENTRIES)
        if size is not None:
            entry_count = min(entry_count, size)
        cursor = consumer_index - (entry_count // 2 if around_consumer else 0)
        traversed = 0

        def mark_consumer(entry: Dict[str, Any], absolute_index: int) -> None:
            if around_consumer and absolute_index == consumer_index:
                entry["consumer_marker"] = "cons_index"

        for _ in range(entry_count):
            if variable_wqe_stride and size is not None and traversed >= size:
                break
            index = cursor % size if size is not None else cursor
            error_status = None
            addr = None
            try:
                addr = dumps._ring_entry_address(
                    wq,
                    index,
                    entry_len=default_len,
                    cqe_mode=cqe_mode,
                )
            except (
                Exception
            ) as err:  # Keep one bad descriptor from aborting the report.
                self._warn(
                    f"descriptor address calculation failed at index {index}: {err}"
                )
                error_status = f"address-error:{type(err).__name__}"
            if error_status is None and addr is None:
                error_status = "address-unavailable"
            raw = (
                compat._read_memory(self.prog, addr, read_len)
                if addr is not None
                else None
            )
            if error_status is None and raw is None:
                error_status = "fault"
            if error_status is not None:
                entry: Dict[str, Any] = {
                    "index": index,
                    "_absolute_index": cursor,
                }
                if addr is not None:
                    entry["address"] = formatting._hex(addr)
                entry["status"] = error_status
                mark_consumer(entry, cursor)
                entries.append(entry)
                cursor += 1
                traversed += 1
                continue
            assert raw is not None
            try:
                decoded = decode(raw)
            except Exception as err:
                self._warn(f"descriptor decode failed at index {index}: {err}")
                decoded = {"status": f"decode-error:{type(err).__name__}"}
            step = (
                _wqe_ctrl_wqebbs(decoded, stride, default_len)
                if variable_wqe_stride
                else 1
            )
            if variable_wqe_stride:
                decoded["wqebbs"] = step
            decoded.setdefault("status", "ok")
            mark_consumer(decoded, cursor)
            if owner_mode is not None:
                dumps._annotate_owner_status(
                    decoded,
                    cursor,
                    size,
                    owner_mode,
                    consumer_index=consumer_index,
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

    # Findings, warnings, and walk limits

    def _analyze_findings(
        self,
        devices: List[Dict[str, Any]],
        dump_reports: Sequence[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []

        def add(severity: str, scope: str, message: str) -> None:
            findings.append(
                {"severity": severity, "scope": scope, "message": message}
            )

        for device in devices:
            health = device.get("health", {})
            if health.get("fatal_error") not in (None, 0):
                add(
                    "HIGH",
                    device.get("name", "mlx5"),
                    "mlx5 health fatal_error is non-zero",
                )
            if health.get("miss_counter") not in (None, 0):
                add(
                    "MED",
                    device.get("name", "mlx5"),
                    "mlx5 health miss_counter is non-zero",
                )
            if (
                device.get("summary", {}).get("device_state")
                == "INTERNAL_ERROR"
            ):
                add(
                    "HIGH",
                    device.get("name", "mlx5"),
                    "mlx5_core_dev state is INTERNAL_ERROR",
                )
            for netdev in device.get("netdevs", []):
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
                for ch in netdev.get("channels", []):
                    for queue in selection._channel_queues(ch):
                        queue_name = _queue_finding_name(queue)
                        wq = queue.get("wq")
                        size = (
                            compat._safe_int(wq.get("size"))
                            if isinstance(wq, dict)
                            else None
                        )
                        pc = compat._safe_int(queue.get("pc"))
                        cc = compat._safe_int(queue.get("cc"))
                        inflight = compat._safe_int(queue.get("inflight"))
                        if queue.get("recovering"):
                            add(
                                "MED",
                                scope,
                                f"{queue_name} is marked recovering",
                            )
                        if _queue_should_warn_disabled(queue):
                            add(
                                "LOW",
                                scope,
                                f"{queue_name} is not marked enabled",
                            )
                        if queue.get("txq_stopped"):
                            add(
                                "MED",
                                scope,
                                f"{queue_name} netdev TX queue is stopped/frozen",
                            )
                        if pc is not None and cc is not None and pc < cc:
                            add(
                                "MED",
                                scope,
                                f"{queue_name} producer counter is behind consumer counter",
                            )
                        if (
                            inflight is not None
                            and size is not None
                            and 0 < size <= inflight
                        ):
                            add(
                                "HIGH",
                                scope,
                                f"{queue_name} in-flight work is at or above WQ size",
                            )
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
        findings = []

        def add(scope: str, message: str) -> None:
            findings.append(
                {"severity": "HIGH", "scope": scope, "message": message}
            )

        for dump in dump_reports:
            kind = dump.get("kind")
            selector_name = dump.get("selector_name") or "id"
            selector = dump.get("selector")
            scope = dump.get("device") or "mlx5"
            for entry in dump.get("entries", []) or []:
                if entry.get("status", "ok") not in ("ok", "ready"):
                    continue
                if (
                    kind == "cqe"
                    and compat._safe_int(entry.get("opcode_value"))
                    in defs._MLX5_CQE_ERROR_OPCODES
                ):
                    syndrome = entry.get("syndrome_display") or entry.get(
                        "syndrome"
                    )
                    add(
                        scope,
                        f"CQE error on {selector_name}={selector} index {entry.get('index')}"
                        f" syndrome={syndrome}",
                    )
                elif (
                    kind == "eqe"
                    and compat._safe_int(entry.get("type_value")) == 0x4
                ):
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

    def _warn_truncated(self, msg: str) -> None:
        self._truncated_walks = True
        self._warn(msg)

    def _walk_count(
        self, total: int, scope: str, hard_limit: int = defs.MAX_WALK_LIMIT
    ) -> int:
        count = compat._bounded(total, self.args.walk_limit, hard_limit)
        if int(total) > count:
            limit = f"sanity-max={hard_limit}"
            if self.args.walk_limit is not None:
                limit = f"--walk-limit={self.args.walk_limit}, {limit}"
            self._warn_truncated(
                f"{scope}: walk truncated after {count} of {int(total)} entries ({limit})"
            )
        return count

    def _iter_limited(
        self, iterable: Iterable[Any], scope: str
    ) -> Iterator[Any]:
        return self._iter_walk_limited(iterable, f"{scope}: iterator walk")


# Core helper functions


def _validate_args(args: argparse.Namespace) -> None:
    if getattr(args, "summary", False) and getattr(args, "full", False):
        raise ValueError("--summary and --full cannot be used together")
    invalid_qp_creators = sorted(
        set(getattr(args, "qp_creators", []) or ()) - {"kernel", "user"}
    )
    if invalid_qp_creators:
        raise ValueError(
            "--qp-creator must be 'kernel' or 'user', got: "
            + ", ".join(invalid_qp_creators)
        )
    for option, value, hard_limit in (
        ("--maxqueues", args.maxqueues, defs.MAX_WALK_LIMIT),
        ("--maxcq", args.maxcq, defs.MAX_WALK_LIMIT),
        ("--maxeq", args.maxeq, defs.MAX_WALK_LIMIT),
        ("--maxqp", args.maxqp, defs.MAX_WALK_LIMIT),
        ("--maxcqe", args.maxcqe, defs.MAX_DESCRIPTOR_ENTRIES),
        ("--maxeqe", args.maxeqe, defs.MAX_DESCRIPTOR_ENTRIES),
        ("--maxwqe", args.maxwqe, defs.MAX_DESCRIPTOR_ENTRIES),
    ):
        if value is not None or option in {"--maxcqe", "--maxeqe", "--maxwqe"}:
            _validate_cap(option, value, hard_limit)
    if args.walk_limit is not None:
        _validate_cap("--walk-limit", args.walk_limit, defs.MAX_WALK_LIMIT)
    if args.dev and ":" in args.dev and "." in args.dev:
        if not defs._PCI_BDF_RE.match(args.dev):
            raise ValueError("invalid --dev BDF value, expected DDDD:BB:DD.F")
    for name in ("cqn", "eqn", "qpn", "sqn", "rqn"):
        value = getattr(args, name, None)
        if value is not None and value < 0:
            raise ValueError(f"--{name} must be >= 0")


def _cq_arm_sn(raw: Optional[int]) -> Optional[int]:
    return None if raw is None else int(raw) & 0x3


def _irq_desc(prog: Program, irqn: Optional[int]) -> Optional[Object]:
    if irqn is None or compat.irq_to_desc is None:
        return None
    try:
        desc = compat.irq_to_desc(prog, int(irqn))
    except Exception:
        return None
    return None if desc is None or compat._is_null(desc) else desc


def _irq_affinity_cpus(prog: Program, irqn: Optional[int]) -> Optional[str]:
    if compat.cpumask_to_cpulist is None:
        return None
    desc = _irq_desc(prog, irqn)
    if desc is None:
        return None
    for path in (
        ("irq_common_data", "effective_affinity"),
        ("irq_common_data", "affinity"),
        ("affinity_hint",),
        ("percpu_affinity",),
    ):
        mask = compat._safe_member_path(desc, path)
        if mask is None or compat._is_null(mask):
            continue
        try:
            cpus = compat.cpumask_to_cpulist(mask)
        except Exception:
            continue
        if cpus:
            return cpus
    return None


def _shared_known_value(values: Iterable[Optional[int]]) -> Optional[int]:
    known = {value for value in values if value is not None}
    return next(iter(known)) if len(known) == 1 else None


def _record_key(device: Any, number: Any) -> Optional[Tuple[str, int]]:
    number = compat._safe_int(number)
    if device is None or number is None:
        return None
    return str(device), number


def _qp_identity(
    qp: Object, device: Any, table_qpn: Optional[int] = None
) -> _QpIdentity:
    """Read the small set of fields used to identify a QP."""

    ib_qpn = compat._first_int_path(qp, (["ibqp", "qp_num"],))
    object_hw_qpn = compat._first_int_path(qp, defs._MLX5_QPN_PATHS)
    hw_qpn = object_hw_qpn if object_hw_qpn is not None else table_qpn
    qpn = ib_qpn if ib_qpn is not None else hw_qpn
    address = compat._nonzero_addr(qp)

    key = None
    if device is not None and qpn is not None:
        if address is not None:
            key = _QpKey(str(device), "address", address)
        elif hw_qpn is not None:
            key = _QpKey(str(device), "hw_qpn", hw_qpn)
        else:
            key = _QpKey(str(device), "qpn", qpn)

    aliases = tuple(selection._qp_aliases(qpn, ib_qpn, hw_qpn, table_qpn))
    return _QpIdentity(key, qpn, ib_qpn, hw_qpn, aliases)


def _merge_missing_fields(
    existing: Dict[str, Any], discovered: Dict[str, Any]
) -> None:
    """Fill missing fields without replacing existing values."""

    for name, value in discovered.items():
        if existing.get(name) in (
            None,
            "",
            [],
            {"status": "unavailable"},
        ) and value not in (None, "", []):
            existing[name] = value


def _qp_queue_progress(
    qp: Object, queue: str
) -> Tuple[Optional[int], Optional[int], Optional[str], Optional[str]]:
    """Read queue counters and the member paths that supplied them."""

    pc, pc_source = compat._first_int_path_with_source(
        qp,
        (
            (f"qp.{queue}.pc", [queue, "pc"]),
            (f"qp.{queue}.wq.pc", [queue, "wq", "pc"]),
            (f"qp.{queue}.head", [queue, "head"]),
        ),
    )
    cc, cc_source = compat._first_int_path_with_source(
        qp,
        (
            (f"qp.{queue}.cc", [queue, "cc"]),
            (f"qp.{queue}.wq.cc", [queue, "wq", "cc"]),
            (f"qp.{queue}.tail", [queue, "tail"]),
        ),
    )
    return pc, cc, pc_source, cc_source


def _qp_type(qp: Optional[Object]) -> Optional[int]:
    if qp is None:
        return None

    for name in ("type", "qp_type"):
        direct_type = compat._safe_int(compat._safe_member(qp, name))
        if direct_type is not None:
            return direct_type

    ib_qp_type = compat._safe_int(
        compat._safe_member_path(qp, ["ibqp", "qp_type"])
    )
    qp_sub_type = compat._safe_int(compat._safe_member(qp, "qp_sub_type"))
    if ib_qp_type == 255 and qp_sub_type is not None:
        return qp_sub_type
    return ib_qp_type if ib_qp_type is not None else qp_sub_type


def _plausible_mlx5_ib_qp(qp: Optional[Object]) -> bool:
    return (
        qp is not None
        and not compat._is_null(qp)
        and compat._safe_member(qp, "ibqp") is not None
        and compat._safe_int(compat._safe_member_path(qp, ["ibqp", "qp_num"]))
        is not None
    )


def _creator_record(
    display: str,
    creator_type: Optional[str],
    source: Optional[str],
    name: Optional[str] = None,
    pid: Optional[int] = None,
) -> Dict[str, Any]:
    return {
        "display": display,
        "type": creator_type,
        "name": name,
        "pid": pid,
        "source": source,
    }


def _qp_creator(qp: Optional[Object]) -> Dict[str, Any]:
    resource = compat._safe_member_path(qp, ["ibqp", "res"])
    if resource is not None:
        user = compat._safe_int(compat._safe_member(resource, "user"))
        if user == 1:
            task = compat._safe_member(resource, "task")
            comm = compat._safe_cstr(compat._safe_member(task, "comm"))
            pid = compat._first_int_path(task, (["pid"], ["tgid"]))
            display = "user"
            if comm and pid is not None:
                display = f"user:{comm}[{pid}]"
            elif comm:
                display = f"user:{comm}"
            elif pid is not None:
                display = f"user:[{pid}]"
            return _creator_record(
                display, "user", "struct ib_qp.res.user/task", comm, pid
            )
        if user == 0:
            kern_name = compat._safe_cstr(
                compat._safe_member(resource, "kern_name")
            )
            display = f"kernel:{kern_name}" if kern_name else "kernel"
            return _creator_record(
                display, "kernel", "struct ib_qp.res.user/kern_name", kern_name
            )

    uobjects = []
    # A non-NULL uobject means userspace ownership. NULL means kernel ownership;
    # a missing member leaves ownership unknown.
    for path, source in (
        (["ibqp", "uobject"], "struct ib_qp.uobject"),
        (["ibqp", "pd", "uobject"], "struct ib_qp.pd.uobject"),
    ):
        uobject = compat._safe_member_path(qp, path)
        uobjects.append(uobject)
        if uobject is not None and not compat._is_null(uobject):
            return _creator_record("user", "user", source)
    if any(uobject is not None for uobject in uobjects):
        return _creator_record("kernel", "kernel", "struct ib_qp.uobject")
    return _creator_record("unresolved", None, None)


def _qp_creator_resolution(qps: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    unresolved = [
        qp for qp in qps if qp.get("creator_type") not in ("kernel", "user")
    ]
    unresolved.sort(
        key=lambda qp: (
            str(qp.get("device") or ""),
            formatting._sort_key(qp.get("qpn")),
        )
    )
    return {
        "unresolved_count": len(unresolved),
        "examples": [
            {"device": qp.get("device"), "qpn": qp.get("qpn")}
            for qp in unresolved[:5]
        ],
    }


def _cq_number_from_cq(cq: Optional[Object]) -> Optional[int]:
    if cq is None or compat._is_null(cq):
        return None
    cqn = compat._first_int_path(cq, (["mcq", "cqn"], ["cqn"]))
    if cqn is not None:
        return cqn
    mlx5_ib_cq = compat._safe_container_of(cq, "struct mlx5_ib_cq", "ibcq")
    return compat._first_int_path(mlx5_ib_cq, (["mcq", "cqn"], ["cqn"]))


def _mlx5_ib_wq_wrid_at_counter(
    wq: Optional[Object], wqe_counter: int
) -> Tuple[Optional[int], Optional[int]]:
    if wq is None or compat._is_null(wq):
        return None, None
    wqe_cnt = compat._first_int_path(wq, (["wqe_cnt"],))
    if wqe_cnt is None or wqe_cnt <= 0:
        return None, None
    index = wqe_counter & (wqe_cnt - 1)
    wrid = compat._safe_member(wq, "wrid")
    if wrid is None or compat._is_null(wrid):
        return None, index
    try:
        return compat._safe_int(wrid[index]), index
    except (
        FaultError,
        compat.ObjectAbsentError,
        compat.OutOfBoundsError,
        LookupError,
        TypeError,
        ValueError,
    ):
        return None, index


def _mlx5_ib_gsi_saved_wr_id(prog: Program, wr_cqe: Any) -> Optional[int]:
    addr = compat._safe_int(wr_cqe)
    if addr is None or not _looks_like_kernel_pointer_value(addr):
        return None
    try:
        cqe = Object(prog, "struct ib_cqe *", value=addr)
        done = compat._safe_int(compat._safe_member(cqe, "done"))
        if (
            done is None
            or prog.symbol(done).name != "handle_single_completion"
        ):
            return None
        gsi_wr = compat._safe_container_of(cqe, "struct mlx5_ib_gsi_wr", "cqe")
        return compat._first_int_path(gsi_wr, (["wc", "wr_id"],))
    except Exception:
        return None


def _looks_like_kernel_pointer_value(value: Any) -> bool:
    number = compat._safe_int(value)
    # Supported 64-bit vmcores use high canonical kernel addresses. Apply this
    # only to kernel QPs because userspace may choose any u64 WR_ID.
    return number is not None and number >= (1 << 63)


def _cq_consumer_index(
    address_struct: Optional[str],
    wq_summary: Dict[str, Any],
    core_cq: Optional[Object],
) -> Tuple[Optional[int], str, Optional[int]]:
    """Choose the CQ consumer counter for its owner.

    mlx5_ib polls mlx5_core_cq.cons_index. mlx5e and ASO poll through
    mlx5_cqwq, so use wq.cc; their mcq.cons_index may remain zero.
    """

    core_cons_index = (
        compat._safe_int(compat._safe_member(core_cq, "cons_index"))
        if core_cq is not None
        else None
    )
    wq_cc = compat._safe_int(wq_summary.get("cc"))
    if (
        address_struct in ("struct mlx5e_cq", "struct mlx5_aso_cq")
        and wq_cc is not None
    ):
        return wq_cc, f"{address_struct}.wq.cc", core_cons_index
    return core_cons_index, "struct mlx5_core_cq.cons_index", core_cons_index


def _validate_cap(option: str, value: int, hard_limit: int) -> None:
    if value < 1:
        raise ValueError(f"{option} must be >= 1")
    if value > hard_limit:
        raise ValueError(f"{option} must be <= {hard_limit}")


def _wqe_ctrl_wqebbs(
    decoded: Dict[str, Any], stride_bytes: Optional[int], default_len: int
) -> int:
    ds = compat._safe_int(decoded.get("ds"))
    if ds is None or ds <= 0:
        return 1
    stride = (
        stride_bytes
        if stride_bytes is not None and stride_bytes > 0
        else default_len
    )
    if stride <= 0:
        stride = defs.DEFAULT_DESCRIPTOR_ENTRY_BYTES
    return max(1, (ds * 16 + stride - 1) // stride)


def _bit_is_set(value: Optional[int], bit: int) -> Optional[bool]:
    return None if value is None else bool(value & (1 << bit))


def _decode_state_bits(
    value: Optional[int], names: Dict[int, str]
) -> List[str]:
    return (
        []
        if value is None
        else [
            name for bit, name in sorted(names.items()) if value & (1 << bit)
        ]
    )


def _nonnegative_delta(pc: Optional[int], cc: Optional[int]) -> Optional[int]:
    if pc is None or cc is None or pc < cc:
        return None
    return pc - cc


def _rq_progress_detail(
    queue_obj: Object,
    active_wq: Optional[Object],
    active_source: Optional[str],
) -> Dict[str, Any]:
    linked_rq = active_source == "rq.mpwqe.wq" or "mlx5_wq_ll" in str(
        compat._object_type_name(active_wq) or ""
    )

    pc = compat._safe_int(compat._safe_member(active_wq, "wqe_ctr"))
    pc_source = (
        f"{active_source}.wqe_ctr"
        if pc is not None and active_source
        else None
    )
    if pc is None:
        pc, pc_source = compat._first_int_path_with_source(
            queue_obj,
            (
                ("rq.wq.wqe_ctr", ["wq", "wqe_ctr"]),
                ("rq.wqe_ctr", ["wqe_ctr"]),
                ("rq.pc", ["pc"]),
            ),
        )

    cc = cc_source = None
    if linked_rq:
        cc = compat._safe_int(compat._safe_member(active_wq, "head"))
        cc_source = (
            f"{active_source}.head"
            if cc is not None and active_source
            else None
        )
        if cc is None and active_source == "rq.mpwqe.wq":
            cc = compat._first_int_path(
                queue_obj, (["mpwqe", "actual_wq_head"],)
            )
            cc_source = "rq.mpwqe.actual_wq_head" if cc is not None else None

    inflight = inflight_source = None
    if linked_rq:
        cur_sz = compat._safe_int(compat._safe_member(active_wq, "cur_sz"))
        size = dumps._ring_size(active_wq, defs.DEFAULT_DESCRIPTOR_ENTRY_BYTES)
        if (
            cur_sz is not None
            and cur_sz >= 0
            and (size is None or cur_sz <= size)
        ):
            inflight = cur_sz
            inflight_source = (
                f"{active_source}.cur_sz" if active_source else None
            )
    if inflight is None and linked_rq:
        inflight = _nonnegative_delta(pc, cc)
        inflight_source = "pc-cc" if inflight is not None else None
    return {
        "pc": pc,
        "cc": cc,
        "inflight": inflight,
        "pc_source": pc_source,
        "cc_source": cc_source,
        "inflight_source": inflight_source,
    }


# Linux/netdev/mlx5 object helpers


def _num_tc_from_priv(priv: Object) -> Optional[int]:
    candidates = (
        ["channels", "params", "mqprio", "num_tc"],
        ["channels", "params", "num_tc"],
        ["channels_info", "params", "mqprio", "num_tc"],
        ["channels_info", "params", "num_tc"],
        ["max_opened_tc"],
    )
    value = compat._first_int_path(priv, candidates)
    return min(value, defs.MAX_TC) if value is not None and value > 0 else None


def _queue_number_with_source(
    queue_obj: Object, kind: str
) -> Tuple[Optional[int], Optional[str]]:
    number_field = "rqn" if kind in ("rq", "xskrq", "ptp_rq") else "sqn"
    return compat._first_int_path_with_source(
        queue_obj,
        (
            (f"queue.{number_field}", [number_field]),
            (f"queue.wq.{number_field}", ["wq", number_field]),
            ("queue.base.mqp.qpn", ["base", "mqp", "qpn"]),
            ("queue.mqp.qpn", ["mqp", "qpn"]),
        ),
    )


def _queue_record_has_identity(record: Dict[str, Any]) -> bool:
    return record.get("number") is not None or record.get("address") not in (
        None,
        "0x0",
    )


def _queue_finding_name(queue: Dict[str, Any]) -> str:
    owner = queue.get("owner")
    if owner:
        return str(owner)
    kind = queue.get("kind") or "queue"
    number = queue.get("number")
    return str(kind) if number is None else f"{kind} {number}"


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


def _descriptor_dump_status(entries: List[Dict[str, Any]]) -> str:
    if not entries:
        return "empty"
    statuses = [entry.get("status", "ok") for entry in entries]
    if all(status == statuses[0] for status in statuses):
        return str(statuses[0])
    return "partial"


def _descriptor_dump_has_errors(entries: List[Dict[str, Any]]) -> bool:
    return any(
        entry.get("status", "ok") not in dumps._BENIGN_DESCRIPTOR_STATUSES
        for entry in entries
    )


def _wq_warning_shape(wq: Optional[Object], include_wq: bool = False) -> str:
    layout = dumps._wq_layout_summary(wq)
    fields: Tuple[Tuple[str, str], ...] = (
        ("wq", "wq"),
        ("frags", "frags"),
        ("direct", "direct"),
        ("computed_size", "computed_size"),
        ("stride", "stride_bytes"),
    )
    if not include_wq:
        fields = fields[1:]
    return "; ".join(
        f"{label}={selection._first_present(layout.get(key), '-')}"
        for label, key in fields
    )
