# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Rendering helpers for the mlx5 Corelens report."""
import argparse
import logging
from collections import Counter
from collections import defaultdict
from collections import OrderedDict
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple

from . import selection
from .compat import _safe_int
from .defs import MAX_DEFAULT_DESCRIPTOR_ENTRIES
from .format import _count_display
from .format import _display
from .format import _short_struct
from drgn_tools.table import Table

LOG = logging.getLogger("drgn_tools.mlx5")

DUMP_SEPARATOR = "-" * 79


def render_report(report: Dict[str, Any], args: argparse.Namespace) -> None:
    selection._resolve_report_sections(args)
    print("MLX5 REPORT")
    print("===========")
    print()
    print("Inputs")
    print(f"  mode    : {report.get('mode')}")
    print(f"  dev     : {report.get('selection', {}).get('dev') or '<all>'}")
    print(
        f"  netdev  : {report.get('selection', {}).get('netdev') or '<all>'}"
    )
    print(f"  ip      : {report.get('selection', {}).get('ip') or '<all>'}")
    report_selection = report.get("selection", {})
    if report_selection.get("summary"):
        print("  summary : yes")
    if report_selection.get("full"):
        print("  full    : yes")
    if report_selection.get("qp_creators"):
        print(
            f"  qp creator: {', '.join(str(v) for v in report_selection.get('qp_creators') or [])}"
        )
    print(
        "  max obj : "
        f"queues={_max_display(report_selection.get('maxqueues'))} "
        f"cq={_max_display(report_selection.get('maxcq'))} "
        f"eq={_max_display(report_selection.get('maxeq'))} "
        f"qp={_max_display(report_selection.get('maxqp'))}"
    )
    print(
        "  max desc: "
        f"cqe={report_selection.get('maxcqe')} "
        f"eqe={report_selection.get('maxeqe')} "
        f"wqe={report_selection.get('maxwqe')}"
    )
    print(f"  walk    : {_max_display(report_selection.get('walk_limit'))}")
    print()

    counts = report.get("counts", {})
    print("Report summary")
    print(f"  - mlx5 devices : {_count_display(counts.get('devices', 0))}")
    print(f"  - netdevs      : {_count_display(counts.get('netdevs', 0))}")
    print(f"  - channels     : {_count_display(counts.get('channels', 0))}")
    print(f"  - queues       : {_count_display(counts.get('queues', 0))}")
    print(
        "  - CQs/EQs/QPs  : "
        f"{_count_display(counts.get('cqs', 0))} / "
        f"{_count_display(counts.get('eqs', 0))} / "
        f"{_count_display(counts.get('qps', 0))}"
    )
    print(
        "  - findings     : "
        f"{_findings_summary_line(report.get('findings', []))} (collected scope only)"
    )
    print(f"  - warnings     : {len(report.get('warnings', []))}")
    if report.get("truncated_walks"):
        print("  - truncated    : yes")
    print()

    _render_section(report, args, "device summary", _render_devices)
    if args.queues or _should_render_wqe_context(
        report, args, "queue", ("sqn", "rqn")
    ):
        _render_section(report, args, "queues", _render_queues)
    if args.cqs or args.ib_cqs or args.eth_cqs or args.dump_cqe:
        _render_section(report, args, "completion queues", _render_cqs)
    if args.eqs or args.dump_eqe:
        _render_section(report, args, "event queues", _render_eqs)
    if (
        args.qps
        or (args.qpn is not None and not args.dump_wqe)
        or _should_render_wqe_context(report, args, "qp", ("qpn",))
    ):
        _render_section(report, args, "queue pairs", _render_qps)
    if report.get("dumps"):
        _render_section(report, args, "descriptor dumps", _render_dumps)
    _render_section(report, args, "findings", _render_findings)
    try:
        _render_warnings(report, args)
    except Exception as err:  # pragma: no cover - last-ditch reporting guard
        msg = f"collector warnings render failed: {type(err).__name__}: {err}"
        LOG.exception(msg)
        print("Collector warnings")
        print(f"  - {msg}")
        print()


def _render_section(
    report: Dict[str, Any],
    args: argparse.Namespace,
    name: str,
    renderer: Callable[[Dict[str, Any], argparse.Namespace], None],
) -> None:
    try:
        renderer(report, args)
    except Exception as err:  # pylint: disable=broad-except
        msg = f"{name} render failed: {type(err).__name__}: {err}"
        LOG.exception(msg)
        warnings = report.get("warnings")
        if isinstance(warnings, list):
            warnings.append(msg)
        elif warnings:
            report["warnings"] = [warnings, msg]
        else:
            report["warnings"] = [msg]


def _render_devices(report: Dict[str, Any], args: argparse.Namespace) -> None:
    print("Device summary")
    device_labels = _device_display_labels(report)
    table = Table(
        "PCI MLX5_CORE_DEV NETDEVS IPS RDMA_DEV RDMA_PORT STATE HEALTH FW CH CQ EQ QP".split()
    )
    for device in report.get("devices", []):
        summary = device.get("summary", {})
        counts = device.get("counts", {})
        netdevs = (
            ",".join(n.get("name", "?") for n in device.get("netdevs", []))
            or "-"
        )
        table.row(
            summary.get("pci_bdf"),
            summary.get("mdev"),
            netdevs,
            _device_ips(device),
            summary.get("rdma_name") or device.get("rdma_name") or "-",
            summary.get("rdma_port") or device.get("rdma_port") or "-",
            summary.get("device_state"),
            device.get("health", {}).get("status"),
            summary.get("fw_version"),
            _count_display(counts.get("channels")),
            _count_display(counts.get("cqs")),
            _count_display(counts.get("eqs")),
            _count_display(counts.get("qps")),
        )
    table.write()
    print()

    if args._full_report:
        print("Device details")
        for device in report.get("devices", []):
            name = device.get("name")
            label = device_labels.get(str(name), name)
            print(f"  {label}")
            summary = dict(device.get("summary", {}) or {})
            if "name" in summary:
                summary["name"] = label
            _print_kv_block("summary", summary, indent="    ")
            _print_kv_block("health", device.get("health", {}), indent="    ")
            _print_kv_block(
                "capabilities", device.get("capabilities", {}), indent="    "
            )
            for netdev in device.get("netdevs", []):
                print(f"    netdev {netdev.get('name')}")
                _print_kv_block(
                    "summary", netdev.get("summary", {}), indent="      "
                )
                _print_kv_block(
                    "priv", netdev.get("priv", {}), indent="      "
                )
        print()


def _device_ips(device: Dict[str, Any]) -> str:
    ips: List[str] = []
    for netdev in device.get("netdevs", []) or []:
        summary = netdev.get("summary", {})
        for ip in summary.get("ip_addresses", []) or []:
            if ip not in ips:
                ips.append(str(ip))
    if not ips:
        return "-"
    shown = ips[:4]
    if len(ips) > len(shown):
        shown.append(f"+{len(ips) - len(shown)} more")
    return ",".join(shown)


def _device_display_labels(report: Dict[str, Any]) -> Dict[str, str]:
    devices = report.get("devices", []) or []
    rdma_counts: Dict[str, int] = defaultdict(int)
    for device in devices:
        rdma_name = _device_rdma_name(device)
        if rdma_name:
            rdma_counts[rdma_name] += 1

    labels: Dict[str, str] = {}
    for device in devices:
        name = device.get("name")
        if name is None:
            continue
        labels[str(name)] = _device_display_label(device, rdma_counts)
    return labels


def _device_rdma_name(device: Dict[str, Any]) -> Optional[str]:
    summary = device.get("summary", {}) or {}
    value = summary.get("rdma_name") or device.get("rdma_name")
    return None if value in (None, "", "-") else str(value)


def _device_display_label(
    device: Dict[str, Any], rdma_counts: Dict[str, int]
) -> str:
    summary = device.get("summary", {}) or {}
    rdma_name = _device_rdma_name(device)
    if rdma_name:
        rdma_port = summary.get("rdma_port") or device.get("rdma_port")
        if rdma_port in (None, "", "-"):
            rdma_port = None
        if rdma_counts.get(rdma_name, 0) > 1 and rdma_port is not None:
            return f"{rdma_name}/{rdma_port}"
        return rdma_name

    netdevs = [
        str(n.get("name"))
        for n in device.get("netdevs", []) or []
        if n.get("name")
    ]
    if len(netdevs) == 1:
        return netdevs[0]

    for key in ("pci_bdf", "mdev"):
        value = summary.get(key)
        if value not in (None, "", "-"):
            return str(value)

    return str(device.get("name") or "-")


def _record_device_display(
    record: Dict[str, Any], device_labels: Dict[str, str]
) -> Any:
    display = record.get("device_display")
    if display not in (None, "", "-"):
        return display
    device = record.get("device")
    if device is None:
        device = record.get("name")
    if device is None:
        return None
    return device_labels.get(str(device), device)


def _should_render_wqe_context(
    report: Dict[str, Any],
    args: argparse.Namespace,
    source: str,
    selectors: Sequence[str],
) -> bool:
    if not args.dump_wqe:
        return False
    return any(getattr(args, name) is not None for name in selectors) or any(
        dump.get("kind") == "wqe" and dump.get("source") == source
        for dump in report.get("dumps", []) or []
    )


def _render_queues(report: Dict[str, Any], args: argparse.Namespace) -> None:
    print("mlx5e channels and queues")
    print(
        "  PC is the producer counter. For SQs, it tracks posted sends. For RQs, it tracks posted receive WQEs."
    )
    print(
        "  CC is the consumer counter. For SQs, it tracks completed sends. "
        "For RQs, it is the receive WQ head/start index."
    )
    print(
        "  TX_STOP shows whether the netdev TX queue is stopped or frozen. "
        "'-' means not found or not used for this row."
    )
    headers = """
    NETDEV RDMA_DEV CH CPU NAPI NAPI_ST ROLE TC QNUM PC CC INFLIGHT WQ_SZ STRIDE STATE TX_STOP
    CQN EQN EQ_VEC IRQN
    """.split()
    table = Table(headers)
    candidates: List[Tuple[Tuple[str, str], List[Any]]] = []
    selected_dump_keys = selection._wqe_queue_context_keys(report, args)
    device_labels = _device_display_labels(report)
    for device in report.get("devices", []):
        rdma_dev = _record_device_display(device, device_labels)
        for netdev in device.get("netdevs", []):
            for ch in netdev.get("channels", []):
                for queue in selection._channel_queues(ch):
                    if not selection._queue_matches_wqe_selector(
                        queue,
                        args,
                        selected_dump_keys=selected_dump_keys,
                        device_name=device.get("name"),
                    ):
                        continue
                    cq = queue.get("cq") or {}
                    wq = queue.get("wq")
                    if not isinstance(wq, dict):
                        wq = {}
                    row = [
                        netdev.get("name"),
                        rdma_dev,
                        ch.get("index"),
                        ch.get("cpu"),
                        ch.get("napi_id"),
                        ch.get("napi_state"),
                        queue.get("kind"),
                        selection._first_present(queue.get("tc"), "-"),
                        queue.get("number"),
                        selection._first_present(queue.get("pc"), "-"),
                        selection._first_present(queue.get("cc"), "-"),
                        selection._first_present(queue.get("inflight"), "-"),
                        selection._first_present(wq.get("size"), "-"),
                        selection._first_present(wq.get("stride_bytes"), "-"),
                        ",".join(queue.get("state_flags", []))
                        or queue.get("state"),
                        ",".join(queue.get("txq_state_flags", []))
                        or selection._first_present(
                            queue.get("txq_stopped"), "-"
                        ),
                        cq.get("cqn"),
                        cq.get("eqn"),
                        selection._first_present(
                            cq.get("eq_vector"), cq.get("vector")
                        ),
                        selection._first_present(
                            cq.get("eq_irqn"), cq.get("irqn")
                        ),
                    ]
                    owner = queue.get(
                        "netdev", netdev.get("name")
                    ) or queue.get("device", device.get("name"))
                    bucket = (str(owner or ""), str(queue.get("kind") or ""))
                    candidates.append((bucket, row))
    for _bucket, row in selection._limit_balanced(
        candidates, args.maxqueues, lambda item: item[0]
    ):
        table.row(*row)
    table.write()
    print()


def _render_cqs(report: Dict[str, Any], args: argparse.Namespace) -> None:
    print("Completion queues")
    print(
        "  CQ_ADDR is the CQ structure address. CQ_STRUCT shows which struct it is."
    )
    print(
        "  ARM_SN is the driver's software arm sequence number "
        "(arm_sn & 3), not hardware arm state."
    )
    print(
        "  EVENTS is the mlx5e CQ event counter. '-' means not found or not used for this CQ."
    )
    if args.ib_cqs or args.eth_cqs:
        print(f"  filter: {', '.join(selection._cq_filter_structs(args))}")
    table = Table(
        "NETDEV RDMA_DEV CQN CQ_ADDR CQ_STRUCT INFO CONS ARM_SN EVENTS SIZE STRIDE EQN IRQN IRQ_CPU".split()
    )
    cqs = [
        cq
        for cq in report.get("cqs", [])
        if selection._cq_matches_filter(cq, args)
    ]
    if args.cqn is not None:
        cqs = [cq for cq in cqs if _safe_int(cq.get("cqn")) == args.cqn]
    device_labels = _device_display_labels(report)
    for cq in selection._limit_balanced(
        cqs, args.maxcq, selection._cq_balance_bucket
    ):
        table.row(
            cq.get("netdev")
            if _short_struct(cq.get("address_struct")) == "mlx5e_cq"
            and cq.get("netdev")
            else "-",
            _record_device_display(cq, device_labels),
            cq.get("cqn"),
            cq.get("address"),
            _short_struct(cq.get("address_struct")),
            _cq_info_column(cq),
            cq.get("consumer_index"),
            cq.get("arm_sn"),
            selection._first_present(cq.get("event_ctr"), "-"),
            selection._first_present(cq.get("size"), "-"),
            cq.get("stride_bytes"),
            cq.get("eqn"),
            selection._first_present(cq.get("eq_irqn"), cq.get("irqn")),
            selection._first_present(cq.get("eq_irq_cpu"), "-"),
        )
    table.write()
    print()


def _cq_info_column(cq: Dict[str, Any]) -> str:
    owners = [
        str(owner)
        for owner in cq.get("owners", []) or []
        if owner and not str(owner).startswith("eq_cq_table:")
    ]
    if not owners:
        owner = cq.get("owner")
        if owner and not str(owner).startswith("eq_cq_table:"):
            owners.append(str(owner))
    if owners:
        if _short_struct(cq.get("address_struct")) == "mlx5e_cq":
            netdev = cq.get("netdev")
            prefix = f"{netdev}/" if netdev else None
            if prefix:
                owners = [
                    owner[len(prefix) :] if owner.startswith(prefix) else owner
                    for owner in owners
                ]
        return ";".join(owners)
    queue_kind = cq.get("queue_kind")
    if queue_kind:
        queue_number = cq.get("queue_number")
        if queue_number is not None:
            return f"{queue_kind}{queue_number}"
        return str(queue_kind)
    return "-"


def _render_eqs(report: Dict[str, Any], args: argparse.Namespace) -> None:
    print("Event queues")
    eqs = list(report.get("eqs", []))
    if args.eqn is not None:
        eqs = [eq for eq in eqs if _safe_int(eq.get("eqn")) == args.eqn]
    if args.dump_eqe and args.eqn is None:
        eqs.sort(key=selection._eq_record_auto_dump_key)
    eqs = selection._limit_balanced(
        eqs, args.maxeq, selection._eq_balance_bucket
    )
    show_mask = any(eq.get("mask") is not None for eq in eqs)
    headers = "RDMA_DEV EQN EQ_ADDR EQ_STRUCT ROLE CONS SIZE CQ_CNT EQE VECTOR IRQN IRQ_CPU".split()
    if show_mask:
        headers.append("MASK")
    print(
        "  EQ_ADDR is the EQ structure address. EQ_STRUCT shows which struct it is."
    )
    print("  CQ_CNT is the number of CQs linked to this EQ.")
    table = Table(headers)
    device_labels = _device_display_labels(report)
    for eq in eqs:
        row = [
            _record_device_display(eq, device_labels),
            eq.get("eqn"),
            eq.get("address"),
            _short_struct(eq.get("address_struct")),
            eq.get("role"),
            eq.get("consumer_index"),
            eq.get("size"),
            selection._first_present(eq.get("cq_count"), "-"),
            eq.get("eqe_size"),
            eq.get("vector"),
            eq.get("irqn"),
            selection._first_present(eq.get("irq_cpu"), "-"),
        ]
        if show_mask:
            row.append(selection._first_present(eq.get("mask"), "-"))
        table.row(*row)
    table.write()
    print()


def _render_qps(report: Dict[str, Any], args: argparse.Namespace) -> None:
    print("Queue pairs")
    resolution_warning = _qp_creator_resolution_warning(report)
    if not report.get("qps"):
        print(
            "  No QPs found in the mlx5 QP tables this tool knows how to read."
        )
        if resolution_warning:
            print(f"  {resolution_warning}")
        print()
        return
    print("  MLX5_IB_QP is the struct mlx5_ib_qp address.")
    print(
        "  CREATOR shows who created the QP: kernel, user process, or unresolved."
    )
    print(
        "  SQ/RQ are send/receive queues; PC/CC are producer/consumer counters."
    )
    if resolution_warning:
        print(f"  {resolution_warning}")
    if getattr(args, "qp_creators", None):
        print(f"  filter: creator={', '.join(args.qp_creators)}")
    table = Table(
        "RDMA_DEV QPN HW_QPN MLX5_IB_QP CREATOR QP_TYPE STATE SEND_CQN RECV_CQN "
        "SQ_SZ RQ_SZ SQ_PC SQ_CC RQ_PC RQ_CC".split()
    )
    device_labels = _device_display_labels(report)
    qps = [
        qp
        for qp in report.get("qps", [])
        if selection._qp_matches_filter(qp, args)
    ]
    if args.qpn is not None:
        qps = [
            qp for qp in qps if selection._qp_record_matches_qpn(qp, args.qpn)
        ]
    for qp in selection._limit_items(qps, args.maxqp):
        row = [
            _record_device_display(qp, device_labels),
            qp.get("qpn"),
            qp.get("hw_qpn"),
            qp.get("address"),
            qp.get("creator"),
            qp.get("type_display") or qp.get("type"),
            qp.get("state_display") or qp.get("state"),
            qp.get("send_cqn"),
            qp.get("recv_cqn"),
            qp.get("sq", {}).get("size")
            if isinstance(qp.get("sq"), dict)
            else None,
            qp.get("rq", {}).get("size")
            if isinstance(qp.get("rq"), dict)
            else None,
            qp.get("sq_pc"),
            qp.get("sq_cc"),
            qp.get("rq_pc"),
            qp.get("rq_cc"),
        ]
        table.row(*row)
    table.write()
    print()


def _qp_creator_resolution_warning(report: Dict[str, Any]) -> Optional[str]:
    resolution = report.get("qp_creator_resolution")
    if not isinstance(resolution, dict) or not resolution.get(
        "unresolved_count"
    ):
        return None
    examples = ", ".join(
        f"{item.get('device') or 'mlx5'}/QPN {item.get('qpn')}"
        for item in resolution.get("examples", [])
    )
    suffix = f"; examples: {examples}" if examples else ""
    return (
        "warning: creator could not be determined for "
        f"{resolution.get('unresolved_count')} QP(s){suffix}."
    )


def _render_dumps(report: Dict[str, Any], args: argparse.Namespace) -> None:
    dumps = report.get("dumps", []) or []
    groups: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict(
        (kind, []) for kind in ("cqe", "eqe", "wqe")
    )
    for dump in dumps:
        groups.setdefault(str(dump.get("kind", "descriptor")), []).append(dump)

    device_labels = _device_display_labels(report)
    for kind, group in groups.items():
        if not group:
            continue
        print(DUMP_SEPARATOR)
        print(f"{kind.upper()} dumps")
        print(DUMP_SEPARATOR)
        for line in _dump_group_legend_lines(kind, group):
            print(line)
        print()
        for dump in group:
            _render_one_dump(dump, args, device_labels)


def _render_one_dump(
    dump: Dict[str, Any],
    args: argparse.Namespace,
    device_labels: Optional[Dict[str, str]] = None,
) -> None:
    kind = str(dump.get("kind", "descriptor"))
    entries = dump.get("entries", [])
    print(f"{kind.upper()} dump")
    if kind == "cqe":
        print(f"  {'CQ':<8}: {_cqe_path_display(dump)}")
    else:
        print(
            f"  selector : {dump.get('selector_name', 'id')}={dump.get('selector')}"
        )
    if dump.get("device"):
        for label, value in _dump_device_lines(dump, device_labels or {}):
            print(f"  {label:<8}: {value}")
    if dump.get("consumer_index") is not None:
        print(f"  consumer : {dump.get('consumer_index')}")
    window = dump.get("window")
    if isinstance(window, dict):
        print(
            f"  window   : {window.get('before')} before, {window.get('from_consumer')} from consumer"
        )
    for note in dump.get("notes", []) or []:
        print(f"  note     : {note}")
    if not entries:
        print("  no entries")
        print()
        return
    _render_descriptor_entries(
        dump,
        list(
            selection._limit_items(entries, _descriptor_entry_cap(dump, args))
        ),
    )
    print()


def _cqe_path_display(dump: Dict[str, Any]) -> str:
    raw_cq = dump.get("cq")
    cq: Dict[str, Any] = raw_cq if isinstance(raw_cq, dict) else {}
    cqn = selection._first_present(
        cq.get("cqn"),
        dump.get("selector")
        if dump.get("selector_name") in (None, "cqn")
        else None,
        "-",
    )
    eqn = selection._first_present(cq.get("eqn"), "-")
    irqn = selection._first_present(cq.get("eq_irqn"), cq.get("irqn"), "-")
    irq_cpus = selection._first_present(
        cq.get("eq_irq_cpu"), cq.get("irq_cpu"), "-"
    )
    return f"CQN={cqn} EQN={eqn} IRQN={irqn} CPU={irq_cpus}"


def _dump_device_lines(
    dump: Dict[str, Any], device_labels: Dict[str, str]
) -> List[Tuple[str, Any]]:
    kind = str(dump.get("kind", "descriptor"))
    netdev = None
    device_record = dump
    if kind == "cqe" and isinstance(dump.get("cq"), dict):
        device_record = dump["cq"]
        if _short_struct(
            device_record.get("address_struct")
        ) == "mlx5e_cq" and device_record.get("netdev"):
            netdev = device_record.get("netdev")
    elif kind == "eqe" and isinstance(dump.get("eq"), dict):
        device_record = dump["eq"]
    elif kind == "wqe":
        queue = dump.get("queue")
        if isinstance(queue, dict) and queue.get("netdev"):
            netdev = queue.get("netdev")
        if isinstance(dump.get("qp"), dict):
            device_record = dump["qp"]
    rdma_dev = _record_device_display(device_record, device_labels)
    if netdev and rdma_dev and netdev != rdma_dev:
        return [("netdev", netdev), ("rdma_dev", rdma_dev)]
    if netdev:
        return [("netdev", netdev)]
    if rdma_dev:
        return [("rdma_dev", rdma_dev)]
    return [("device", _record_device_display(dump, device_labels))]


def _is_rq_wqe_dump(dump: Dict[str, Any]) -> bool:
    return dump.get("wqe_kind") == "rq" or (
        dump.get("wqe_kind") is None and dump.get("selector_name") == "rqn"
    )


def _dump_group_legend_lines(
    kind: str, group: Sequence[Dict[str, Any]]
) -> List[str]:
    if kind == "wqe":
        modes = {_is_rq_wqe_dump(dump) for dump in group}
        parts = []
        if False in modes:
            parts.append(
                "SQ/QP WQEs use off_in_bbs=send-ring offset in basic blocks, "
                "OP=WQE opcode, WQE_IDX=WQE counter, QPN=queue pair number, "
                "DS=descriptor segment count, size_op_bbs=WQE size in basic blocks"
            )
        if True in modes:
            parts.append(
                "RQ WQEs use RQ_IDX=receive descriptor slot, BYTE_CNT=buffer length, "
                "LKEY=local memory key, DMA_ADDR=DMA buffer address"
            )
        return [
            (
                "  legend   : WQE rows show decoded work queue ring entries. "
                "If the queue has no outstanding work, entries may be old ring contents."
            ),
            f"  columns  : {'; '.join(parts)}.",
        ]
    if kind not in ("cqe", "eqe"):
        return ["  columns  : decoded descriptor metadata."]

    entries = [
        entry for dump in group for entry in dump.get("entries", []) or []
    ]
    optional_parts: Tuple[Tuple[str, str], ...]
    if kind == "cqe":
        parts = [
            "IDX=CQ ring index",
            "CQE_ADDR=CQE slot address",
            "STATUS=current pollability",
            "OP=CQE opcode",
            "WQE_CTR=completed WQE counter",
            "QPN=queue pair number",
        ]
        optional_parts = (
            ("req_opcode_display", "REQ_OP=request opcode"),
            ("wr_id", "WR_ID=IB work request id"),
            ("byte_count_display", "BYTE_CNT=completed byte count"),
            ("syndrome_display", "SYND=error syndrome"),
        )
        status_line = (
            "  statuses : ready means the CQE is pollable now; not-ready means it is "
            "consumed, owner-mismatched, or an empty INVALID(0xf) sentinel."
        )
    else:
        parts = [
            "IDX=EQ ring index",
            "EQE_ADDR=EQE slot address",
            "STATUS=ownership state",
            "TYPE=event type",
        ]
        optional_parts = (
            ("cqn", "CQN=completion queue number"),
            ("syndrome_display", "SYND=error syndrome"),
        )
        status_line = (
            "  statuses : ready means the kernel owns this entry and can read it; "
            "not-ready means the device still owns it for this pass."
        )
    parts.extend(
        text
        for key, text in optional_parts
        if _entries_have_value(entries, key)
    )
    return [
        "  legend   : IDX* marks the current consumer index.",
        status_line,
        f"  columns  : {', '.join(parts)}.",
    ]


def _render_descriptor_entries(
    dump: Dict[str, Any], entries: List[Dict[str, Any]]
) -> None:
    kind = dump.get("kind")
    if kind == "cqe":
        columns = [
            ("IDX", "index", True, False),
            ("CQE_ADDR", "address", True, False),
            ("STATUS", "status", True, False),
            ("OP", "opcode_display", True, False),
            ("REQ_OP", "req_opcode_display", False, False),
            ("WQE_ID", "wqe_id", False, True),
            ("WQE_CTR", "wqe_counter", True, False),
            ("WR_ID", "wr_id", False, False),
            ("BYTE_CNT", "byte_count_display", False, False),
            ("QPN", "qpn", True, False),
            ("SRQN", "srqn", False, True),
            ("SYND", "syndrome_display", False, False),
            ("VENDOR_SYND", "vendor_err_synd", False, False),
            ("ERR_QPN", "error_qpn", False, False),
        ]
    elif kind == "eqe":
        columns = [
            ("IDX", "index", True, False),
            ("EQE_ADDR", "address", True, False),
            ("STATUS", "status", True, False),
            ("TYPE", "type_display", True, False),
            ("SUBTYPE", "sub_type", False, True),
            ("CQN", "cqn", False, False),
            ("RES_TYPE", "resource_type", False, False),
            ("RES_ID", "resource_id", False, False),
            ("SYND", "syndrome_display", False, False),
            ("FUNC_ID", "func_id", False, False),
            ("NUM_PAGES", "num_pages", False, False),
            ("VPORT", "vport_num", False, False),
            ("MODULE", "module", False, False),
            ("MODULE_STATUS", "module_status", False, False),
            ("OBJ_TYPE", "obj_type", False, False),
            ("OBJ_ID", "obj_id", False, False),
            ("PORT", "port", False, False),
        ]
    elif kind == "wqe" and _is_rq_wqe_dump(dump):
        columns = [
            ("RQ_IDX", "index", True, False),
            ("WQE_ADDR", "address", True, False),
            ("BYTE_CNT", "byte_count", True, False),
            ("LKEY", "lkey", True, False),
            ("DMA_ADDR", "dma_addr", True, False),
        ]
    else:
        columns = [
            ("off_in_bbs", "index", True, False),
            ("WQE_ADDR", "address", True, False),
            ("OP", "opcode_display", True, False),
            ("WQE_IDX", "wqe_index", True, False),
            ("QPN", "qpn", True, False),
            ("DS", "ds", True, False),
            ("size_op_bbs", "wqebbs", True, False),
        ]

    visible = [
        (header, key)
        for header, key, always, nonzero in columns
        if _descriptor_column_visible(entries, key, always, nonzero)
    ]
    table = Table([header for header, _key in visible])
    for entry in entries:
        table.row(*(_descriptor_cell(entry, key) for _header, key in visible))
    table.write()


def _entries_have_value(entries: Sequence[Dict[str, Any]], key: str) -> bool:
    return any(entry.get(key) is not None for entry in entries)


def _is_zeroish(value: Any) -> bool:
    if isinstance(value, (bool, int)):
        return value == 0
    if not isinstance(value, str):
        return False
    text = value.strip().lower()
    if text == "0":
        return True
    if text.startswith("0x"):
        try:
            return int(text, 16) == 0
        except ValueError:
            return False
    return text.endswith("(0x0)") or text.endswith("(0)")


def _descriptor_column_visible(
    entries: Sequence[Dict[str, Any]], key: str, always: bool, nonzero: bool
) -> bool:
    if always:
        return True
    for entry in entries:
        value = entry.get(key)
        if value is not None and (not nonzero or not _is_zeroish(value)):
            return True
    return False


def _descriptor_cell(entry: Dict[str, Any], key: str) -> Any:
    value = entry.get(key)
    if key == "index" and entry.get("consumer_marker"):
        return f"{value}*" if value is not None else "*"
    return "-" if value is None else value


def _render_findings(report: Dict[str, Any], args: argparse.Namespace) -> None:
    findings = report.get("findings", [])
    if not findings:
        return
    print("Findings")
    device_labels = _device_display_labels(report)
    for finding in findings:
        scope = finding.get("scope")
        if scope is not None:
            scope = device_labels.get(str(scope), scope)
        print(
            f"  [{finding.get('severity')}] {scope}: {finding.get('message')}"
        )
    print()


def _render_warnings(report: Dict[str, Any], args: argparse.Namespace) -> None:
    warnings = report.get("warnings", [])
    if not isinstance(warnings, (list, tuple)):
        warnings = [warnings]
    if not warnings:
        return
    print("Collector warnings")
    for warning in warnings:
        print(f"  - {warning}")
    print()


def _max_display(value: Optional[int]) -> str:
    return "all" if value is None else str(value)


def _descriptor_entry_cap(
    dump: Dict[str, Any], args: argparse.Namespace
) -> int:
    kind = dump.get("kind")
    if kind == "cqe":
        return args.maxcqe
    if kind == "eqe":
        return args.maxeqe
    if kind == "wqe":
        return args.maxwqe
    return MAX_DEFAULT_DESCRIPTOR_ENTRIES


def _print_kv_block(
    title: str, data: Dict[str, Any], indent: str = "  "
) -> None:
    print(f"{indent}{title}:")
    for key in sorted(data.keys()):
        if str(key).startswith("_") or str(key).endswith("_source"):
            continue
        print(f"{indent}  {key}: {_display(data[key])}")


def _findings_summary_line(findings: List[Dict[str, str]]) -> str:
    if not findings:
        return "HIGH=0 MED=0 LOW=0"
    counts = Counter(finding.get("severity", "LOW") for finding in findings)
    return f"HIGH={counts['HIGH']} MED={counts['MED']} LOW={counts['LOW']}"
