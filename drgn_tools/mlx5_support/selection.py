# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Rules for choosing, filtering, and limiting mlx5 report data."""
import argparse
from collections import deque
from collections import OrderedDict
from typing import Any
from typing import Callable
from typing import Deque
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple

from .compat import _safe_int
from .format import _short_struct

DEFAULT_REPORT_MODE = "full"

_EQ_AUTO_DUMP_ROLE_RANK = {"completion": 0, "async": 1, "cmd": 2, "pages": 3}
_EXPLICIT_SECTION_FLAGS = """
queues summary full cqs ib_cqs eth_cqs eqs qps dump_cqe dump_eqe dump_wqe
""".split()
# SQN and RQN select queues only with --dump-wqe, so they do not select a
# report section by themselves.
_EXPLICIT_SELECTORS = "cqn eqn qpn".split()


def _resolve_report_sections(args: argparse.Namespace) -> None:
    if getattr(args, "_report_sections_resolved", False):
        return
    if DEFAULT_REPORT_MODE not in {"full", "summary"}:
        raise ValueError("DEFAULT_REPORT_MODE must be 'full' or 'summary'")
    args._report_sections_resolved = True

    explicit_dump_cqe = bool(getattr(args, "dump_cqe", False))
    explicit_dump_eqe = bool(getattr(args, "dump_eqe", False))
    explicit_dump_wqe = bool(getattr(args, "dump_wqe", False))
    explicit_sections = any(
        bool(getattr(args, name, False)) for name in _EXPLICIT_SECTION_FLAGS
    ) or any(
        getattr(args, name, None) is not None for name in _EXPLICIT_SELECTORS
    )
    if not explicit_sections and DEFAULT_REPORT_MODE == "summary":
        args.summary = True
    full_report = bool(
        getattr(args, "full", False)
        or (not explicit_sections and DEFAULT_REPORT_MODE == "full")
    )
    args._full_report = full_report

    if full_report:
        # Full reports leave table counts uncapped unless --max* is set.
        # Descriptor entries remain limited by --maxcqe, --maxeqe, and
        # --maxwqe.
        for name in "queues cqs eqs qps dump_cqe dump_eqe dump_wqe".split():
            setattr(args, name, True)
        args._auto_select_cqs = not explicit_dump_cqe
        return

    if (
        getattr(args, "ib_cqs", False)
        or getattr(args, "eth_cqs", False)
        or getattr(args, "cqn", None) is not None
        or explicit_dump_cqe
    ):
        args.cqs = True
    if getattr(args, "eqn", None) is not None or explicit_dump_eqe:
        args.eqs = True
    if getattr(args, "qpn", None) is not None:
        args.qps = True
    if explicit_dump_wqe and (
        getattr(args, "sqn", None) is not None
        or getattr(args, "rqn", None) is not None
    ):
        args.queues = True
    args._auto_select_cqs = False


def _wqe_queue_context_keys(
    report: Dict[str, Any], args: argparse.Namespace
) -> Set[Tuple[Optional[str], str, int]]:
    if not args.dump_wqe or args.sqn is not None or args.rqn is not None:
        return set()
    keys: Set[Tuple[Optional[str], str, int]] = set()
    for dump in report.get("dumps", []) or []:
        if dump.get("kind") != "wqe" or dump.get("source") != "queue":
            continue
        selector_name = dump.get("selector_name")
        selector = _safe_int(dump.get("selector"))
        if selector_name not in ("sqn", "rqn") or selector is None:
            continue
        device = dump.get("device")
        keys.add(
            (
                str(device) if device is not None else None,
                str(selector_name),
                selector,
            )
        )
    return keys


def _queue_matches_wqe_selector(
    queue: Dict[str, Any],
    args: argparse.Namespace,
    selected_dump_keys: Optional[Set[Tuple[Optional[str], str, int]]] = None,
    device_name: Optional[str] = None,
) -> bool:
    if not args.dump_wqe:
        return True
    selectors = [
        (name, getattr(args, name))
        for name in ("sqn", "rqn")
        if getattr(args, name) is not None
    ]
    if not selectors and not selected_dump_keys:
        return True
    queue_selector = (
        "rqn" if queue.get("kind") in ("rq", "xskrq", "ptp_rq") else "sqn"
    )
    queue_number = _safe_int(queue.get("number"))
    if not selectors:
        if queue_number is None:
            return False
        assert selected_dump_keys is not None
        device = (
            device_name if device_name is not None else queue.get("device")
        )
        device_key = str(device) if device is not None else None
        return (
            device_key,
            queue_selector,
            queue_number,
        ) in selected_dump_keys or (
            None,
            queue_selector,
            queue_number,
        ) in selected_dump_keys
    return any(
        queue_selector == selector and queue_number == _safe_int(number)
        for selector, number in selectors
    )


def _cq_filter_structs(args: argparse.Namespace) -> List[str]:
    wanted = []
    if getattr(args, "ib_cqs", False):
        wanted.append("mlx5_ib_cq")
    if getattr(args, "eth_cqs", False):
        wanted.append("mlx5e_cq")
    return wanted


def _cq_matches_filter(cq: Dict[str, Any], args: argparse.Namespace) -> bool:
    wanted = _cq_filter_structs(args)
    return not wanted or _short_struct(cq.get("address_struct")) in wanted


def _cq_balance_bucket(cq: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(cq.get("device") or ""),
        str(_short_struct(cq.get("address_struct")) or ""),
        str(cq.get("queue_kind") or cq.get("owner") or ""),
    )


def _qp_matches_filter(qp: Dict[str, Any], args: argparse.Namespace) -> bool:
    wanted = getattr(args, "qp_creators", []) or []
    return not wanted or qp.get("creator_type") in wanted


def _eq_auto_dump_role_rank(eq: Dict[str, Any]) -> int:
    role_text = str(eq.get("role") or "")
    return min(
        (
            rank
            for role, rank in _EQ_AUTO_DUMP_ROLE_RANK.items()
            if role in role_text
        ),
        default=len(_EQ_AUTO_DUMP_ROLE_RANK),
    )


def _eq_item_auto_dump_key(
    item: Tuple[Tuple[str, int], Dict[str, Any]]
) -> Tuple[int, str, int]:
    key, eq = item
    return (_eq_auto_dump_role_rank(eq), key[0], key[1])


def _eq_record_auto_dump_key(eq: Dict[str, Any]) -> Tuple[int, str, int]:
    eqn = _safe_int(eq.get("eqn"))
    return (
        _eq_auto_dump_role_rank(eq),
        str(eq.get("device") or ""),
        eqn if eqn is not None else -1,
    )


def _eq_balance_bucket(eq: Dict[str, Any]) -> Tuple[str, int]:
    return (str(eq.get("device") or ""), _eq_auto_dump_role_rank(eq))


def _queue_balance_bucket(queue: Dict[str, Any]) -> Tuple[str, str]:
    return (
        str(queue.get("netdev") or queue.get("device") or ""),
        str(queue.get("kind") or ""),
    )


def _first_present(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _qp_aliases(*values: Any) -> List[int]:
    aliases: Set[int] = set()
    for value in values:
        number = _safe_int(value)
        if number is not None:
            aliases.add(number)
    return sorted(aliases)


def _qp_record_matches_qpn(record: Dict[str, Any], qpn: Optional[int]) -> bool:
    if qpn is None:
        return True
    target = _safe_int(qpn)
    if target is None:
        return False
    aliases = record.get("qpn_aliases")
    if not isinstance(aliases, list):
        aliases = (
            record.get("qpn"),
            record.get("ib_qpn"),
            record.get("hw_qpn"),
            record.get("table_qpn"),
        )
    return target in map(_safe_int, aliases)


def _limit_items(
    items: Sequence[Any], max_items: Optional[int]
) -> Sequence[Any]:
    return items if max_items is None else items[:max_items]


def _limit_balanced(
    items: Sequence[Any],
    max_items: Optional[int],
    bucket: Callable[[Any], Any],
) -> List[Any]:
    if max_items is None:
        return list(items)
    buckets: "OrderedDict[Any, Deque[Any]]" = OrderedDict()
    for item in items:
        buckets.setdefault(bucket(item), deque()).append(item)

    selected: List[Any] = []
    while buckets and len(selected) < max_items:
        for key, values in list(buckets.items()):
            selected.append(values.popleft())
            if not values:
                buckets.pop(key, None)
            if len(selected) >= max_items:
                break
    return selected


def _channel_queues(ch: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    rq = ch.get("rx_rq")
    if rq:
        yield rq
    for key in ("xsk_rqs", "tx_sqs", "xdp_sqs", "icosqs"):
        yield from ch.get(key, [])
