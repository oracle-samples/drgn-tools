# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Ring layout and descriptor address helpers for mlx5 dumps."""
from typing import Any
from typing import Dict
from typing import Optional
from typing import Tuple

from drgn import FaultError
from drgn import Object
from drgn import ObjectAbsentError
from drgn import OutOfBoundsError

from .compat import _addr
from .compat import _safe_int
from .compat import _safe_member
from .defs import MAX_DESCRIPTOR_ENTRIES
from .format import _hex

_BENIGN_DESCRIPTOR_STATUSES = {"ok", "ready", "not-ready"}


def _dump_window_summary(
    max_entries: int, ring_size: Optional[Any] = None
) -> Dict[str, int]:
    count = max(0, min(int(max_entries), MAX_DESCRIPTOR_ENTRIES))
    size = _safe_int(ring_size)
    if size is not None and size > 0:
        count = min(count, size)
    before = count // 2
    return {"before": before, "from_consumer": count - before}


def _annotate_owner_status(
    decoded: Dict[str, Any],
    absolute_index: int,
    ring_size: Optional[int],
    descriptor_kind: str,
    consumer_index: Optional[int] = None,
) -> None:
    owner = _safe_int(decoded.get("owner_bit"))
    if owner is None or ring_size is None or ring_size <= 0:
        return
    expected = (absolute_index // ring_size) & 1
    owner_match = owner == expected
    decoded["expected_owner"] = expected
    decoded["owner_match"] = owner_match
    # Kept for JSON compatibility. This is only the owner-bit comparison, not
    # whether the CQE can be polled.
    decoded["owner_ready"] = owner_match

    if descriptor_kind == "cqe" and decoded.get("status") == "ok":
        if consumer_index is not None and absolute_index < consumer_index:
            decoded["status"] = "not-ready"
            decoded["not_ready_reason"] = "consumed"
        elif decoded.get("opcode_value") == 0xF:
            # mlx5_ib initializes empty CQ slots with MLX5_CQE_INVALID (0xf)
            # and checks both the opcode and owner bit before polling.
            decoded["status"] = "not-ready"
            decoded["not_ready_reason"] = "invalid-sentinel"
        elif not owner_match:
            decoded["status"] = "not-ready"
            decoded["not_ready_reason"] = "owner-mismatch"
        else:
            decoded["status"] = "ready"
            decoded.pop("not_ready_reason", None)
        return

    if decoded.get("status") == "ok":
        decoded["status"] = "ready" if owner_match else "not-ready"


def _wq_layout_summary(wq: Optional[Object]) -> Dict[str, Any]:
    if wq is None:
        return {"status": "unavailable"}
    fbc_ref, fbc = _read_fbc(wq)
    summary: Dict[str, Any] = {
        "wq": _hex(_addr(wq)),
        "wq_type": str(wq.type_),
        "fbc": _hex(_addr(fbc_ref)),
    }
    if fbc is None:
        summary["status"] = "unavailable"
        return summary
    frags = _safe_member(fbc, "frags")
    log_stride = _safe_int(_safe_member(fbc, "log_stride"))
    summary.update(
        {
            "frags": _hex(_addr(frags)),
            "frag0_buf": _hex(_fragment_base(frags, 0)),
            "sz_m1": _safe_int(_safe_member(fbc, "sz_m1")),
            "log_sz": _safe_int(_safe_member(fbc, "log_sz")),
            "log_stride": log_stride,
            "stride_bytes": (1 << log_stride)
            if log_stride is not None and 0 <= log_stride < 32
            else None,
            "log_frag_strides": _safe_int(
                _safe_member(fbc, "log_frag_strides")
            ),
            "frag_sz_m1": _safe_int(_safe_member(fbc, "frag_sz_m1")),
            "strides_offset": _safe_int(_safe_member(fbc, "strides_offset")),
        }
    )
    return summary


def _read_fbc(wq: Object) -> Tuple[Optional[Object], Optional[Object]]:
    """Return the FBC reference and one cached read of its value."""

    fbc_ref = _safe_member(wq, "fbc")
    if fbc_ref is None:
        return None, None
    try:
        return fbc_ref, fbc_ref.read_()
    except (FaultError, ObjectAbsentError, TypeError):
        return fbc_ref, None


def _fragment_base(frags: Optional[Object], index: int) -> Optional[int]:
    if frags is None:
        return None
    try:
        return int(frags[index].buf) or None
    except (
        FaultError,
        ObjectAbsentError,
        OutOfBoundsError,
        LookupError,
        TypeError,
        ValueError,
    ):
        return None
