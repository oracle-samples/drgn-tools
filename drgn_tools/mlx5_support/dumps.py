# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Ring layout and descriptor address helpers for mlx5 dumps."""
from typing import Any
from typing import Dict
from typing import Optional

from drgn import Object

from .format import _hex

_BENIGN_DESCRIPTOR_STATUSES = {"ok", "ready", "not-ready"}


def _dump_window_summary(max_entries: int, ring_size: Any) -> Dict[str, int]:
    count = min(int(max_entries), int(ring_size))
    before = count // 2
    return {"before": before, "from_consumer": count - before}


def _annotate_owner_status(
    decoded: Dict[str, Any],
    absolute_index: int,
    ring_size: int,
    descriptor_kind: str,
    consumer_index: Optional[int] = None,
) -> None:
    owner = int(decoded["owner_bit"])
    expected = (absolute_index // ring_size) & 1
    owner_match = owner == expected

    if descriptor_kind == "cqe" and decoded.get("status") == "ok":
        if consumer_index is not None and absolute_index < consumer_index:
            decoded["status"] = "not-ready"
        elif decoded.get("opcode_value") == 0xF:
            # mlx5_ib initializes empty CQ slots with MLX5_CQE_INVALID (0xf)
            # and checks both the opcode and owner bit before polling.
            decoded["status"] = "not-ready"
        elif not owner_match:
            decoded["status"] = "not-ready"
        else:
            decoded["status"] = "ready"
        return

    if decoded.get("status") == "ok":
        decoded["status"] = "ready" if owner_match else "not-ready"


def _wq_layout_summary(wq: Object) -> Dict[str, Any]:
    fbc = wq.fbc.read_()
    log_stride = int(fbc.log_stride)
    return {
        "wq": _hex(int(wq.address_)),
        "frags": _hex(int(fbc.frags)),
        "sz_m1": int(fbc.sz_m1),
        "stride_bytes": 1 << log_stride,
    }
