# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Ring layout and descriptor address helpers for mlx5 dumps."""
from typing import Any
from typing import Dict
from typing import Optional

from drgn import Object

from .compat import _addr
from .compat import _bounded
from .compat import _first_int_path
from .compat import _first_member_path
from .compat import _nonzero_addr
from .compat import _safe_index
from .compat import _safe_int
from .compat import _safe_member
from .compat import _type_name
from .defs import DEFAULT_DESCRIPTOR_ENTRY_BYTES
from .defs import MAX_DESCRIPTOR_ENTRIES
from .defs import MAX_PLAUSIBLE_RING_ENTRIES
from .format import _hex

_BENIGN_DESCRIPTOR_STATUSES = {"ok", "ready", "not-ready", "invalid"}
_DIRECT_BUFFER_PATHS = (
    ["buf"],
    ["frag_buf", "buf"],
    ["fbc", "buf"],
    ["fbc", "frag_buf", "buf"],
)


def _dump_window_summary(
    max_entries: int, ring_size: Optional[Any] = None
) -> Dict[str, int]:
    count = _bounded(max_entries, None, MAX_DESCRIPTOR_ENTRIES)
    size = _safe_int(ring_size)
    if size is not None and size > 0:
        count = min(count, size)
    before = count // 2
    return {"before": before, "from_consumer": count - before}


def _annotate_owner_status(
    decoded: Dict[str, Any],
    absolute_index: int,
    ring_size: Optional[int],
    owner_mode: str,
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

    if owner_mode == "cqe" and decoded.get("status") in (
        "ok",
        "ready",
        "not-ready",
    ):
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

    if not owner_match and decoded.get("status") in ("ok", "ready"):
        decoded["status"] = "not-ready"
    elif owner_match and decoded.get("status") == "ok":
        decoded["status"] = "ready"


def _wq_layout_summary(wq: Optional[Object]) -> Dict[str, Any]:
    if wq is None:
        return {"status": "unavailable"}
    fbc = _safe_member(wq, "fbc")
    if fbc is None:
        fbc = wq
    frags = _safe_member(fbc, "frags")
    frag0 = _safe_index(frags, 0) if frags is not None else None
    frag0_buf = _safe_member(frag0, "buf")
    frags_buf = _safe_member(frags, "buf") if frags is not None else None
    direct = _first_member_path(wq, _DIRECT_BUFFER_PATHS)
    log_stride = _safe_int(_safe_member(fbc, "log_stride"))
    fragbuf_size = _first_int_path(wq, (["size"], ["fbc", "size"]))
    page_shift = _first_int_path(wq, (["page_shift"], ["fbc", "page_shift"]))
    npages = _first_int_path(wq, (["npages"], ["fbc", "npages"]))
    return {
        "wq": _hex(_addr(wq)),
        "wq_type": _type_name(wq),
        "fbc": _hex(_addr(fbc)),
        "fbc_type": _type_name(fbc),
        "frags": _hex(_addr(frags)),
        "frag0": _hex(_addr(frag0)),
        "frag0_buf": _hex(_addr(frag0_buf)),
        "frags_buf": _hex(_addr(frags_buf)),
        "direct": _hex(_addr(direct)),
        "sz_m1": _safe_int(_safe_member(fbc, "sz_m1")),
        "log_sz": _safe_int(_safe_member(fbc, "log_sz")),
        "log_stride": log_stride,
        "stride_bytes": (1 << log_stride)
        if log_stride is not None and 0 <= log_stride < 32
        else None,
        "log_frag_strides": _safe_int(_safe_member(fbc, "log_frag_strides")),
        "frag_sz_m1": _safe_int(_safe_member(fbc, "frag_sz_m1")),
        "strides_offset": _safe_int(_safe_member(fbc, "strides_offset")),
        "fragbuf_npages": npages,
        "fragbuf_size_bytes": fragbuf_size,
        "page_shift": page_shift,
        "cc": _first_int_path(wq, (["cc"], ["cons_index"], ["wqe_ctr"])),
        "computed_size": _ring_size(wq, DEFAULT_DESCRIPTOR_ENTRY_BYTES),
    }


def _ring_size(
    wq: Object, entry_len: int = DEFAULT_DESCRIPTOR_ENTRY_BYTES
) -> Optional[int]:
    sz_m1 = _first_int_path(wq, (["sz_m1"], ["fbc", "sz_m1"], ["wq", "sz_m1"]))
    if sz_m1 is not None:
        return sz_m1 + 1
    log_sz = _first_int_path(wq, (["fbc", "log_sz"], ["log_sz"]))
    if log_sz is not None and 0 <= log_sz < 32:
        return 1 << log_sz
    entry_count = _first_int_path(
        wq, (["sz"], ["wqe_cnt"], ["nentries"], ["num_entries"])
    )
    if entry_count is not None and entry_count > 0:
        return entry_count
    size_bytes = _first_int_path(wq, (["size"], ["frag_buf", "size"]))
    return (
        size_bytes // entry_len
        if size_bytes is not None and size_bytes > 0 and entry_len > 0
        else None
    )


def _same_address(left: Any, right: Any) -> bool:
    left_addr = _addr(left)
    right_addr = _addr(right)
    return left_addr is not None and left_addr == right_addr


def _plausible_cq_wq(wq: Optional[Object]) -> bool:
    if wq is None:
        return False
    size = _ring_size(wq, DEFAULT_DESCRIPTOR_ENTRY_BYTES)
    stride = _ring_stride_bytes(wq)
    if size is None or size <= 0 or size > MAX_PLAUSIBLE_RING_ENTRIES:
        return False
    if stride not in (64, 128):
        return False
    fbc = _safe_member(wq, "fbc")
    if fbc is None:
        fbc = wq
    frags = _safe_member(fbc, "frags")
    return _addr(frags) not in (None, 0)


def _ring_stride_bytes(wq: Object) -> Optional[int]:
    log_stride = _first_int_path(wq, (["log_stride"], ["fbc", "log_stride"]))
    if log_stride is not None and 0 <= log_stride < 32:
        return 1 << log_stride
    stride = _first_int_path(wq, (["stride"], ["stride_bytes"]))
    return stride if stride is not None and stride > 0 else None


def _ring_entry_address(
    wq: Object,
    index: int,
    entry_len: int = DEFAULT_DESCRIPTOR_ENTRY_BYTES,
    cqe_mode: bool = False,
) -> Optional[int]:
    # Do not use Python truthiness for drgn.Object; some structs raise
    # TypeError on bool() to prevent pointer/null mistakes.
    fbc = _safe_member(wq, "fbc")
    if fbc is None:
        fbc = wq

    frags = _safe_member(fbc, "frags")
    if frags is None:
        frag_buf = _first_member_path(wq, (["fbc", "frag_buf"], ["frag_buf"]))
        if frag_buf is not None:
            frags = _safe_member(frag_buf, "frags")

    log_stride = _safe_int(_safe_member(fbc, "log_stride"))
    log_frag_strides = _safe_int(_safe_member(fbc, "log_frag_strides"))
    frag_sz_m1 = _safe_int(_safe_member(fbc, "frag_sz_m1"))
    strides_offset = _safe_int(_safe_member(fbc, "strides_offset")) or 0

    stride = (
        1 << log_stride
        if log_stride is not None and 0 <= log_stride < 32
        else DEFAULT_DESCRIPTOR_ENTRY_BYTES
    )
    cqe_offset = 64 if cqe_mode and stride == 128 else 0

    # Some WQ/CQ/EQ layouts store a direct buffer pointer instead of fbc.frags.
    direct = _first_member_path(wq, _DIRECT_BUFFER_PATHS)
    if frags is None and direct is not None:
        base = _nonzero_addr(direct)
        if base is not None:
            return base + index * stride + cqe_offset

    if frags is None or log_stride is None:
        return _plain_frag_buf_entry_address(wq, index, entry_len)

    if log_frag_strides is None or frag_sz_m1 is None:
        # frags normally points to mlx5_buf_list entries with a .buf pointer.
        # The fragment-list object itself is not descriptor memory.
        frag0 = _safe_index(frags, 0)
        base = _nonzero_addr(_safe_member(frag0, "buf"))
        if base is None:
            base = _nonzero_addr(_safe_member(frags, "buf"))
        if base is None:
            return _plain_frag_buf_entry_address(wq, index, entry_len)
        return base + (index << log_stride) + cqe_offset

    ix = index + strides_offset
    frag_index = ix >> log_frag_strides
    frag = _safe_index(frags, frag_index)
    base = _nonzero_addr(_safe_member(frag, "buf"))
    if base is None:
        return _plain_frag_buf_entry_address(wq, index, entry_len)
    return base + ((frag_sz_m1 & ix) << log_stride) + cqe_offset


def _plain_frag_buf_entry_address(
    frag_buf: Object,
    index: int,
    entry_len: int = DEFAULT_DESCRIPTOR_ENTRY_BYTES,
) -> Optional[int]:
    frags = _safe_member(frag_buf, "frags")
    if frags is None:
        nested = _safe_member(frag_buf, "frag_buf")
        if nested is not None:
            frags = _safe_member(nested, "frags")
            frag_buf = nested
    size_bytes = _safe_int(_safe_member(frag_buf, "size"))
    page_shift = _safe_int(_safe_member(frag_buf, "page_shift"))
    npages = _safe_int(_safe_member(frag_buf, "npages"))

    if (
        frags is None
        or size_bytes is None
        or size_bytes <= 0
        or entry_len <= 0
    ):
        return None
    if page_shift is None or page_shift <= 0:
        return None

    frag_size = 1 << page_shift
    byte_offset = (index * entry_len) % size_bytes
    frag_index, frag_offset = divmod(byte_offset, frag_size)

    if npages is not None and frag_index >= npages:
        return None

    frag = _safe_index(frags, frag_index)
    base = _nonzero_addr(_safe_member(frag, "buf"))
    if base is None and frag_index == 0:
        base = _nonzero_addr(_safe_member(frags, "buf"))
    return base + frag_offset if base is not None else None
