# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Descriptor decoders for mlx5 CQE, EQE, and WQE bytes."""
from typing import Any
from typing import Dict
from typing import Optional

from drgn import Program

from .format import _hex


def _read_be(raw: bytes, offset: int, size: int) -> Optional[int]:
    end = offset + size
    if len(raw) < end:
        return None
    return int.from_bytes(raw[offset:end], "big")


def _byte(raw: bytes, offset: int) -> Optional[int]:
    return raw[offset] if offset < len(raw) else None


def _constant(prog: Program, name: str) -> int:
    return int(prog.constant(name))


def _enum_name(
    prog: Program,
    value: int,
    *,
    representative: Optional[str] = None,
    type_name: Optional[str] = None,
    prefix: str = "",
) -> str:
    key = (representative, type_name, prefix)
    tables = prog.cache.setdefault("_mlx5_enum_tables", {})
    names = tables.get(key)
    if names is None:
        type_ = (
            prog.constant(representative).type_
            if representative is not None
            else prog.type(type_name)
        )
        enumerators = type_.enumerators
        if enumerators is None:
            raise TypeError("cannot decode incomplete enumerated type")
        names = {
            enum_value: (
                name[len(prefix) :]
                if prefix and name.startswith(prefix)
                else name
            )
            for name, enum_value in enumerators
            if not prefix or name.startswith(prefix)
        }
        tables[key] = names
    return names.get(value) or f"unknown({value})"


def _enum_label(
    prog: Program,
    value: Optional[int],
    representative: str,
    prefix: str,
) -> Optional[str]:
    if value is None:
        return None
    name = _enum_name(
        prog, value, representative=representative, prefix=prefix
    )
    rendered = _hex(value)
    return rendered if name.startswith("unknown(") else f"{name}({rendered})"


def _enum_type_label(
    prog: Program, value: Optional[int], type_name: str
) -> Optional[str]:
    if value is None:
        return None
    return _enum_name(prog, value, type_name=type_name)


def _decode_cqe(prog: Program, raw: bytes) -> Dict[str, Any]:
    op_own = _byte(raw, 63)
    opcode = (op_own >> 4) if op_own is not None else None
    owner = (
        op_own & _constant(prog, "MLX5_CQE_OWNER_MASK")
        if op_own is not None
        else None
    )
    srqn_word = _read_be(raw, 32, 4)
    sop_drop_qpn = _read_be(raw, 56, 4)
    req_opcode = (
        (sop_drop_qpn >> 24)
        if opcode == _constant(prog, "MLX5_CQE_REQ")
        and sop_drop_qpn is not None
        else None
    )
    byte_count = _read_be(raw, 44, 4)
    byte_count_display = None
    responder_opcodes = {
        _constant(prog, name)
        for name in (
            "MLX5_CQE_RESP_WR_IMM",
            "MLX5_CQE_RESP_SEND",
            "MLX5_CQE_RESP_SEND_IMM",
            "MLX5_CQE_RESP_SEND_INV",
        )
    }
    if opcode in responder_opcodes:
        byte_count_display = byte_count
    elif opcode == _constant(prog, "MLX5_CQE_REQ") and req_opcode == _constant(
        prog, "MLX5_OPCODE_RDMA_READ"
    ):
        byte_count_display = byte_count
    decoded = {
        "owner_bit": owner,
        "opcode_value": opcode,
        "opcode_display": _enum_label(
            prog, opcode, "MLX5_CQE_REQ", "MLX5_CQE_"
        ),
        "req_opcode_display": _enum_label(
            prog, req_opcode, "MLX5_OPCODE_NOP", "MLX5_OPCODE_"
        ),
        "wqe_id": _read_be(raw, 2, 2),
        "srqn": (srqn_word & 0xFFFFFF) if srqn_word is not None else None,
        "byte_count_display": byte_count_display,
        "qpn": (sop_drop_qpn & 0xFFFFFF) if sop_drop_qpn is not None else None,
        "wqe_counter": _read_be(raw, 60, 2),
    }
    error_opcodes = {
        _constant(prog, name)
        for name in (
            "MLX5_CQE_SIG_ERR",
            "MLX5_CQE_REQ_ERR",
            "MLX5_CQE_RESP_ERR",
        )
    }
    if opcode in error_opcodes:
        syndrome_value = _byte(raw, 55)
        vendor_syndrome = _byte(raw, 54)
        syndrome_name = (
            _enum_name(
                prog,
                syndrome_value,
                representative="MLX5_CQE_SYNDROME_LOCAL_LENGTH_ERR",
                prefix="MLX5_CQE_SYNDROME_",
            )
            if syndrome_value is not None
            else None
        )
        decoded.update(
            {
                "vendor_err_synd": _hex(vendor_syndrome),
                "syndrome": _hex(syndrome_value),
                "syndrome_name": syndrome_name
                if syndrome_name is None
                or not syndrome_name.startswith("unknown(")
                else None,
                "syndrome_display": _enum_label(
                    prog,
                    syndrome_value,
                    "MLX5_CQE_SYNDROME_LOCAL_LENGTH_ERR",
                    "MLX5_CQE_SYNDROME_",
                ),
                "error_qpn": (sop_drop_qpn & 0xFFFFFF)
                if sop_drop_qpn is not None
                else None,
            }
        )
    return decoded


def _decode_eqe(prog: Program, raw: bytes) -> Dict[str, Any]:
    event_type = _byte(raw, 1)
    event_name = (
        _enum_name(
            prog,
            event_type,
            representative="MLX5_EVENT_TYPE_COMP",
            prefix="MLX5_EVENT_TYPE_",
        )
        if event_type is not None
        else None
    )
    sub_type = _byte(raw, 3)
    owner_byte = _byte(raw, 63)
    owner = (
        owner_byte & _constant(prog, "MLX5_CQE_OWNER_MASK")
        if owner_byte is not None
        else None
    )
    decoded = {
        "owner_bit": owner,
        "type_value": event_type,
        "type_display": _enum_label(
            prog, event_type, "MLX5_EVENT_TYPE_COMP", "MLX5_EVENT_TYPE_"
        ),
        "sub_type": _hex(sub_type),
    }
    if event_name == "COMP":
        decoded["cqn"] = _read_be(raw, 56, 4)
    elif event_name == "CQ_ERROR":
        syndrome_value = _byte(raw, 43)
        decoded["cqn"] = _read_be(raw, 32, 4)
        decoded["syndrome"] = _hex(syndrome_value)
        syndrome_name = (
            _enum_name(
                prog,
                syndrome_value,
                representative="MLX5_CQ_ERROR_SYNDROME_CQ_OVERRUN",
                prefix="MLX5_CQ_ERROR_SYNDROME_",
            )
            if syndrome_value is not None
            else None
        )
        decoded["syndrome_name"] = (
            syndrome_name
            if syndrome_name is None
            or not syndrome_name.startswith("unknown(")
            else None
        )
        decoded["syndrome_display"] = _enum_label(
            prog,
            syndrome_value,
            "MLX5_CQ_ERROR_SYNDROME_CQ_OVERRUN",
            "MLX5_CQ_ERROR_SYNDROME_",
        )
    elif event_name in {
        "PATH_MIG",
        "COMM_EST",
        "SQ_DRAINED",
        "WQ_CATAS_ERROR",
        "PATH_MIG_FAILED",
        "WQ_INVAL_REQ_ERROR",
        "WQ_ACCESS_ERROR",
        "SRQ_CATAS_ERROR",
        "SRQ_LAST_WQE",
        "SRQ_RQ_LIMIT",
    }:
        decoded["resource_type"] = _hex(_byte(raw, 52))
        decoded["resource_id"] = _read_be(raw, 56, 4)
    elif event_name == "PAGE_REQUEST":
        decoded["func_id"] = _read_be(raw, 34, 2)
        decoded["num_pages"] = _read_be(raw, 36, 4)
    elif event_name == "NIC_VPORT_CHANGE":
        decoded["vport_num"] = _read_be(raw, 34, 2)
    elif event_name == "VHCA_STATE_CHANGE":
        decoded["func_id"] = _read_be(raw, 34, 2)
    elif event_name == "PORT_MODULE_EVENT":
        decoded["module"] = _byte(raw, 33)
        decoded["module_status"] = _hex(_byte(raw, 35))
    elif event_name == "OBJECT_CHANGE":
        decoded["obj_type"] = _hex(_read_be(raw, 34, 2))
        decoded["obj_id"] = _read_be(raw, 36, 4)
    if event_name == "PORT_CHANGE":
        decoded["port"] = _byte(raw, 40)
    return decoded


def _decode_wqe(prog: Program, raw: bytes) -> Dict[str, Any]:
    opmod_idx_opcode = _read_be(raw, 0, 4)
    qpn_ds = _read_be(raw, 4, 4)
    opcode = opmod_idx_opcode & 0xFF if opmod_idx_opcode is not None else None
    wqe_index = (
        (opmod_idx_opcode >> 8) & 0xFFFF
        if opmod_idx_opcode is not None
        else None
    )
    qpn = qpn_ds >> 8 if qpn_ds is not None else None
    ds = qpn_ds & 0x3F if qpn_ds is not None else None
    return {
        "opcode_display": _enum_label(
            prog, opcode, "MLX5_OPCODE_NOP", "MLX5_OPCODE_"
        ),
        "wqe_index": wqe_index,
        "qpn": qpn,
        "ds": ds,
    }


def _decode_rq_wqe(raw: bytes, linked: bool = False) -> Dict[str, Any]:
    data_offset = 16 if linked else 0
    return {
        "byte_count": _read_be(raw, data_offset, 4),
        "lkey": _hex(_read_be(raw, data_offset + 4, 4)),
        "dma_addr": _hex(_read_be(raw, data_offset + 8, 8)),
    }
