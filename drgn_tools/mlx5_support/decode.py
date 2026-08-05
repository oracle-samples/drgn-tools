# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Descriptor decoders for mlx5 CQE, EQE, and WQE bytes."""
from typing import Any
from typing import Dict
from typing import Optional

from drgn import Object
from drgn import Program

from .format import _hex


def _read_be(raw: bytes, offset: int, size: int) -> Optional[int]:
    end = offset + size
    if len(raw) < end:
        return None
    return int.from_bytes(raw[offset:end], "big")


def _byte(raw: bytes, offset: int) -> Optional[int]:
    return raw[offset] if offset < len(raw) else None


def _be(field: Object) -> int:
    return int.from_bytes(field.to_bytes_(), "big")


def _enum_name(
    prog: Program,
    value: Optional[int],
    *,
    representative: Optional[str] = None,
    type_name: Optional[str] = None,
    prefix: str = "",
) -> Optional[str]:
    if value is None:
        return None
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


def _enum_label(value: Optional[int], name: Optional[str]) -> Optional[str]:
    if value is None or name is None:
        return None
    rendered = _hex(value)
    return rendered if name.startswith("unknown(") else f"{name}({rendered})"


def _enum_type_label(
    prog: Program, value: Optional[int], type_name: str
) -> Optional[str]:
    return _enum_name(prog, value, type_name=type_name)


def _decode_cqe(prog: Program, raw: bytes) -> Dict[str, Any]:
    cqe = Object.from_bytes_(prog, "struct mlx5_cqe64", raw)
    op_own = int(cqe.op_own)
    opcode = op_own >> 4
    opcode_name = _enum_name(
        prog,
        opcode,
        representative="MLX5_CQE_REQ",
        prefix="MLX5_CQE_",
    )
    owner = op_own & 1
    srqn_word = _be(cqe.srqn)
    sop_drop_qpn = _be(cqe.sop_drop_qpn)
    req_opcode = (sop_drop_qpn >> 24) if opcode_name == "REQ" else None
    req_opcode_name = _enum_name(
        prog,
        req_opcode,
        representative="MLX5_OPCODE_NOP",
        prefix="MLX5_OPCODE_",
    )
    byte_count = _be(cqe.byte_cnt)
    byte_count_display = None
    if opcode_name in (
        "RESP_WR_IMM",
        "RESP_SEND",
        "RESP_SEND_IMM",
        "RESP_SEND_INV",
    ) or (opcode_name == "REQ" and req_opcode_name == "RDMA_READ"):
        byte_count_display = byte_count
    decoded = {
        "owner_bit": owner,
        "opcode_value": opcode,
        "opcode_display": _enum_label(opcode, opcode_name),
        "req_opcode_display": _enum_label(req_opcode, req_opcode_name),
        "wqe_id": _be(cqe.wqe_id),
        "srqn": srqn_word & 0xFFFFFF,
        "byte_count_display": byte_count_display,
        "qpn": sop_drop_qpn & 0xFFFFFF,
        "wqe_counter": _be(cqe.wqe_counter),
    }
    if opcode_name in ("SIG_ERR", "REQ_ERR", "RESP_ERR"):
        err_cqe = Object.from_bytes_(prog, "struct mlx5_err_cqe", raw)
        syndrome_value = int(err_cqe.syndrome)
        vendor_syndrome = int(err_cqe.vendor_err_synd)
        error_qpn = _be(err_cqe.s_wqe_opcode_qpn) & 0xFFFFFF
        syndrome_name = _enum_name(
            prog,
            syndrome_value,
            representative="MLX5_CQE_SYNDROME_LOCAL_LENGTH_ERR",
            prefix="MLX5_CQE_SYNDROME_",
        )
        decoded.update(
            {
                "vendor_err_synd": _hex(vendor_syndrome),
                "syndrome": _hex(syndrome_value),
                "syndrome_name": syndrome_name
                if syndrome_name is None
                or not syndrome_name.startswith("unknown(")
                else None,
                "syndrome_display": _enum_label(syndrome_value, syndrome_name),
                "error_qpn": error_qpn,
            }
        )
    return decoded


def _decode_eqe(prog: Program, raw: bytes) -> Dict[str, Any]:
    event_type = _byte(raw, 1)
    event_name = _enum_name(
        prog,
        event_type,
        representative="MLX5_EVENT_TYPE_COMP",
        prefix="MLX5_EVENT_TYPE_",
    )
    sub_type = _byte(raw, 3)
    owner_byte = _byte(raw, 63)
    owner = owner_byte & 1 if owner_byte is not None else None
    decoded = {
        "owner_bit": owner,
        "type_value": event_type,
        "type_display": _enum_label(event_type, event_name),
        "sub_type": _hex(sub_type),
    }
    if event_name == "COMP":
        decoded["cqn"] = _read_be(raw, 56, 4)
    elif event_name == "CQ_ERROR":
        syndrome_value = _byte(raw, 43)
        decoded["cqn"] = _read_be(raw, 32, 4)
        decoded["syndrome"] = _hex(syndrome_value)
        syndrome_name = _enum_name(
            prog,
            syndrome_value,
            representative="MLX5_CQ_ERROR_SYNDROME_CQ_OVERRUN",
            prefix="MLX5_CQ_ERROR_SYNDROME_",
        )
        decoded["syndrome_name"] = (
            syndrome_name
            if syndrome_name is None
            or not syndrome_name.startswith("unknown(")
            else None
        )
        decoded["syndrome_display"] = _enum_label(
            syndrome_value, syndrome_name
        )
    elif event_name in (
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
    ):
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
    opcode_name = _enum_name(
        prog,
        opcode,
        representative="MLX5_OPCODE_NOP",
        prefix="MLX5_OPCODE_",
    )
    return {
        "opcode_display": _enum_label(opcode, opcode_name),
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
