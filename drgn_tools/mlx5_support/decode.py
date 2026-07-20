# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Descriptor decoders for mlx5 CQE, EQE, and WQE bytes."""
from typing import Any
from typing import Dict
from typing import Optional

from .defs import _MLX5_CQ_ERROR_SYNDROME
from .defs import _MLX5_CQE_BYTE_COUNT_REQ_OPCODES
from .defs import _MLX5_CQE_ERROR_OPCODES
from .defs import _MLX5_CQE_OPCODE
from .defs import _MLX5_CQE_RESPONDER_OPCODES
from .defs import _MLX5_CQE_SYNDROME
from .defs import _MLX5_EQE_QP_SRQ_TYPES
from .defs import _MLX5_EQE_TYPE
from .defs import _MLX5_WQE_OPCODE
from .format import _hex


def _read_be(raw: bytes, offset: int, size: int) -> Optional[int]:
    end = offset + size
    if len(raw) < end:
        return None
    return int.from_bytes(raw[offset:end], "big")


def _byte(raw: bytes, offset: int) -> Optional[int]:
    return raw[offset] if offset < len(raw) else None


def _hex_label(value: Optional[int], names: Dict[int, str]) -> Optional[str]:
    if value is None:
        return None
    value = int(value)
    name = names.get(value)
    rendered = _hex(value)
    return f"{name}({rendered})" if name else rendered


def _enum_table_label(
    value: Optional[int], names: Dict[int, str]
) -> Optional[str]:
    if value is None:
        return None
    value = int(value)
    return names.get(value) or f"unknown({value})"


def _decode_cqe(raw: bytes) -> Dict[str, Any]:
    op_own = _byte(raw, 63)
    opcode = (op_own >> 4) if op_own is not None else None
    owner = (op_own & 0x1) if op_own is not None else None
    srqn_word = _read_be(raw, 32, 4)
    sop_drop_qpn = _read_be(raw, 56, 4)
    req_opcode = (
        (sop_drop_qpn >> 24)
        if opcode == 0x0 and sop_drop_qpn is not None
        else None
    )
    byte_count = _read_be(raw, 44, 4)
    byte_count_display = None
    if opcode in _MLX5_CQE_RESPONDER_OPCODES:
        byte_count_display = byte_count
    elif opcode == 0x0 and req_opcode in _MLX5_CQE_BYTE_COUNT_REQ_OPCODES:
        byte_count_display = byte_count
    decoded = {
        "owner_bit": owner,
        "opcode_value": opcode,
        "opcode_display": _hex_label(opcode, _MLX5_CQE_OPCODE),
        "req_opcode_display": _hex_label(req_opcode, _MLX5_WQE_OPCODE),
        "wqe_id": _read_be(raw, 2, 2),
        "srqn": (srqn_word & 0xFFFFFF) if srqn_word is not None else None,
        "byte_count_display": byte_count_display,
        "qpn": (sop_drop_qpn & 0xFFFFFF) if sop_drop_qpn is not None else None,
        "wqe_counter": _read_be(raw, 60, 2),
    }
    if opcode in _MLX5_CQE_ERROR_OPCODES:
        syndrome_value = _byte(raw, 55)
        vendor_syndrome = _byte(raw, 54)
        decoded.update(
            {
                "vendor_err_synd": _hex(vendor_syndrome),
                "syndrome": _hex(syndrome_value),
                "syndrome_name": _MLX5_CQE_SYNDROME.get(syndrome_value)
                if syndrome_value is not None
                else None,
                "syndrome_display": _hex_label(
                    syndrome_value, _MLX5_CQE_SYNDROME
                ),
                "error_qpn": (sop_drop_qpn & 0xFFFFFF)
                if sop_drop_qpn is not None
                else None,
            }
        )
    return decoded


def _decode_eqe(raw: bytes) -> Dict[str, Any]:
    event_type = _byte(raw, 1)
    sub_type = _byte(raw, 3)
    owner_byte = _byte(raw, 63)
    owner = owner_byte & 0x1 if owner_byte is not None else None
    decoded = {
        "owner_bit": owner,
        "type_value": event_type,
        "type_display": _hex_label(event_type, _MLX5_EQE_TYPE),
        "sub_type": _hex(sub_type),
    }
    if event_type == 0x0:
        decoded["cqn"] = _read_be(raw, 56, 4)
    elif event_type == 0x4:
        syndrome_value = _byte(raw, 43)
        decoded["cqn"] = _read_be(raw, 32, 4)
        decoded["syndrome"] = _hex(syndrome_value)
        decoded["syndrome_name"] = (
            _MLX5_CQ_ERROR_SYNDROME.get(syndrome_value)
            if syndrome_value is not None
            else None
        )
        decoded["syndrome_display"] = _hex_label(
            syndrome_value, _MLX5_CQ_ERROR_SYNDROME
        )
    elif event_type in _MLX5_EQE_QP_SRQ_TYPES:
        decoded["resource_type"] = _hex(_byte(raw, 52))
        decoded["resource_id"] = _read_be(raw, 56, 4)
    elif event_type == 0xB:
        decoded["func_id"] = _read_be(raw, 34, 2)
        decoded["num_pages"] = _read_be(raw, 36, 4)
    elif event_type == 0xD:
        decoded["vport_num"] = _read_be(raw, 34, 2)
    elif event_type == 0xF:
        decoded["func_id"] = _read_be(raw, 34, 2)
    elif event_type == 0x16:
        decoded["module"] = _byte(raw, 33)
        decoded["module_status"] = _hex(_byte(raw, 35))
    elif event_type == 0x27:
        decoded["obj_type"] = _hex(_read_be(raw, 34, 2))
        decoded["obj_id"] = _read_be(raw, 36, 4)
    if event_type == 0x9:
        decoded["port"] = _byte(raw, 40)
    return decoded


def _decode_wqe(raw: bytes) -> Dict[str, Any]:
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
        "opcode_display": _hex_label(opcode, _MLX5_WQE_OPCODE),
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
