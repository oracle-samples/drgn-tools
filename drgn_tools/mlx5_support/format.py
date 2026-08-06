# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Formatting helpers for the mlx5 Corelens report."""
from typing import Any
from typing import List
from typing import Optional
from typing import Tuple

from drgn import Object
from drgn import Type
from drgn.helpers.common.format import decode_enum_type_flags


def _hex(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return hex(int(value))


def _strip_enum_prefix(name: str, prefix: str) -> str:
    return name[len(prefix) :] if name.startswith(prefix) else name


def _enum_value_name(
    value: Optional[int], type_: Type, prefix: str = ""
) -> str:
    if value is None:
        return "unavailable"
    enumerators = type_.enumerators
    if enumerators is None:
        raise TypeError("cannot decode incomplete enumerated type")
    names = {
        enum_value: _strip_enum_prefix(name, prefix)
        for name, enum_value in enumerators
        if not prefix or name.startswith(prefix)
    }
    return names.get(value) or "unknown({})".format(value)


def _enum_name(value: Object, prefix: str = "") -> str:
    return _enum_value_name(int(value), value.type_, prefix)


def _enum_flags(value: Optional[int], type_: Type, prefix: str) -> List[str]:
    if value is None:
        return []
    decoded = decode_enum_type_flags(value, type_)
    if decoded == "0":
        return []
    return [_strip_enum_prefix(name, prefix) for name in decoded.split("|")]


def _display(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        return ",".join(_display(v) for v in value)
    return str(value)


def _short_struct(value: Any) -> str:
    if value in (None, "", "unavailable"):
        return "-"
    text = str(value).strip()
    if text.startswith("struct "):
        return text[len("struct ") :]
    return text


def _sort_key(value: Any) -> Tuple[int, Any]:
    return (1, 0) if value is None else (0, value)


def _format_ib_fw_ver(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return _format_fw_revision(
        (value >> 32) & 0xFFFF, (value >> 16) & 0xFFFF, value & 0xFFFF
    )


def _format_fw_revision(
    major: Optional[int], minor: Optional[int], sub: Optional[int]
) -> Optional[str]:
    revision = (major, minor, sub)
    if None in revision or revision in ((0, 0, 0), (0xFFFF, 0xFFFF, 0xFFFF)):
        return None
    return "{}.{}.{}".format(major, minor, sub)


def _format_iseg_fw_revision(
    fw_rev: Optional[int], sub: Optional[int]
) -> Optional[str]:
    if fw_rev is None or sub is None:
        return None
    if fw_rev in (0, 0xFFFFFFFF) or sub == 0xFFFFFFFF:
        return None
    return _format_fw_revision(
        fw_rev & 0xFFFF, (fw_rev >> 16) & 0xFFFF, sub & 0xFFFF
    )
