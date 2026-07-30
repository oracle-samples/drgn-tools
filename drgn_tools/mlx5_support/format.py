# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Formatting helpers for the mlx5 Corelens report."""
from typing import Any
from typing import Dict
from typing import Optional
from typing import Tuple


def _hex(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return hex(int(value))


def _enum_name(mapping: Dict[int, str], value: Optional[int]) -> str:
    if value is None:
        return "unavailable"
    return mapping.get(value) or "unknown({})".format(value)


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


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: _jsonable(v)
            for k, v in value.items()
            if not str(k).startswith("_")
        }
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


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
