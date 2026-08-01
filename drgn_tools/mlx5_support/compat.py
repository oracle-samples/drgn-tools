# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""drgn and kernel-version compatibility helpers for mlx5 reports."""
from typing import Any
from typing import Optional

from drgn import FaultError
from drgn import Object
from drgn import ObjectAbsentError

_MEMBER_ERRORS = (
    LookupError,
    FaultError,
    ObjectAbsentError,
    TypeError,
)
_VALUE_ERRORS = (FaultError, ObjectAbsentError, TypeError, ValueError)


def _safe_member(obj: Optional[Object], name: str) -> Optional[Object]:
    if obj is None:
        return None
    try:
        return obj.member_(name)
    except _MEMBER_ERRORS:
        return None


def _safe_int(obj: Any) -> Optional[int]:
    if obj is None:
        return None
    try:
        if isinstance(obj, int):
            return obj
        return int(obj)
    except _VALUE_ERRORS:
        return None


def _addr(obj: Any) -> Optional[int]:
    if obj is None:
        return None
    value = _safe_int(obj)
    if value is not None:
        return value
    return _safe_int(getattr(obj, "address_", None))
