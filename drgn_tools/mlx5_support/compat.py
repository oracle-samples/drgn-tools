# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""drgn and kernel-version compatibility helpers for mlx5 reports."""
from typing import Any
from typing import Callable
from typing import Iterable
from typing import Optional
from typing import Sequence
from typing import Tuple

from drgn import FaultError
from drgn import Object
from drgn import ObjectAbsentError
from drgn import OutOfBoundsError
from drgn import TypeKind

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


def _safe_member_path(
    obj: Optional[Object], path: Sequence[str]
) -> Optional[Object]:
    cur = obj
    for member in path:
        cur = _safe_member(cur, member)
    return cur


def _first_path_value(
    obj: Optional[Object],
    paths: Iterable[Tuple[Optional[str], Sequence[str]]],
    convert: Callable[[Any], Any],
) -> Tuple[Any, Optional[str]]:
    for source, path in paths:
        value = convert(_safe_member_path(obj, path))
        if value is not None:
            return value, source
    return None, None


def _first_member_path(
    obj: Optional[Object], paths: Sequence[Sequence[str]]
) -> Optional[Object]:
    return _first_path_value(
        obj, ((None, path) for path in paths), lambda value: value
    )[0]


def _safe_index(obj: Optional[Object], index: int) -> Optional[Object]:
    if obj is None:
        return None
    try:
        value = obj[index]
        if isinstance(value, Object) and value.type_.kind == TypeKind.POINTER:
            if _is_null(value):
                return None
            try:
                return value.read_()
            except (FaultError, ObjectAbsentError):
                return value
        return value
    except (FaultError, ObjectAbsentError, OutOfBoundsError, TypeError):
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


def _first_int_path(
    obj: Optional[Object], paths: Sequence[Sequence[str]]
) -> Optional[int]:
    return _first_path_value(obj, ((None, path) for path in paths), _safe_int)[
        0
    ]


def _addr(obj: Any) -> Optional[int]:
    if obj is None:
        return None
    value = _safe_int(obj)
    if value is not None:
        return value
    return _safe_int(getattr(obj, "address_", None))


def _nonzero_addr(obj: Any) -> Optional[int]:
    return _addr(obj) or None


def _is_null(obj: Optional[Object]) -> bool:
    return obj is None or _addr(obj) == 0


def _type_name(obj: Optional[Object]) -> Optional[str]:
    return str(obj.type_) if obj is not None else None
