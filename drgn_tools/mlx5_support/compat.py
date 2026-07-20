# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""drgn and kernel-version compatibility helpers for mlx5 reports."""
from importlib import import_module
from typing import Any
from typing import Callable
from typing import Iterable
from typing import Iterator
from typing import Optional
from typing import Sequence
from typing import Tuple

from drgn import container_of
from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn import sizeof
from drgn import TypeKind

try:
    from drgn import ObjectAbsentError, OutOfBoundsError
except ImportError:  # pragma: no cover - older drgn compatibility
    ObjectAbsentError = FaultError  # type: ignore
    OutOfBoundsError = FaultError  # type: ignore


def _optional_helper(module: str, name: str) -> Any:
    try:
        return getattr(import_module(module), name)
    except (ImportError, AttributeError):
        return None


for_each_netdev = _optional_helper("drgn.helpers.linux.net", "for_each_netdev")
netdev_name = _optional_helper("drgn.helpers.linux.net", "netdev_name")
netdev_priv = _optional_helper("drgn.helpers.linux.net", "netdev_priv")
list_for_each_entry = _optional_helper(
    "drgn.helpers.linux.list", "list_for_each_entry"
)
idr_for_each = _optional_helper("drgn.helpers.linux.idr", "idr_for_each")
irq_to_desc = _optional_helper("drgn.helpers.linux.irq", "irq_to_desc")
cpumask_to_cpulist = _optional_helper(
    "drgn.helpers.linux.cpumask", "cpumask_to_cpulist"
)
radix_tree_for_each = _optional_helper(
    "drgn.helpers.linux.radixtree", "radix_tree_for_each"
)
xa_for_each = _optional_helper("drgn.helpers.linux.xarray", "xa_for_each")

_HELPER_DEFAULT = object()
_MEMBER_ERRORS = (
    LookupError,
    FaultError,
    ObjectAbsentError,
    OutOfBoundsError,
    AttributeError,
    TypeError,
    ValueError,
)


def _safe_iter(
    factory: Callable[[], Iterable[Any]],
    warn: Callable[[str], None],
    what: str,
) -> Iterator[Any]:
    try:
        yield from factory()
    except (FaultError, ObjectAbsentError, OutOfBoundsError) as err:
        warn("fault while {}: {}".format(what, err))
    except Exception as err:  # pylint: disable=broad-except
        warn("failed while {}: {}".format(what, err))


def _for_each_netdev_compat(
    prog: Program,
    for_each_netdev_helper: Any = _HELPER_DEFAULT,
    list_for_each_entry_helper: Any = _HELPER_DEFAULT,
) -> Iterable[Object]:
    if for_each_netdev_helper is _HELPER_DEFAULT:
        for_each_netdev_helper = for_each_netdev
    if list_for_each_entry_helper is _HELPER_DEFAULT:
        list_for_each_entry_helper = list_for_each_entry
    if for_each_netdev_helper is not None:
        return for_each_netdev_helper(prog)
    if list_for_each_entry_helper is None:
        raise RuntimeError("list_for_each_entry is unavailable")
    net = prog["init_net"]
    head = _safe_member(net, "dev_base_head")
    if head is None:
        raise RuntimeError("init_net.dev_base_head is unavailable")
    return list_for_each_entry_helper(
        "struct net_device", head.address_of_(), "dev_list"
    )


def _safe_member(obj: Optional[Object], name: str) -> Optional[Object]:
    if obj is None:
        return None
    try:
        return obj.member_(name)
    except _MEMBER_ERRORS:
        return None


def _safe_pointer(
    prog: Program, type_name: str, address: Optional[int]
) -> Optional[Object]:
    if address is None:
        return None
    try:
        return Object(prog, type_name, value=address)
    except Exception:
        return None


def _safe_container_of(
    obj: Optional[Object], type_name: str, member: str
) -> Optional[Object]:
    try:
        return container_of(obj, type_name, member)
    except Exception:
        return None


def _safe_member_path(
    obj: Optional[Object], path: Sequence[str]
) -> Optional[Object]:
    cur = obj
    for member in path:
        cur = _safe_member(cur, member)
        if cur is None:
            return None
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


def _first_member_path_with_source(
    obj: Optional[Object],
    paths: Sequence[Tuple[str, Sequence[str]]],
) -> Tuple[Optional[Object], Optional[str]]:
    return _first_path_value(obj, paths, lambda value: value)


def _safe_index(obj: Optional[Object], index: int) -> Optional[Object]:
    if obj is None:
        return None
    try:
        value = obj[index]
        if _is_pointer_object(value):
            if _is_null(value):
                return None
            try:
                return value.read_()
            except Exception:
                return value
        return value
    except Exception:
        return None


def _safe_array_int(obj: Optional[Object], index: int) -> Optional[int]:
    if obj is None:
        return None
    try:
        return _safe_int(obj[index])
    except Exception:
        return None


def _safe_index_or_self(obj: Optional[Object], index: int) -> Optional[Object]:
    if obj is None:
        return None
    # Index 0 may refer to a single struct rather than an array.
    if (
        index == 0
        and _addr(obj) is not None
        and _safe_int(_safe_member(obj, "sqn")) is not None
    ):
        return obj
    return _safe_index(obj, index)


def _safe_int(obj: Any) -> Optional[int]:
    if obj is None:
        return None
    try:
        if isinstance(obj, int):
            return obj
        if hasattr(obj, "value_"):
            return int(obj.value_())
        return int(obj)
    except (
        FaultError,
        ObjectAbsentError,
        OutOfBoundsError,
        AttributeError,
        TypeError,
        ValueError,
    ):
        return None


def _bounded(
    value: int, requested_limit: Optional[int], hard_limit: int
) -> int:
    limits = [int(value), int(hard_limit)]
    if requested_limit is not None:
        limits.append(int(requested_limit))
    return max(0, min(limits))


def _sizeof_type(prog: Program, type_name: str) -> Optional[int]:
    try:
        return int(sizeof(prog.type(type_name)))
    except Exception:
        return None


def _first_int_path(
    obj: Optional[Object], paths: Sequence[Sequence[str]]
) -> Optional[int]:
    return _first_path_value(obj, ((None, path) for path in paths), _safe_int)[
        0
    ]


def _first_int_path_with_source(
    obj: Optional[Object],
    paths: Sequence[Tuple[str, Sequence[str]]],
) -> Tuple[Optional[int], Optional[str]]:
    return _first_path_value(obj, paths, _safe_int)


def _safe_cstr(obj: Any) -> Optional[str]:
    if obj is None:
        return None
    try:
        if hasattr(obj, "string_"):
            return obj.string_().decode("utf-8", "replace").rstrip("\x00")
    except Exception:
        pass
    try:
        if isinstance(obj, (bytes, bytearray)):
            return bytes(obj).split(b"\x00", 1)[0].decode("utf-8", "replace")
    except Exception:
        pass
    return None


def _addr(obj: Any) -> Optional[int]:
    if obj is None:
        return None
    value = _safe_int(obj)
    if value is not None:
        return value
    try:
        addr = getattr(obj, "address_", None)
        return _safe_int(addr() if callable(addr) else addr)
    except Exception:
        return None


def _nonzero_addr(obj: Any) -> Optional[int]:
    return _addr(obj) or None


def _is_null(obj: Optional[Object]) -> bool:
    return obj is None or _addr(obj) == 0


def _object_type_name(obj: Any) -> Optional[str]:
    try:
        return obj.type_.type_name()
    except Exception:
        return None


def _is_pointer_object(obj: Any) -> bool:
    try:
        return obj.type_.kind == TypeKind.POINTER
    except Exception:
        type_name = _object_type_name(obj)
        return bool(type_name and type_name.rstrip().endswith("*"))


def _type_name(obj: Optional[Object]) -> Optional[str]:
    if obj is None:
        return None
    try:
        return str(obj.type_)
    except Exception:
        try:
            return str(obj.type_())
        except Exception:
            return None


def _struct_type_name(obj: Optional[Object]) -> Optional[str]:
    type_name = _object_type_name(obj) or _type_name(obj)
    if type_name is None:
        return None
    type_name = str(type_name).strip()
    while type_name.endswith("*"):
        type_name = type_name[:-1].strip()
    if type_name.startswith("const "):
        type_name = type_name[len("const ") :].strip()
    return type_name or None


def _read_memory(prog: Program, addr: int, length: int) -> Optional[bytes]:
    try:
        return prog.read(addr, length)
    except Exception:
        return None
