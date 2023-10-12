# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import sys
import time
import typing as t
from contextlib import contextmanager
from urllib.request import urlopen

from drgn import NULL
from drgn import Object
from drgn import Program
from drgn import sizeof
from drgn.helpers.common.format import decode_enum_type_flags
from drgn.helpers.linux.cpumask import for_each_cpu
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.percpu import per_cpu

try:
    # drgn v0.21.0+
    from drgn.helpers.common import escape_ascii_string
except ImportError:
    # drgn <v0.21.0
    from drgn.helpers import escape_ascii_string


def get_uts(prog: Program) -> t.Dict[str, str]:
    """
    Get system and version info

    :returns: dict of uts data
    """

    def uts_to_string(s):
        return escape_ascii_string(s.string_(), escape_backslash=True)

    uts = {}
    uts_obj = prog["init_uts_ns"].name

    uts["sysname"] = uts_to_string(uts_obj.sysname)
    uts["nodename"] = uts_to_string(uts_obj.nodename)
    uts["release"] = uts_to_string(uts_obj.release)
    uts["version"] = uts_to_string(uts_obj.version)
    uts["machine"] = uts_to_string(uts_obj.machine)
    uts["domainname"] = uts_to_string(uts_obj.domainname)

    return uts


def has_member(obj: Object, name: str) -> bool:
    """
    Return true if a given object has a member with the given name.
    :param obj: Drgn object to check
    :param name: string member name to check
    :returns: whether the object has a member by that name
    """
    try:
        obj.member_(name)
        return True
    except LookupError:
        return False


def type_exists(prog: Program, type_: str) -> bool:
    """
    Check whether some type exists in drgn

    :param prog: drgn program
    :param type_: type name
    :returns: true if exist, otherwise false
    """
    try:
        prog.type(type_)
        return True
    except LookupError:
        return False


@contextmanager
def redirect_stdout(
    filename: str, append: bool = False
) -> t.Iterator[t.TextIO]:
    """
    Redirect standard output to a file within the body of the context manager

    This context manager is a safe way to run code and capture its results in a
    new file. Here's how to use it properly:

    >>> with redirect_stdout("myfile.txt"):
            print("hello world")

    In the above example, the file ``myfile.txt`` will now contain the string
    "hello world\\n".

    :param filename: Name of the file to redirect to.
    :param append: Set this to true when you want to append, like the ``>>``
        operator. Default is false.
    :returns: A context manager which yields the new stdout file
    """
    mode = "a" if append else "w"
    with open(filename, mode) as f:
        f = t.cast(t.TextIO, f)
        sys.stdout = f
        try:
            yield f
        finally:
            sys.stdout = sys.__stdout__


def enum_name_get(
    enum: t.Type, value: t.Any, default: t.Optional[str] = None
) -> t.Optional[str]:
    """
    Given an enum class and a value, return its name, or a default.

    :param enum: the :py:class:`enum.Enum` type
    :param value: a value which is the same type as the enum values
    :param default: a string to use when not found
    :returns: The string name, or else the value of default
    """
    for enumerator in enum:
        if enumerator.value == value:
            return enumerator.name
    return default


def enum_flags_str(prog: Program, t: str, flags: int) -> str:
    """
    Convert enum flag bit to string

    :param prog: drgn program
    :param t: enum type as string
    :param flags: flags to be decoded
    :returns: enum bit string or hex mode of 'param flags' if 'param t' doesn't exist
    """
    if not type_exists(prog, t):
        return hex(flags)
    else:
        return decode_enum_type_flags(flags, prog.type(t))


def percpu_ref_sum(prog: Program, ref: Object) -> int:
    """
    Get the sum of percpu reference count from ``struct percpu_ref``

    :param prog: drgn Program
    :param ref: ``struct percpu_ref``
    :returns: sum of the percpu reference count
    """
    ptr = ref.percpu_count_ptr
    atomic_count = ref.count if has_member(ref, "count") else ref.data.count
    # Last two bits of ptr is uses as flags, not in percpu mode if any bit set.
    # PERCPU_COUNT_BIAS = (1LU << (BITS_PER_LONG - 1)) was set to counter
    # in percpu mode.
    bits_per_long = prog.type("long").size * 8
    PERCPU_COUNT_BIAS = 1 << (bits_per_long - 1)
    counter = atomic_count.counter & ~PERCPU_COUNT_BIAS
    if ptr & 0x3 != 0 or ptr == 0:
        return counter
    percpu = Object(prog, "unsigned long", address=ptr)
    for cpu in for_each_possible_cpu(prog):
        counter += per_cpu(percpu, cpu).value_()
    return counter


def to_binary_units(num: t.Union[float, int], units: t.List[str]) -> str:
    """
    Format a number as a simple human-readable number with units
    """
    num = float(num)
    for unit in units:
        if num < 1024:
            break
        num = num / 1024
    if num < 10:
        return f"{num:.2f} {unit}"
    else:
        return f"{num:.1f} {unit}"


def human_bytes(num: t.Union[float, int]) -> str:
    return to_binary_units(
        num, ["bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"]
    )


def human_bps(num: t.Union[float, int]) -> str:
    return to_binary_units(
        num, ["bps", "KiB/s", "MiB/s", "GiB/s", "TiB/s", "PiB/s", "EiB/s"]
    )


class SimpleProgress:
    """
    A simple download progress reporter
    """

    def __init__(
        self,
        desc: str,
        total_bytes: t.Union[float, int],
        quiet: bool = False,
        update_every: float = 0.5,
        notty_update_every: float = 5.0,
    ) -> None:
        self.desc = desc
        self.total_bytes = total_bytes
        self.current_bytes = 0.0
        self.quiet = quiet
        self.update_every = update_every
        self.notty_update_every = notty_update_every
        self.start_time = time.time()
        self.next_report = self.start_time
        self.isatty = sys.stdout.isatty()

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, t, v, tb):
        self.complete()

    def step(self, nbytes: t.Union[float, int]) -> None:
        self.current_bytes += nbytes
        if not self.quiet and time.time() > self.next_report:
            self.print_report()

    def print_report(self) -> None:
        current_time = time.time()
        elapsed_time = current_time - self.start_time
        rate = self.current_bytes / elapsed_time

        rstr = human_bps(rate)
        cbstr = human_bytes(self.current_bytes)
        tbstr = human_bytes(self.total_bytes)
        if self.total_bytes:
            pct = str(int(100 * self.current_bytes / self.total_bytes))
        else:
            pct = "??"

        if self.isatty:
            print(
                f"\033[1k\r{self.desc}: {pct}% @ {rstr} ({cbstr} / {tbstr})",
                end="",
                flush=True,
            )
            self.next_report = current_time + self.update_every
        else:
            print(f"{self.desc}: {pct}% @ {rstr} ({cbstr} / {tbstr})")
            self.next_report = current_time + self.notty_update_every

    def complete(self):
        self.print_report()
        if self.isatty and not self.quiet:
            print()


def download_file(
    url: str,
    f: t.BinaryIO,
    quiet: bool = True,
    desc: str = "Downloading",
) -> None:
    response = urlopen(url)

    buf = bytearray(4096 * 4)
    total_bytes = int(response.headers.get("Content-Length", "0"))
    progress = SimpleProgress(desc, total_bytes, quiet=quiet)

    while True:
        num = response.readinto(buf)
        if num == 0:
            break
        # Yes, this is Python, but it doesn't mean that we need to copy
        # data around wildly and inefficiently. The memoryview allows us
        # to create a read-only view onto the buffer which we can slice
        # without copying it. That can then be given to write().
        f.write(memoryview(buf)[:num])
        progress.step(num)
    progress.complete()


def cpumask_to_cpulist(cpumask: Object) -> str:
    """
    Get list of CPUs, present in a cpumask.

    :param cpumask: ``struct cpumask*``
    :returns: list of CPUs as string
    """
    start = 0
    end = 0
    count = 1
    cpu_range = str()
    all_cpu_ranges = str()
    cpulist = [cpu for cpu in for_each_cpu(cpumask)]

    if len(cpulist) == 1:  # Just one CPU in mask
        return str(cpulist[0])

    for index, value in enumerate(cpulist):
        if index < len(cpulist) - 1:
            if cpulist[index + 1] > value + 1:
                end = index
                if count > 1:
                    cpu_range = str(cpulist[start]) + "-" + str(cpulist[end])
                else:
                    cpu_range = str(cpulist[start])
                start = end + 1
                count = 1
                if not len(all_cpu_ranges):
                    all_cpu_ranges += cpu_range
                else:
                    all_cpu_ranges += ", " + cpu_range
            else:
                count += 1
        else:
            if count == index + 1:  # only one range
                all_cpu_ranges = (
                    str(cpulist[start]) + "-" + str(cpulist[index])
                )
            else:
                if (
                    cpulist[start] == cpulist[index]
                ):  # only one element in last range
                    all_cpu_ranges += ", " + str(cpulist[index])
                else:  # more than 1 element in last range
                    all_cpu_ranges += (
                        ", " + str(cpulist[start]) + "-" + str(cpulist[index])
                    )

    return all_cpu_ranges


def uek4_radix_tree_lookup(root: Object, index: int) -> Object:
    _RADIX_TREE_MAP_SHIFT = 6
    _RADIX_TREE_INDEX_BITS = 8 * sizeof(root.prog_.type("unsigned long"))
    _RADIX_TREE_MAX_PATH = (
        _RADIX_TREE_INDEX_BITS + _RADIX_TREE_MAP_SHIFT - 1
    ) // _RADIX_TREE_MAP_SHIFT
    _RADIX_TREE_MAP_SIZE = 1 << _RADIX_TREE_MAP_SHIFT
    _RADIX_TREE_MAP_MASK = _RADIX_TREE_MAP_SIZE - 1
    _RADIX_TREE_HEIGHT_SHIFT = _RADIX_TREE_MAX_PATH + 1

    _RADIX_TREE_HEIGHT_MASK = (1 << _RADIX_TREE_HEIGHT_SHIFT) - 1

    node = root.rnode.value_()
    is_indirect_ptr = node & 1
    if not is_indirect_ptr:
        if index > 0:
            return NULL(root.prog_, "void *")

        return node

    node = Object(
        root.prog_, "struct radix_tree_node", address=(node & ~1)
    ).address_of_()
    height = node.path.value_() & _RADIX_TREE_HEIGHT_MASK
    if index > root.prog_["height_to_maxindex"][height].value_():
        return NULL(root.prog_, "void *")

    shift = (height - 1) * _RADIX_TREE_MAP_SHIFT

    while True:
        idx = (index >> shift) & _RADIX_TREE_MAP_MASK
        node = Object(
            root.prog_, "void *", address=node.slots[idx].address_of_()
        )
        if not node.value_():
            return NULL(root.prog_, "void *")

        shift -= _RADIX_TREE_MAP_SHIFT
        height -= 1

        if height <= 0:
            break

    return node
