# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
import logging
import re
import sys
import time
import typing as t
from contextlib import contextmanager
from enum import IntEnum
from urllib.error import HTTPError
from urllib.request import Request
from urllib.request import urlopen

from drgn import NULL
from drgn import Object
from drgn import Program
from drgn import sizeof
from drgn import Type
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


def kernel_version(prog: Program) -> t.Tuple[int, int, int]:
    """
    Returns the kernel version as a tuple (major, minor, patch)

    This is not the full release string, and it shouldn't be confused with the
    UEK-specific parsing that is present in
    :class:`drgn_tools.debuginfo.KernelVersion`. It simply corresponds to the
    upstream major, minor, and patch versions, which typically (but not always)
    remain constant over a distribution kernel's releases.

    Given a kernel version, especially the major.minor version alone, there is
    no guarantee about whether a commit is necessarily present or not. The
    linux-stable process regularly backports commits from newer releases into
    older ones, especially when they have a Fixes tag. Distributions like UEK
    also backport certain changes, regardless of whether they were included in
    stable releases.

    This should be used only as a last resort for helper compatibility. At each
    usage of this function, a comment should be in place describing (a) the
    exact git commit SHA which introduces the change, and which kernel version
    the change appears in. (b) Why couldn't the change in behavior be handled by
    detecting changes to variables or types? (c) Address whether there is a risk
    that stable/distro kernels may have a bakckport of the commit, which
    couldn't be detected via a simple kernel version comparison.
    """
    release = prog["UTS_RELEASE"].string_().decode("utf-8")
    # Accepts 5.15.0, 6.0, 4.1.3-whatever...
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", release)
    if not match:
        raise ValueError(f"Cannot understand kernel release: {release}")
    maj, min, patch = match.groups()
    if not patch:
        patch = "0"
    return (int(maj), int(min), int(patch))


def type_has_member(prog: Program, typ: str, name: str) -> bool:
    """
    Return true if a given object has a member with the given name.
    :param typ: type name to check
    :param name: string member name to check
    :returns: whether the object has a member by that name
    """
    try:
        prog.type(typ).member(name)
        return True
    except LookupError:
        return False


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
    if has_member(ref, "data"):
        if ref.data.value_() != 0:
            atomic_count = ref.data.count
        else:
            return 0
    else:
        atomic_count = ref.count
    # Last two bits of ptr is uses as flags, not in percpu mode if any bit set.
    # PERCPU_COUNT_BIAS = (1LU << (BITS_PER_LONG - 1)) was set to counter
    # in percpu mode.
    bits_per_long = prog.type("long").size * 8
    PERCPU_COUNT_BIAS = 1 << (bits_per_long - 1)
    counter = atomic_count.counter & ~PERCPU_COUNT_BIAS
    ptr = ref.percpu_count_ptr
    if ptr & 0x3 != 0 or ptr == 0:
        return int(counter)
    percpu = Object(prog, "unsigned long", address=ptr)
    for cpu in for_each_possible_cpu(prog):
        counter += per_cpu(percpu, cpu).value_()
    return int(counter)


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
        self.isatty = sys.stderr.isatty()

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
                file=sys.stderr,
            )
            self.next_report = current_time + self.update_every
        else:
            print(
                f"{self.desc}: {pct}% @ {rstr} ({cbstr} / {tbstr})",
                file=sys.stderr,
            )
            self.next_report = current_time + self.notty_update_every

    def complete(self):
        if not self.quiet:
            self.print_report()
            if self.isatty:
                print()


def head_file(url: str) -> bool:
    request = Request(url, method="HEAD")
    try:
        urlopen(request)
        return True
    except HTTPError:
        return False


def download_file(
    url: str,
    f: t.BinaryIO,
    quiet: bool = True,
    desc: str = "Downloading",
    logger: t.Optional[logging.Logger] = None,
    caller: t.Optional[str] = None,
) -> None:
    response = urlopen(url)

    if response.status >= 400:
        raise Exception(f"HTTP {response.status} while fetching {url}")

    if logger:
        logger.info("%sDownloading %s", caller, url)

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


class BitNumberFlags(IntEnum):
    @classmethod
    def decode(cls, value: int) -> str:
        names = []
        for bit in cls:
            if (1 << bit) & value:
                names.append(bit.name)
                value &= ~(1 << bit)
        if not names or value:
            names.append(f"0x{value:x}")
        return "|".join(names)


def timestamp_str(ns: int) -> str:
    value = ns // 1000000
    ms = value % 1000
    value = value // 1000
    secs = value % 60
    value = value // 60
    mins = value % 60
    value = value // 60
    hours = value % 24
    days = value // 24
    return "%d %02d:%02d:%02d.%03d" % (days, hours, mins, secs, ms)


def type_lookup_conflict(
    prog: Program, name: str, module: str, filenames: t.List[str]
) -> Type:
    """
    Lookup a type which has conflicting definitions, with DWARF or CTF

    Unfortunately, DWARF and CTF handle conflicting type definitions in
    different ways, and drgn can't handle them uniformly. With DWARF, drgn
    allows us to provide the filename which contains the definition of the
    desired type. However, CTF doesn't contain filename information. It uses
    module names to resolve these conflicts. This function smooths over those
    problems.

    :param prog: Program whose types we are looking up
    :param name: the type name to look up
    :param module: the name of the kernel module containing the definition
    :param filenames: one or more lists of filenames containing the definition
      (in case the filenames have changed over different kernel versions)
    :returns: the Type associated with ``name``, or else raises ``LookupError``
    """
    # DWARF type finder raises LookupError when filename is not found.
    # CTF type finder *does not* raise error when module is not found.
    # So try CTF module first: a LookupError either means the type doesn't
    # exist, or we're using DWARF debuginfo.
    try:
        return prog.type(name, module)
    except LookupError:
        pass

    # Try DWARF filenames:
    for filename in filenames:
        try:
            return prog.type(name, filename)
        except LookupError:
            pass

    raise LookupError(
        f"Could not find type {name} in module {module} or files {filenames}"
    )


def per_cpu_owner(name: str, val: Object) -> int:
    """
    Given a per-cpu variable/pointer, return CPU to which this per-cpu
    variable/pointer belongs.

    :param name: name of the per-cpu variable/pointer
    :param val: per-cpu variable/pointer
    :returns: cpu number to which per-cpu variable/pointer belongs.
              If cpu can't be found return -1
    """

    prog = val.prog_
    var_name = prog[name]
    for cpu in for_each_possible_cpu(prog):
        if per_cpu(var_name, cpu).value_() == val.value_():
            return cpu

    return -1


class CommaList(argparse.Action):
    """Action that allows specifying an option multiple times, with comma-separated values"""

    def __init__(self, *args, element_type=str, **kwargs) -> None:
        self.element_type = element_type
        return super().__init__(*args, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        value: t.Union[str, t.Sequence[t.Any], None],
        option_string: t.Optional[str] = None,
    ) -> None:
        assert isinstance(value, str)
        result = getattr(namespace, self.dest, []) or []
        for element in value.split(","):
            result.append(self.element_type(element))
        setattr(namespace, self.dest, result)
