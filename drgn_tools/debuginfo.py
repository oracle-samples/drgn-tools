# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
The ``drgn_tools.debuginfo`` module provides the APIs for finding debuginfo.

Please note: this file is quite special. Currently, it is not just the
``drgn_tools.debuginfo`` module: it is also a file which is copied and pasted
into the /share/linuxtools/bin directory in order to allow people & bash scripts
to easily find and extract debuginfo, while ensuring that they also make the
appropriate updates to the access.db file.

In the future, the CRASH scripts will be updated to call drgn-tools directly to
do this. But in the meantime, this quick solution is easier for testing, and
allows me to avoid having to deal with OL8 drgn-tools deployment yet. The
consequence here is that we can only use the standard library: no imports from
drgn or drgn-tools or third-party modules.
"""
import abc
import argparse
import enum
import itertools
import os
import re
import shutil
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import NamedTuple
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union
from urllib.error import HTTPError
from urllib.error import URLError

from drgn_tools.config import get_config
from drgn_tools.logging import get_logger
from drgn_tools.util import download_file

if TYPE_CHECKING:
    from drgn import Program

__all__ = (
    "fetch_debuginfo",
    "find_debuginfo",
    "KernelVersion",
)

REPO_DIR = os.getenv("LINUXRPM", "/share/linuxrpm")
log = get_logger("drgn_tools.debuginfo")


class DebuginfoFetcher(abc.ABC):
    """
    An interface for different strategies of fetching debuginfo
    """

    def fetch_modules(
        self, uname: str, modules: List[str], quiet: bool = True
    ) -> Dict[str, Path]:
        raise NotImplementedError("implement me!")

    def output_directories(self) -> List[Path]:
        raise NotImplementedError("implement me!")


class VmlinuxRepoFetcher(DebuginfoFetcher):
    """
    A fetcher designed for Oracle internal analysis machines

    The idea of this finder is that each debuginfo RPM lives on a network
    filesystem, and a separate network filesystem contains a directory per
    kernel release, which will house the individual debuginfo files: vmlinux,
    module.ko.debug, etc. Debuginfo files may need to be extracted on demand,
    since they are quite large and may have been cleaned up to conserve disk
    space. In practice, we usually have:

    - ``/share/linuxrpm/debuginfo-rpms/build-output-$OLVER-debuginfo/kernel-uek-debuginfo-$release.rpm``
    - ``/share/linuxrpm/vmlinux_repo/$bits/$release/vmlinux``

    This finder only works when the expensive mode is turned on. It will extract
    the debuginfo RPM and place the vmlinux and module files into the
    corresponding directory.
    """

    def __init__(self, root_path: Optional[str] = REPO_DIR):
        if root_path:
            self.root_path = Path(root_path)
        else:
            self.root_path = Path(REPO_DIR)

    def fetch_modules(
        self, uname: str, modules: List[str], quiet: bool = True
    ) -> Dict[str, Path]:
        version = KernelVersion.parse(uname)

        if version.arch in ("x86_64", "aarch64"):
            bits = "64"
        else:
            bits = "32"

        source_rpm = (
            self.root_path
            / "debuginfo-rpms"
            / f"build-output-{version.ol_version}-debuginfo"
            / version.oraclelinux_debuginfo_rpm()
        )
        dest_dir = self.root_path / f"vmlinux_repo/{bits}/{uname}"

        if not source_rpm.is_file():
            log.warning(
                "%s: debuginfo RPM is not present in %s:\n%s",
                self.__class__.__name__,
                self.root_path,
                source_rpm,
            )
            return {}
        return extract_rpm(source_rpm, dest_dir, modules, permissions=0o777)

    def output_directories(self) -> List[Path]:
        return [
            self.root_path / "vmlinux_repo/64",
            self.root_path / "vmlinux_repo/32",
        ]


class OracleLinuxYumFetcher(DebuginfoFetcher):
    """
    A fetcher which downloads from oss.oracle.com Yum server
    """

    urls: List[str] = ["https://oss.oracle.com/ol{olver}/debuginfo/{rpm}"]
    out_dir: Path = Path.home() / "vmlinux_repo"
    rpm_cache: bool = False

    def __init__(
        self, urls: Optional[str] = None, rpm_cache: bool = False
    ) -> None:
        self.rpm_cache = rpm_cache
        if urls:
            self.urls = []
            for u in urls.split("\n"):
                u = u.strip()
                if u:
                    self.urls.append(u)

    def fetch_modules(
        self, uname: str, modules: List[str], quiet: bool = False
    ) -> Dict[str, Path]:
        version = KernelVersion.parse(uname)
        rpm = version.oraclelinux_debuginfo_rpm()
        cached = self.out_dir / "rpms" / rpm
        out_dir = self.out_dir / uname

        # Even if we don't enable caching, that doesn't mean we shouldn't take
        # advantage of a cached RPM we find. The rpm_cache setting merely
        # controls whether we keep the downloaded RPM around.
        if cached.is_file():
            return extract_rpm(cached, out_dir, modules)

        urls = [
            url_fmt.format(olver=version.ol_version, rpm=rpm)
            for url_fmt in self.urls
        ]
        with tempfile.NamedTemporaryFile(suffix=".rpm", mode="wb") as f:
            # Apparently a temporary file is not a "BytesIO", so type
            # checking fails. Ignore that error.
            errors = []
            for url in urls:
                try:
                    download_file(url, f, quiet, desc="Downloading RPM")  # type: ignore
                    break
                except HTTPError as e:
                    errors.append(
                        "download failed for debuginfo RPM: {} {}\n{}".format(
                            e.code, e.reason, url
                        )
                    )
                except URLError as e:
                    errors.append(f"download failed for debuginfo RPM: {e}")
            else:
                log.warning(
                    "%s: tried all URLs and download failed:\n%s",
                    self.__class__.__name__,
                    "\n".join(errors),
                )
                return {}
            f.flush()
            out_dir.mkdir(parents=True, exist_ok=True)
            path = Path(f.name)
            if self.rpm_cache:
                cached.parent.mkdir(exist_ok=True, parents=True)
                shutil.move(str(path), str(cached))
                path.touch()  # prevent error in unlink
                path = cached
            return extract_rpm(path, out_dir, modules)

    def output_directories(self) -> List[Path]:
        return [self.out_dir]


@lru_cache(maxsize=1)
def _get_configured_fetchers() -> List[DebuginfoFetcher]:
    """
    Return debuginfo fetchers as configured by the user

    If the drgn-tools configuration file has debuginfo related configuration,
    this creates the required fetchers and returns them. If no configuration is
    present, then we check if the REPO_DIR exists, and if so, we return the
    VmlinuxRepoFetcher. Otherwise, we return an empty list.
    """
    config = get_config()
    fetchers = []

    name_to_fetcher = {
        cls.__name__: cls for cls in DebuginfoFetcher.__subclasses__()
    }
    fetcher_config = config.get("debuginfo", "fetchers", fallback=None)
    if fetcher_config is not None:
        for name in fetcher_config.split():
            if name in name_to_fetcher:
                params: Mapping[str, Any] = {}
                if name in config:
                    params = config[name]
                fetchers.append(name_to_fetcher[name](**params))
            else:
                log.warning('Unknown debuginfo fetcher "%s"', name)
    elif os.path.isdir(REPO_DIR):
        fetchers.append(VmlinuxRepoFetcher(root_path=REPO_DIR))
    return fetchers


def fetch_debuginfo(uname: str, modules: List[str]) -> Dict[str, Path]:
    """
    Fetch debuginfo in a potentially expensive way

    Assuming that :func:`find_debuginfo()` has failed, we can assume that
    debuginfo is not easily available locally. However, we may be able to
    "fetch" it and extract it from a remote source. This is usually costly: it
    will take some time to download and process the debuginfo. This function
    may use different strategies depending on the user's configuration.

    The result may be incomplete: out-of-tree modules likely can't be found,
    and it's of course possible that nothing can be found.

    :param uname: Kernel release to search debuginfo for
    :param modules: List of standardized module names
    :returns: Mapping of names to paths
    """
    for fetcher in _get_configured_fetchers():
        result = fetcher.fetch_modules(uname, modules)
        if result:
            return result
    return {}


def _get_debuginfo_paths(
    prog_or_release: Union["Program", str],
    dinfo_path: Optional[Iterable[str]] = None,
) -> List[Path]:
    """
    Return list of paths to search for DWARF debuginfo

    We cache this after the first run, to make it more efficient. We search in
    the following order:

        dinfo_path  (user argument)
        $PWD/$RELEASE
          -> or $PWD if the above does not exist
        $DEBUGINFO_BASE/$RELEASE   (for each colon-separated path)
        /usr/lib/debug/lib/modules/$RELEASE
        $PWD/usr/lib/debug/lib/modules/$RELEASE

    :param prog: Program we're debugging, or else the kernel release string.
      When a Program is provided, we cache the path on the object and use the
      Program to determine the release string.
    :dinfo_path: List of pathnames to search first
    :returns: Concrete list of paths to search, cached
    """
    prog: Optional["Program"] = None
    if isinstance(prog_or_release, str):
        release = prog_or_release
    else:
        # Assume to be a program, without explicitly using the name
        prog = prog_or_release
        cached_paths = prog.cache.setdefault("drgn_tools", {}).get(
            "debuginfo_paths"
        )
        if cached_paths:
            return cached_paths.copy()
        release = prog["UTS_RELEASE"].string_().decode()

    paths: List[Path] = []

    if dinfo_path:
        for path_str in dinfo_path:
            # User provided "dinfo_path" should not have the kernel release
            # appended, just use the exact path provided.
            path = Path(path_str).absolute()
            if path.is_dir():
                paths.append(path)

    # If we find a directory by the same name as this kernel's release in the
    # working directory, use that. Otherwise, use the working directory since
    # there may be some modules in there.
    cwd = Path.cwd().absolute()
    cwd_release = cwd / release
    if cwd_release.is_dir():
        paths.append(cwd_release)
    else:
        paths.append(cwd)

    # Finally, these paths expect that there must be a release appended.
    candidate_paths: List[str] = []

    env_dinfo_path = os.environ.get("DEBUGINFO_BASE")
    if env_dinfo_path is not None:
        path = Path(env_dinfo_path).absolute()
        if (path / release).is_dir():
            candidate_paths.append(str(path / release))

    candidate_paths.extend(
        [
            "/usr/lib/debug/lib/modules",
            "./usr/lib/debug/lib/modules",
        ]
    )
    # Include paths where the configured fetcher would store debuginfo
    for fetcher in _get_configured_fetchers():
        candidate_paths.extend(map(str, fetcher.output_directories()))

    for path_str in candidate_paths:
        path = Path(path_str).absolute() / release
        if path.is_dir():
            paths.append(path)
    if prog is not None:
        prog.cache["drgn_tools"]["debuginfo_paths"] = paths.copy()
    return paths


def _find_debuginfo(paths: List[Path], mod: str) -> Optional[Path]:
    replace_pat = re.compile(r"[_-]")
    for search_dir in paths:
        if "lib/modules" in str(search_dir) and mod != "vmlinux":
            # If the path contains "lib/modules", it's likely the result of
            # extracting an RPM. That means that we'll have a nested directory
            # structure to search for modules. Be lenient on hyphens and
            # underscores too.
            mod_pat = replace_pat.sub("[_-]", mod)
            for candidate in search_dir.glob(f"**/{mod_pat}.ko.debug*"):
                return candidate
        else:
            name_alt = None
            if "-" in mod:
                name_alt = mod.replace("-", "_")
            elif "_" in mod:
                name_alt = mod.replace("_", "-")
            exts = (
                ("",) if mod == "vmlinux" else (".ko.debug", ".ko", ".ko.xz")
            )
            # Otherwise, it's likely to be a flat directory containing the
            # files without any additional structure. Just test the common
            # extensions. Using path lookup will be faster than the glob which
            # requires a readdir operation. This can matter for network
            # filesystems or very large directories.
            for ext in exts:
                candidate = search_dir / f"{mod}{ext}"
                if candidate.exists():
                    return candidate
                # try the alternative name (hyphen or underscore)
                if name_alt:
                    candidate = search_dir / f"{name_alt}{ext}"
                    if candidate.exists():
                        return candidate
    return None


def find_debuginfo(
    prog_or_release: Union["Program", str],
    mod: str,
    dinfo_path: Optional[str] = None,
) -> Optional[Path]:
    """
    Search for debuginfo (either module or regular debuginfo)

    This function searches for a given module's debuginfo in a list of paths.
    It returns the path of a match, if found. The debuginfo paths are determined
    as follows:

    1. Files within ``$PWD/$RELEASE`` are considered, if it exists. Otherwise,
       files within ``$PWD`` are considered.

    2. Files in the directory ``$DEBUGINFO_BASE/$RELEASE`` are considered, for
       each colon-separated path in ``$DEBUGINFO_BASE``, if it exists.

    3. Files in ``/usr/lib/debug/lib/modules/$RELEASE`` and
       ``./usr/lib/debug/lib/modules/$RELASE``, if either exist.

    4. Files in ``/share/linuxrpm/vmlinux_repo/{64,32}/$RELEASE`` are searched.

    The directories may be searched in one of two ways. For directories whose
    full paths contain the string ``lib/modules``, we assume that the directory
    was created by installing the RPM, or by extracting the RPM directly. This
    means that the module debuginfo may be in a subdirectory, and so we use a
    recursive search through subdirectories. For directories which do not
    contain the string ``lib/modules``, our search is not recursive. This is
    mainly to improve performance: listing directories is slow on network
    filesystems, and there's a chance that directories like ``$PWD`` will
    contain a lot of subdirectories.

    Finally, it is important to note that this function is lenient on module
    names. It should be called with the original module name, but it will match
    a module file whose name has had hyphens replaced by underscore. This
    ensures it can match files extracted by :func:`fetch_debuginfo()`.

    :param mod: The original module name (not standardized with underscores)
    :param dinfo_path: An optional additional path to search
    :returns: The path to a debuginfo file, if found
    """
    user_paths = []
    if dinfo_path:
        user_paths.append(dinfo_path)
    paths = _get_debuginfo_paths(prog_or_release, dinfo_path=user_paths)
    return _find_debuginfo(paths, mod)


# Mapping of kernel version (without release) to the UEK major version. The
# kernel version 3-tuple never changes throughout a UEK release.
_UEK_VER = {
    "2.6.32": 1,
    "2.6.39": 2,
    "3.8.13": 3,
    "4.1.12": 4,
    "4.14.35": 5,
    "5.4.17": 6,
    "5.15.0": 7,
}


class KernelVersion(NamedTuple):
    version: str
    """
    The upstream kernel version (e.g. 5.15.0).

    Note that depending on the package versioning scheme, the patchlevel number
    here may be useless, misleading, or otherwise unhelpful.
    """
    version_tuple: Tuple[int, ...]
    """
    The upstream version, split into integer groups for easy comparison.

    This should be a three element tuple, but the code does not enforce it as a
    requirement, so you should treat it as a variable length tuple of integers.
    """
    release: str
    """The packaging release version (the stuff after the hyphen)."""
    release_tuple: Tuple[int, ...]
    """The release version, split into integer groups for easy comparison."""
    ol_version: int
    """The Oracle Linux distribution version"""
    ol_update: Optional[int]
    """
    The Oracle Linux distribution update.

    Note that this is not provided by UEK kernel versions. It is, however,
    provided by the regular kernel package.
    """
    arch: str
    """The package architecture."""
    original: str
    """The original version string"""

    extraversion1: str
    """The extra version text prior to the OL version."""
    extraversion2: str
    """The extra version text prior to the OL version."""

    is_uek: bool
    """Whether the kernel is a UEK kernel."""
    uek_version: Optional[int]
    """The major version of the UEK release, if applicable."""
    is_ueknext: bool
    """Whether the kernel is a UEK-next kernel (uek_version will be None)"""

    @classmethod
    def parse(cls, original: str) -> "KernelVersion":
        """
        Parse the given kernel release string and return a ``KernelVersion``:

            >>> KernelVersion.parse('4.14.35-2047.516.2.4.el7uek.x86_64')
            KernelVersion(version='4.14.35', version_tuple=(4, 14, 35),
                          release='2047.516.2.4',
                          release_tuple=(2047, 516, 2, 4),
                          ol_version=7, ol_update=None, arch='x86_64',
                          original='4.14.35-2047.516.2.4.el7uek.x86_64',
                          extraversion1='', extraversion2='', is_uek=True,
                          uek_version=5, is_ueknext=False)

        :param original: The kernel's release string
        :returns: A ``KernelVersion`` with fields parsed
        """
        version_re = re.compile(
            r"(?P<version>\d+\.\d+\.\d+)-(?P<release>\w+(?:\.\w+)*)"
            r"\.el(?P<ol_version>\d+)(?P<extra>uek|ueknext|_(?P<update>\d+)|)"
            r"(?P<extraversion2>\.[0-9a-zA-Z._]+?)?"
            r"\.(?P<arch>.+)",
            re.ASCII,
        )
        match = version_re.fullmatch(original)
        if not match:
            raise ValueError(
                "Could not understand kernel version string: " + original
            )
        version_tuple = tuple(
            int(g) for g in re.split("[.-]", match["version"])
        )
        # The release string is complicated. Normally there are two parts: a
        # release that is a normal version number (digits separated by dots),
        # and then an optional extra component that could contain text. By
        # convention, all the numeric elements get looped into the "release" and
        # the remaining elements are the "extraversion".
        release_elements = []
        extraversion_elements = []
        elements = list(match["release"].split("."))
        for i, group in enumerate(elements):
            try:
                release_elements.append(int(group))
            except ValueError:
                extraversion_elements.extend(elements[i:])
                break
        release_tuple = tuple(release_elements)
        extraversion = ".".join(extraversion_elements)
        update = None
        if match["update"]:
            update = int(match["update"])
        is_uek = match["extra"].startswith("uek")
        uek_ver = None
        if is_uek:
            uek_ver = _UEK_VER.get(match["version"])
        is_uek_next = (
            match["extra"] == "ueknext"
            # In the initial 6.8.0 releases of UEK-next, there was no "ueknext"
            # in the extra part of the version. Since 6.9.0 this is present.
            or (is_uek and uek_ver is None and version_tuple == (6, 8, 0))
        )
        return cls(
            match["version"],
            version_tuple,
            ".".join(str(n) for n in release_elements),
            release_tuple,
            int(match.group("ol_version")),
            update,
            match["arch"],
            original,
            extraversion,
            match["extraversion2"] or "",
            is_uek,
            uek_ver,
            is_uek_next,
        )

    def oraclelinux_debuginfo_rpm(self) -> str:
        if self.is_uek and self.is_ueknext:
            package_name = "kernel-ueknext"
        elif self.is_uek:
            package_name = "kernel-uek"
        else:
            package_name = "kernel"
        return f"{package_name}-debuginfo-{self.original}.rpm"


def extract_rpm(
    source_rpm: Path,
    dest_dir: Path,
    modules: List[str],
    permissions: Optional[int] = None,
) -> Dict[str, Path]:
    if not dest_dir.exists():
        # Rather than use .mkdir(exist_ok=True), we do the test explicitly here,
        # because when creating the directory, we need to set 777 permissions in
        # order to allow other users to extract debuginfo on shared
        # repositories.
        dest_dir.mkdir()
        if permissions is not None:
            dest_dir.chmod(permissions)
    elif not os.access(dest_dir, os.R_OK | os.W_OK | os.X_OK):
        # If the directory was created by another user who did not set 777
        # permissions on the directory, we will not be able to update it with
        # new files. Extracting the RPM is expensive, and the resulting error
        # message from this case will be cryptic. So, detect it and raise the
        # error early. We can also suggest a workaround for it.
        raise Exception(
            f"The directory {dest_dir} exists, but you do not have permission "
            "to update it. This commonly occurs when users create a directory "
            "but fail to set 0777 permissions. A common workaround is to "
            "rename the directory (e.g. add a -DONTUSE suffix) and then run "
            "the extraction again. The extraction code here will properly set "
            "the 0777 permissions when it creates the directory."
        )

    with tempfile.NamedTemporaryFile(
        "wt"
    ) as tf, tempfile.TemporaryDirectory() as tdname:
        td = Path(tdname)
        for module in modules:
            if module == "vmlinux":
                tf.write("*/vmlinux\n")
            else:
                # Per the documentation, callers should provide module names
                # using the standardized underscore naming. However, we need to
                # recognize hyphen naming too.
                tf.write(f"*/{module}.ko.debug\n")
                if "_" in module:
                    tf.write(f"*/{module.replace('_', '-')}.ko.debug\n")
        tf.flush()
        proc = subprocess.run(
            f"rpm2cpio {source_rpm} | cpio -ivd --quiet -E {tf.name}",
            shell=True,
            check=True,
            cwd=tdname,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="ascii",
        )
        extracted = []
        for line in proc.stderr.split("\n"):  # filenames on stderr
            line = line.strip()
            if not line:
                continue
            file_path = td / line[2:]
            if not file_path.is_file():
                continue
            # standardize the names to use underscore
            name = file_path.name.replace("-", "_")
            dst = dest_dir / name
            # pathlib rename does not work since this is likely to be across
            # filesystems. Use shutil, and use a str() because shutil.move()
            # only got support for handling Path objects in 3.9.
            if dst.exists():
                dst.unlink()
            shutil.move(
                str(file_path),
                str(dst),
            )
            if file_path.name == "vmlinux":
                extracted.append(name)
            elif file_path.name.endswith(".ko.debug"):
                extracted.append(name[: -len(".ko.debug")])

    result = {
        module: dest_dir
        / (module if module == "vmlinux" else f"{module}.ko.debug")
        for module in extracted
    }
    return result


class CtfCompatibility(enum.Enum):
    YES = "YES"
    """CTF is fully compatible: symbol lookup, types, and stack traces"""
    LIMITED_PROC = "LIMITED_PROC"
    """Only compatible for live kernels as root using /proc/kallsyms"""
    LIMITED_STACK = "LIMITED_STACK"
    """Limited compatibility - stack tracing not currently supported"""
    NO = "NO"
    """Functionality is not available"""

    @classmethod
    def get(
        cls, kver: KernelVersion, host_ol: Optional[int]
    ) -> "CtfCompatibility":
        # At this point, only UEK kernels have CTF debuginfo.
        if not kver.is_uek:
            return cls.NO
        # UEK-next kernels have no compatibility issues
        if kver.is_ueknext:
            return cls.YES
        elif kver.uek_version is None:
            # If it's UEK, but we can't identify a version or -next, that's a
            # bug!
            return cls.NO

        # Prior to UEK4, it is untested and will not be tested.
        # UEK4 itself has broken CTF data (e.g. struct page) and this means that
        # a large majority of helpers cannot function.
        if kver.uek_version <= 4:
            return cls.NO

        # The OL7 libctf version does not support CTF generated for kernels on
        # later OL versions.
        if host_ol == 7 and kver.ol_version > 7:
            return cls.NO

        # For OL8, UEK6, the CTF generation process produced buggy data. The
        # data was fixed starting in 5.4.17-2136.323.1: all prior versions are
        # fully broken. This is specific to x86_64: the aarch64 build used a
        # different toolchain which was not affected.
        if (
            kver.ol_version == 8
            and kver.uek_version == 6
            and kver.arch == "x86_64"
            and kver.release_tuple < (2136, 323, 1)
        ):
            return cls.NO

        # Kernel commit f09bddbd8661 ("vmcoreinfo: add kallsyms_num_syms
        # symbol") and its dependent commits are required in order to read
        # kallsyms data directly out of the vmcore. Prior to that, only live
        # /proc/kallsyms was supported. The commit was merged in 6.0 and
        # backported to UEK5. The following releases are minimally required:
        kallsyms_backport = {
            5: (2047, 518, 0),
            6: (2136, 312, 2),
            7: (3, 60, 2),
        }
        if (
            kver.uek_version < 8
            and kver.release_tuple < kallsyms_backport[kver.uek_version]
        ):
            return cls.LIMITED_PROC

        return cls.YES


_epilog = """
This tool can find the requested vmlinux and module debuginfo for a UEK kernel.
If necessary, it will extract the necessary files from the debuginfo RPM. As
output, it will print to stdout the full path to the vmlinux as its first line,
followed by the path to any requested module debuginfo, each on a separate line.
An error in the search or extraction process will result in a non-zero error
code.  However, modules which are not found will not be considered an error:
this is common for the case of out-of-tree or proprietary modules. Instead, the
list of modules which were not found will be printed to stderr as a warning.
This can be silenced with the --quiet option.
"""


def _main():
    parser = argparse.ArgumentParser(
        description="tool for locating and extracting UEK debuginfo",
        epilog=_epilog.strip(),
    )
    parser.add_argument(
        "release",
        type=str,
        help="UEK release string",
    )
    parser.add_argument(
        "--modules",
        "--module",
        "-m",
        action="append",
        default=[],
        help=(
            "Comma-separated list of modules to attempt to load (may be "
            "specified multiple times)"
        ),
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Do not print any extraneous output to stderr",
    )
    args = parser.parse_args()
    modules = list(
        itertools.chain.from_iterable(
            s.replace(
                "-",
                "_",
            ).split(",")
            for s in args.modules
        )
    )
    modules.insert(0, "vmlinux")

    exists = {}
    to_load = set()
    for module in modules:
        path = find_debuginfo(args.release, module)
        if path:
            exists[module] = path
        else:
            to_load.add(module)

    if to_load:
        if not args.quiet:
            print("Fetching debuginfo...", file=sys.stderr)
        extracted = fetch_debuginfo(args.release, list(to_load))
        for extracted_mod, path in extracted.items():
            exists[extracted_mod] = path
            to_load.remove(extracted_mod)

    if to_load and not args.quiet:
        print(
            "warning: could not find debuginfo for modules: {}".format(
                ", ".join(to_load)
            ),
            file=sys.stderr,
        )

    # Unclear how this could happen, but handle it explicitly:
    vmlinux_path = exists.pop("vmlinux")
    if not vmlinux_path:
        sys.exit("error: could not find vmlinux file")
    print(vmlinux_path)
    for module_path in exists.values():
        print(module_path)


if __name__ == "__main__":
    _main()
