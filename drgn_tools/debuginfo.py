# Copyright (c) 2023-2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
The ``drgn_tools.debuginfo`` module is a drgn plugin for OL kernel debuginfo

It is configurable by using the "drgn_tools.ini" configuration file. When
drgn-tools is installed, an "entry point" is installed which allows drgn to find
our plugin. Thus, the native drgn CLI can actually use our debuginfo finders and
rely on our configuration file. Corelens and drgn_tools.cli both rely on the
finders as well, though they use their own logic.

Finally, this module may also be run from the command line, in which case it
find (maybe extract, depending on config) and print the locations of the
debuginfo for a vmcore.
"""
import enum
import logging
import os
import re
import shutil
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Tuple
from urllib.error import HTTPError
from urllib.error import URLError

from drgn import DebugInfoOptions
from drgn import MainModule
from drgn import Module
from drgn import ModuleFileStatus
from drgn import Program
from drgn import ProgramFlags
from drgn import RelocatableModule

from drgn_tools.config import get_config
from drgn_tools.util import download_file

try:
    from drgn.helpers.linux.ctf import load_ctf

    HAVE_CTF = True
except (ImportError, ModuleNotFoundError):
    HAVE_CTF = False


__all__ = (
    "CtfCompatibility",
    "KernelVersion",
)


CTF_PATHS = [
    "./vmlinux.ctfa",
    "/lib/modules/{uname}/kernel/vmlinux.ctfa",
]

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
    "6.12.0": 8,
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

    def format_params(self) -> Dict[str, str]:
        return {
            "ol_version": str(self.ol_version),
            "olver": str(self.ol_version),
            "arch": self.arch,
            "uname": self.original,
            "bits": "64" if self.arch in ("x86_64", "aarch64") else "32",
            "rpm": self.oraclelinux_debuginfo_rpm(),
        }


def is_vmlinux(module: Module) -> bool:
    return module.prog.flags & ProgramFlags.IS_LINUX_KERNEL and isinstance(
        module, MainModule
    )


def is_in_tree_module(module: Module) -> bool:
    return (
        module.prog.flags & ProgramFlags.IS_LINUX_KERNEL
        and isinstance(module, RelocatableModule)
        and not (module.object.taints & (1 << TAINT_OOT_MODULE))
    )


def find_debug_info_vmlinux_repo(repo_dir: Path, modules: List[Module]):
    for module in modules:
        if not module.wants_debug_file():
            continue
        if is_vmlinux(module):
            module.try_file(repo_dir / "vmlinux")
        elif is_in_tree_module(module):
            filename = f"{module.name.replace('-', '_')}.ko.debug"
            module.try_file(repo_dir / filename)


class DebugInfoOptionsExt:
    repo_paths: List[str]
    local_path: str
    urls: List[str]
    ctf_file: Optional[str]
    rpm_cache: bool

    def __init__(
        self,
        repo_paths: List[str],
        local_path: str,
        urls: List[str],
        ctf_file: Optional[str] = None,
        rpm_cache: bool = False,
    ) -> None:
        self.repo_paths = repo_paths
        self.local_path = local_path
        self.urls = urls
        self.ctf_file = ctf_file
        self.rpm_cache = rpm_cache


def ol_vmlinux_repo_finder(modules: List[Module]) -> None:
    prog = modules[0].prog
    opts: DebugInfoOptionsExt = prog.cache["drgn_tools.debuginfo.options"]
    uname = prog["UTS_RELEASE"].string_().decode()
    try:
        version = KernelVersion.parse(uname)
    except ValueError as e:
        log.warning(
            "ol-vmlinux-repo: error parsing kernel version: %s", str(e)
        )
        return
    fmtparams = version.format_params()
    for repo_format in opts.repo_paths:
        repo_dir = Path(repo_format.format(**fmtparams))
        if repo_dir.is_dir():
            log.debug("ol-vmlinux-repo: loading from %s", repo_dir)
            find_debug_info_vmlinux_repo(repo_dir, modules)


def ol_local_rpm_finder(modules: List[Module]) -> None:
    prog = modules[0].prog
    opts: DebugInfoOptionsExt = prog.cache["drgn_tools.debuginfo.options"]
    uname = prog["UTS_RELEASE"].string_().decode()
    try:
        version = KernelVersion.parse(uname)
    except ValueError as e:
        log.warning("ol-local: error parsing kernel version: %s", str(e))
        return
    fmtparams = version.format_params()

    # The local RPM finder must extract to a directory: the vmlinux repo. We
    # allow the "repo_paths" option to contain multiple elements, but the one at
    # the end of the list is the one which we would extract to. (The one(s) at
    # the beginning of the list may have been prepended there by a CLI
    # argument.)
    if not opts.repo_paths:
        log.debug("ol-local-rpm: no vmlinux repo to extract to, exiting")
        return
    dest_dir = Path(opts.repo_paths[-1].format(**fmtparams))
    source_rpm = Path(opts.local_path.format(**fmtparams))

    if not source_rpm.exists():
        log.debug("ol-local-rpm: local RPM is missing: %s", source_rpm)
        return

    mods_needing_debuginfo = []
    for module in modules:
        if module.wants_debug_file() and (
            is_vmlinux(module) or is_in_tree_module(module)
        ):
            mods_needing_debuginfo.append(module)

    if not mods_needing_debuginfo:
        log.debug(
            "ol-local-rpm: no vmlinux/in-tree modules need debug info, exiting"
        )
        return

    modnames = [m.name for m in mods_needing_debuginfo]
    extract_rpm(source_rpm, dest_dir, modnames, permissions=0o777)
    find_debug_info_vmlinux_repo(dest_dir, mods_needing_debuginfo)


def ol_download_finder(modules: List[Module]) -> None:
    prog = modules[0].prog
    opts: DebugInfoOptionsExt = prog.cache["drgn_tools.debuginfo.options"]
    uname = prog["UTS_RELEASE"].string_().decode()
    try:
        version = KernelVersion.parse(uname)
    except ValueError as e:
        log.warning("ol-download: error parsing kernel version: %s", str(e))
        return
    fmtparams = version.format_params()

    # The download RPM finder must extract to a directory: the vmlinux repo. We
    # allow the "repo_paths" option to contain multiple elements, but the one at
    # the end of the list is the one which we would extract to. (The one(s) at
    # the beginning of the list may have been prepended there by a CLI
    # argument.)
    if not opts.repo_paths:
        log.debug("ol-download: no vmlinux repo to extract to, exiting")
        return
    out_dir = Path(opts.repo_paths[-1].format(**fmtparams))
    dest_rpm = Path(opts.local_path.format(**fmtparams))

    mods_needing_debuginfo = []
    for module in modules:
        if module.wants_debug_file() and (
            is_vmlinux(module) or is_in_tree_module(module)
        ):
            mods_needing_debuginfo.append(module)

    if not mods_needing_debuginfo:
        log.debug(
            "ol-download: no vmlinux/in-tree modules need debug info, exiting"
        )
        return

    urls = [url_fmt.format(**fmtparams) for url_fmt in opts.urls]
    with tempfile.NamedTemporaryFile(suffix=".rpm", mode="wb") as f:
        for url in urls:
            try:
                # Apparently a temporary file is not a "BytesIO", so type
                # checking fails. Ignore that error.
                download_file(url, f, desc="Downloading RPM", quiet=False)  # type: ignore
                break
            except (HTTPError, URLError):
                pass
        else:
            log.warning(
                "ol-download: tried all URLs and download failed:\n%s",
                "\n".join(urls),
            )
            return
        f.flush()

        path = Path(f.name)
        if opts.rpm_cache:
            dest_rpm.parent.mkdir(exist_ok=True, parents=True)
            shutil.move(str(path), str(dest_rpm))
            path.touch()  # prevent error in tempfile unlink
            path = dest_rpm
        log.info("ol-download: extracting to %s", out_dir)
        modnames = [m.name for m in mods_needing_debuginfo]
        out_dir.mkdir(parents=True, exist_ok=True)
        extract_rpm(path, out_dir, modnames)
        find_debug_info_vmlinux_repo(out_dir, mods_needing_debuginfo)


def _get_host_ol() -> Optional[int]:
    path = "/etc/oracle-release"
    if not os.path.exists(path):
        return None
    m = re.search(r"(\d+)\.\d+", open(path).read())
    if m:
        return int(m.group(1))
    return None


def _check_ctf_compat(prog: Program, kver: KernelVersion) -> bool:
    """
    Return True if CTF is compatible with this kernel release

    If False, print a user-friendly diagnostic.
    """
    host_ol = _get_host_ol()
    compat = CtfCompatibility.get(kver, host_ol)
    if compat == CtfCompatibility.YES:
        return True
    elif (
        compat == CtfCompatibility.LIMITED_PROC
        and prog.flags & ProgramFlags.IS_LIVE
    ):
        return True

    log.error("error: CTF found, but incompatible with drgn-tools")
    log.error(f"  uname = {kver.original}")
    log.error(f"  host_ol = {host_ol}")
    log.error(f"  compat = {compat}")

    # Some helpful extra info
    if kver.uek_version and kver.uek_version < 4:
        log.error("Kernels prior to UEK4 are completely unsupported.")
        log.error("Please update.")
    elif compat == CtfCompatibility.LIMITED_PROC and kver.uek_version == 4:
        log.error("UEK 4 kernels can only be used with CTF in live mode")
    elif compat == CtfCompatibility.LIMITED_PROC:
        log.error("This UEK version only supports using CTF in live mode.")
        log.error("More recent UEK releases support core dump debugging.")
    elif (
        compat == CtfCompatibility.NO and host_ol == 7 and kver.ol_version > 7
    ):
        log.error("Debugging OL8 and later vmcores on OL7 is not supported.")
        log.error("Please debug on a more recent version of Oracle Linux.")
    return False


def ctf_finder(modules: List["Module"]):
    prog = modules[0].prog
    opts: DebugInfoOptionsExt = prog.cache["drgn_tools.debuginfo.options"]
    uname = prog["UTS_RELEASE"].string_().decode()
    version = KernelVersion.parse(uname)

    ctf_loaded = prog.cache.get("using_ctf", False)
    log.debug("ctf: enter debuginfo finder ctf_loaded=%r", ctf_loaded)

    ctf_paths = CTF_PATHS.copy()
    if opts.ctf_file:
        ctf_paths.insert(0, opts.ctf_file)

    # Internal systems may have a `vmlinux.ctfa` file in the normal vmlinux repo
    # path.
    if opts.repo_paths:
        fmtparams = version.format_params()
        ctf_paths.append(
            os.path.join(
                opts.repo_paths[-1].format(**fmtparams),
                "vmlinux.ctfa",
            )
        )

    for module in modules:
        if isinstance(module, MainModule) and not ctf_loaded:
            uname = prog["UTS_RELEASE"].string_().decode()
            for path in ctf_paths:
                path = path.format(uname=uname)
                if os.path.isfile(path) and _check_ctf_compat(prog, version):
                    load_ctf(prog, path)
                    prog.cache["using_ctf"] = True
                    ctf_loaded = True
                    module.debug_file_status = ModuleFileStatus.DONT_NEED
                    log.info("ctf: loaded %s", path)
                    break
                else:
                    log.debug("ctf: skip %s", path)
            else:
                log.debug("failed to find vmlinux.ctfa")
        elif isinstance(module, RelocatableModule) and ctf_loaded:
            # CTF contains symbols for all in-tree modules. Mark them DONT_NEED
            if not module.object.taints & TAINT_OOT_MODULE:
                module.debug_file_status = ModuleFileStatus.DONT_NEED


@lru_cache(maxsize=1)
def _debug_info_finders() -> (
    Tuple[DebugInfoOptionsExt, List[Tuple[str, Optional[int], Any]]]
):
    """
    Return debug info finders as configured by the user

    If the drgn-tools configuration file has debuginfo related configuration,
    this creates the required fetchers and returns them. If no configuration is
    present, then we check if the REPO_DIR exists, and if so, we return the
    VmlinuxRepoFetcher. Otherwise, we return an empty list.
    """
    config = get_config()

    # The path of the "vmlinux repo" where drgn-tools searches for DWARF files,
    # and also where it will extract them.
    repo_format = config.get("debuginfo", "vmlinux_repo", fallback=None)
    if repo_format is None:
        if os.path.isdir("/share/linuxrpm/vmlinux_repo"):
            repo_format = "/share/linuxrpm/vmlinux_repo/{bits}/{uname}"
        else:
            repo_format = str(Path.home()) + "/vmlinux_repo/{bits}/{uname}"

    # The path where the local finder checks if there is a debuginfo RPM.
    path_format = config.get("debuginfo", "rpm_path_format", fallback=None)
    if path_format is None:
        if os.path.isdir("/share/linuxrpm/debuginfo-rpms"):
            path_format = "/share/linuxrpm/debuginfo-rpms/build-output-{olver}-debuginfo/{rpm}"
        else:
            path_format = str(Path.home()) + "/vmlinux_repo/{bits}/rpms/{rpm}"

    # Finding RPMs via Yum / remote URL fetching is disabled by default:
    # drgn-tools should never make network requests without the user explicitly
    # enabling it.
    urls = config.get("debuginfo", "urls", fallback=None)
    if urls:
        url_list = urls.split()
    else:
        url_list = ["https://oss.oracle.com/ol{olver}/debuginfo/{rpm}"]
    enable_download = config.get(
        "debuginfo", "enable_download", fallback="f"
    ).lower() in ("t", "true", "1", "y", "yes")
    rpm_cache = config.get("debuginfo", "rpm_cache", fallback="f").lower() in (
        "t",
        "true",
        "1",
        "y",
        "yes",
    )

    opts = DebugInfoOptionsExt(
        repo_paths=[repo_format],
        local_path=path_format,
        urls=url_list,
        ctf_file=None,
        rpm_cache=rpm_cache,
    )

    # The end result here is that, when registered, the fetchers should be
    # ordered as follows:
    #
    # 1. "ol-vmlinux-repo" - because it's quite efficient to check
    # 2. All standard drgn debuginfo finding logic ...
    # 3. "ol-local-rpm" - it's also efficient to check. Most people don't have a
    #    directory full of debuginfo RPMs, so for customers it doesn't matter.
    #    We use this internally to access a remote filesystem mount.
    # 4. IF ENABLED, "ol-download" - requires network access and it's not quick
    #    to fetch, so this is disabled by default. However, it can be enabled on
    #    the command line or by the config file.
    # 5. "ctf" - This is last, so that if we find any DWARF debuginfo, we'll use
    #    it first.
    return opts, [
        ("ol-vmlinux-repo", 0, ol_vmlinux_repo_finder),
        ("ol-local-rpm", -1, ol_local_rpm_finder),
        ("ol-download", -1 if enable_download else None, ol_download_finder),
        ("ctf", None, ctf_finder),
    ]


def drgn_prog_set(prog: Program) -> None:
    if not prog.flags & ProgramFlags.IS_LINUX_KERNEL:
        return
    opts, finders = _debug_info_finders()
    prog.cache["drgn_tools.debuginfo.options"] = opts
    for name, enable_idx, finder in finders:
        prog.register_debug_info_finder(name, finder, enable_index=enable_idx)


def update_debug_info_policy(
    prog: Program,
    dwarf_only: bool = False,
    ctf_only: bool = False,
    ctf_file: Optional[str] = None,
    dwarf_path: Optional[str] = None,
    enable_download: Optional[bool] = None,
) -> None:
    """
    Configure the debug info finders on a program based on CLI arguments

    Once the finders are registered, we can still customize their behavior based
    on the command line argument, for example provided to corelens. This allows
    the user to control, for example, whether CTF gets used, or whether we
    enable downloading RPMs from Yum.

    :param dwarf_only: if set, then CTF will be disabled
    :param ctf_only: if set, then CTF will be the only registered debuginfo
      finder
    :param ctf_file: provide an explicit path to load the CTF from
    :param dwarf_path: provide an explicit path to find DWARF from. This can be
      interpreted in two ways: first, as a directory which contains the vmlinux
      and .ko files. Second, as a directory into which the debuginfo RPM was
      extracted.
    :param enable_download: if set to a non-None value, then we will enable or
      disable the URL finder, depending on that value. When unset, the
      configured behavior is left.
    """
    finders = prog.enabled_debug_info_finders()
    if dwarf_only and "ctf" in finders:
        finders.remove("ctf")
    if ctf_only:
        finders = ["ctf"]
    if enable_download and "ol-download" not in finders:
        if "ctf" in finders:
            finders.insert(finders.index("ctf"), "ol-download")
        else:
            finders.append("ol-download")
    if enable_download is False and "ol-download" in finders:
        finders.remove("ol-download")
    prog.set_enabled_debug_info_finders(finders)
    opts: DebugInfoOptionsExt = prog.cache["drgn_tools.debuginfo.options"]
    if ctf_file:
        opts.ctf_file = ctf_file
    if dwarf_path:
        opts.repo_paths.insert(0, dwarf_path)
        debug_dir = os.path.abspath(os.path.join(dwarf_path, "usr/lib/debug"))
        if os.path.isdir(debug_dir):
            drgn_opts = prog.debug_info_options
            prog.debug_info_options = DebugInfoOptions(
                drgn_opts, directories=drgn_opts.directories + (debug_dir,)
            )


def extract_rpm(
    source_rpm: Path,
    dest_dir: Path,
    modules: List[str],
    permissions: Optional[int] = None,
) -> Dict[str, Path]:
    log.info(
        "extracting %d debuginfo modules (%s) from %s...",
        len(modules),
        ", ".join(f"{s}" for s in modules[:3])
        + ("..." if len(modules) > 3 else ""),
        source_rpm,
    )
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
            if module in ("vmlinux", "kernel"):
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
                log.warning("wat")
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
