# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Rootfs build and validation for testing.vm."""
import argparse
import contextlib
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import List
from typing import Optional

from testing.config import APPSTREAM_PYTHONS
from testing.config import Architecture
from testing.config import KERNEL_TOOLSETS
from testing.config import OLVersion
from testing.config import Rootfs
from testing.config import TestDirectories
from testing.config import yumvars_from_host
from testing.util import builddir
from testing.vm.logging import VmLogger


def have_ol7_rootfs(layout: TestDirectories) -> bool:
    rootfs = layout.rootfs_path(
        Rootfs(OLVersion.OL7, Architecture.host_arch())
    )
    return rootfs.is_dir()


def _validate_rootfs(path: Path) -> None:
    expected = [
        "bin/bash",
        "usr/bin/fio",
        "usr/bin/python3",
        "usr/bin/make",
        "usr/bin/gcc",
        "usr/bin/drgn",
    ]
    for relpath in expected:
        fullpath = path / relpath
        if not (fullpath.is_file() or fullpath.is_symlink()):
            raise RuntimeError(f"Rootfs is missing required file: {fullpath}")


def _format_urls(rootfs: Rootfs, urls: List[str]) -> List[str]:
    fmtdict = {
        "ol_ver": rootfs.ol_ver.value,
        "arch": rootfs.arch.value,
    }
    res = []
    for url in urls:
        res.append(url.format_map(fmtdict))
    return res


OL7_COMMAND = """
set -euo pipefail
mkdir -p /rootfs/etc/yum/vars
echo -n {ociregion} >/rootfs/etc/yum/vars/ociregion
echo -n {ociregion} >/etc/yum/vars/ociregion
echo -n {ocidomain} >/rootfs/etc/yum/vars/ocidomain
echo -n {ocidomain} >/etc/yum/vars/ocidomain
yum -y --releasever={ol_ver} --installroot=/rootfs \\
       --setopt=install_weak_deps=False \\
       --setopt=tsflags=nodocs \\
       --enablerepo=ol{ol_ver}_addons \\
       --enablerepo=ol{ol_ver}_developer \\
       --enablerepo=ol{ol_ver}_UEKR6 \\
       install {rpms}
yum -y --installroot=/rootfs clean all;
rm -rf /rootfs/var/cache/yum
"""

MODERN_COMMAND = """
set -euo pipefail
mkdir -p /rootfs/etc/yum/vars
echo -n {ociregion} >/rootfs/etc/yum/vars/ociregion
echo -n {ociregion} >/etc/yum/vars/ociregion
echo -n {ocidomain} >/rootfs/etc/yum/vars/ocidomain
echo -n {ocidomain} >/etc/yum/vars/ocidomain
dnf -y --releasever={ol_ver} --installroot=/rootfs \\
       --setopt=install_weak_deps=False \\
       --setopt=tsflags=nodocs \\
       --enablerepo=ol{ol_ver}_addons \\
       --enablerepo=ol{ol_ver}_codeready_builder \\
       --refresh \\
       install {rpms}
dnf -y --installroot=/rootfs clean all;
rm -rf /rootfs/var/cache/dnf
"""


def _build_rootfs(
    rootfs: Rootfs,
    build_dir: Path,
    output_log: Path,
    log: VmLogger,
    urls: List[str],
    image: Optional[str],
) -> None:
    if not shutil.which("podman"):
        raise RuntimeError("podman is required to build rootfs")

    build_dir.mkdir(parents=True, exist_ok=True)

    dnf = "dnf"
    if rootfs.ol_ver == OLVersion.OL7:
        dnf = "yum"

    # The necessary RPMs for running drgn-tools tests within a VM, and
    # also building a kernel module.
    rpm_list = [
        "drgn",
        "python3",
        "bash",
        "coreutils",
        "findutils",
        "fio",
        "fuse3-libs",
        "gcc",
        "make",
        "binutils-devel",
        "hostname",
        "util-linux",  # needed for "setsid" command
        # Following commands are not strictly necessary, but make it far easier
        # to install custom packages into the rootfs ad-hoc.
        dnf,
        f"oraclelinux-release-el{rootfs.ol_ver}",
        *_format_urls(rootfs, urls),
    ]

    # Include the extra pythonx.xx-drgn RPMs
    for pyver in APPSTREAM_PYTHONS[rootfs.ol_ver]:
        rpm_list.append(f"{pyver.value}-drgn")

    # Include the necessary toolset RPMs for building kernel modules
    toolsets = set(v for k, v in KERNEL_TOOLSETS.items() if k.rootfs == rootfs)
    for toolset in toolsets:
        rpm_list.extend(
            [
                f"{toolset}-gcc",
                f"{toolset}-binutils-devel",
            ]
        )
        if rootfs.ol_ver == OLVersion.OL8:
            rpm_list.append(f"{toolset}-elfutils-libelf-devel")

    # OL7 requires libdtrace-ctf for kernel module build
    if rootfs.ol_ver.value == 7:
        rpm_list.extend(["libdtrace-ctf", "elfutils-libelf"])

    # The OL8 RHCK requires elfutils-libelf-devel for ORC generation
    if rootfs.ol_ver.value == 8:
        rpm_list.append("elfutils-libelf-devel")

    # OL8 and later require dwarves for kernel module build
    if rootfs.ol_ver.value >= 8:
        rpm_list.append("dwarves")

    # Since OL9, fio needs an engine to run
    if rootfs.ol_ver.value >= 9:
        rpm_list.append("fio-engine-libaio")

    rpms = " ".join(rpm_list)
    if rootfs.ol_ver == OLVersion.OL7:
        install_cmd = OL7_COMMAND.format(
            ol_ver=7,
            rpms=rpms,
            **{k: shlex.quote(v) for k, v in yumvars_from_host().items()},
        )
    else:
        install_cmd = MODERN_COMMAND.format(
            ol_ver=rootfs.ol_ver.value,
            rpms=rpms,
            **{k: shlex.quote(v) for k, v in yumvars_from_host().items()},
        )

    if image is None:
        image = os.environ.get("IMAGE", "oraclelinux")

    command = [
        "podman",
        "run",
        "--rm",
        "--mount",
        f"type=bind,src={build_dir},dst=/rootfs,relabel=private",
        f"{image}:{rootfs.ol_ver}",
        "bash",
        "-lc",
        install_cmd,
    ]
    with contextlib.ExitStack() as stack:
        stdout = None
        stderr = None

        # Redirect stdout to file unless verbose
        if not log.verbose:
            output_log.parent.mkdir(parents=True, exist_ok=True)
            stdout = stack.enter_context(output_log.open("wb"))
            stderr = subprocess.STDOUT

        subprocess.run(command, stdout=stdout, stderr=stderr, check=True)


def _rmtree_rootfs(path: Path) -> None:
    if not path.is_dir():
        path.unlink()
        return

    for root, dirs, files in os.walk(str(path)):
        # The rootfs contains many directories which have 555 permissions.
        # This blocks modifying the contents of any of the directories,
        # including deleting them. The resulting error makes the user want to
        # use sudo, which works reasonably safely, but is not necessary. Just
        # set the proper directory permissions.
        Path(root).chmod(0o755)
    shutil.rmtree(str(path))


def ensure_rootfs(
    rootfs: Rootfs,
    layout: TestDirectories,
    log: VmLogger,
    skip_build: bool = False,
    urls: List[str] = [],
    image: Optional[str] = None,
) -> Path:
    final_dir = layout.rootfs_path(rootfs)
    if final_dir.is_dir():
        _validate_rootfs(final_dir)
        log.already_done("build rootfs", final_dir)
        return final_dir

    if skip_build:
        raise RuntimeError(
            f"Rootfs {final_dir} does not exist (disable --skip-rootfs-build)"
        )
    log.working("build rootfs", final_dir)

    building_dir = builddir(final_dir, rmtree=_rmtree_rootfs)

    try:
        _build_rootfs(
            rootfs,
            building_dir,
            layout.logs_dir / f"rootfs-build-{rootfs.name}.log",
            log,
            urls,
            image,
        )
        _validate_rootfs(building_dir)
        os.rename(building_dir, final_dir)
    except BaseException:
        _rmtree_rootfs(building_dir)
        raise

    log.done("build rootfs", final_dir)
    return final_dir


def build_rootfses():
    # It is possible to build an OL7 rootfs. However, it requires drgn RPMs
    # which have never been publicly released for OL7, which need to be provided
    # with --rpm-url. Include it as an option for advanced users, but don't
    # include it in the default rootfs set.
    supported_ol_vers = [v.value for v in OLVersion]
    default_ol_vers = [v.value for v in OLVersion if v.value > 7]
    parser = argparse.ArgumentParser(description="rootfs builder")
    parser.add_argument(
        "--base-dir",
        type=Path,
        help="Test data base directory",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print detailed progress",
    )
    parser.add_argument(
        "--rpm-url",
        "-u",
        action="append",
        default=[],
        help="Add formatted URLs to the RPM installation list",
    )
    parser.add_argument(
        "--rebuild",
        help="Delete old rootfs and rebuild",
        action="store_true",
    )
    parser.add_argument(
        "--image",
        help="Choose the container image used to bootstrap. The default "
        "is 'oraclelinux' or the $IMAGE environment variable, but a "
        "fully qualified URL may be provided here to use a local cache.",
    )
    parser.add_argument(
        "versions",
        nargs="*",
        type=int,
        choices=supported_ol_vers,
        help=f"OL rootfs version to build (default: {' '.join(map(str, default_ol_vers))})",
    )
    args = parser.parse_args()
    layout = TestDirectories.create(base_dir=args.base_dir)
    log = VmLogger(args.verbose, False)
    versions = args.versions or default_ol_vers
    for version in versions:
        rootfs = Rootfs(OLVersion(version), Architecture.host_arch())
        dir_ = layout.rootfs_path(rootfs)
        if args.rebuild and dir_.exists():
            _rmtree_rootfs(dir_)
        ensure_rootfs(rootfs, layout, log, urls=args.rpm_url, image=args.image)


if __name__ == "__main__":
    build_rootfses()
