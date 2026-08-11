# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Rootfs build and validation for testing.vm."""
import argparse
import contextlib
import inspect
import os
import shutil
import subprocess
from pathlib import Path

from testing.util import builddir
from testing.vm.config import APPSTREAM_PYTHONS
from testing.vm.config import Architecture
from testing.vm.config import OLVersion
from testing.vm.config import Rootfs
from testing.vm.config import TestDirectories
from testing.vm.logging import VmLogger


def _validate_rootfs(path: Path) -> None:
    expected = [
        "bin/bash",
        "usr/bin/fio",
        "usr/bin/python3",
        "usr/bin/make",
        "usr/bin/gcc",
    ]
    for relpath in expected:
        fullpath = path / relpath
        if not (fullpath.is_file() or fullpath.is_symlink()):
            raise RuntimeError(f"Rootfs is missing required file: {fullpath}")


def _build_rootfs(
    rootfs: Rootfs,
    build_dir: Path,
    output_log: Path,
    log: VmLogger,
) -> None:
    if not shutil.which("podman"):
        raise RuntimeError("podman is required to build rootfs")

    build_dir.mkdir(parents=True, exist_ok=True)

    # The necessary RPMs for running drgn-tools tests within a VM, and
    # also building a kernel module.
    rpm_list = [
        "drgn",
        "python3",
        "bash",
        "coreutils",
        "findutils",
        "fio",
        "gcc",
        "make",
        "binutils-devel",
        "dwarves",
        "hostname",
        "util-linux",  # needed for "setsid" command
        # Following commands are not strictly necessary, but make it far easier
        # to install custom packages into the rootfs ad-hoc.
        "dnf",
        f"oraclelinux-release-el{rootfs.ol_ver}",
    ]
    for pyver in APPSTREAM_PYTHONS[rootfs.ol_ver]:
        rpm_list.append(f"{pyver.value}-drgn")
    if rootfs.ol_ver == OLVersion.OL8:
        rpm_list.extend(
            [
                # For UEK7 module build
                "gcc-toolset-11-gcc",
                "gcc-toolset-11-binutils-devel",
                # For RHCK module build (ORC generation)
                "elfutils-libelf-devel",
            ]
        )
    elif rootfs.ol_ver == OLVersion.OL9:
        rpm_list.extend(
            [
                # Required since OL9, fio engine
                "fio-engine-libaio",
                # For UEK8 module build
                "gcc-toolset-14-gcc",
                "gcc-toolset-14-binutils-devel",
            ]
        )
    elif rootfs.ol_ver == OLVersion.OL10:
        rpm_list.extend(
            [
                # Required since OL9, fio engine
                "fio-engine-libaio",
            ]
        )
    else:
        raise ValueError(
            f"Invalid ol_ver={rootfs.ol_ver}, we support 8, 9, 10"
        )
    rpms = " ".join(rpm_list)
    install_cmd = inspect.cleandoc(
        f"""
        set -euo pipefail
        dnf -y --releasever={rootfs.ol_ver} --installroot=/rootfs \\
               --setopt=install_weak_deps=False \\
               --setopt=tsflags=nodocs \\
               --enablerepo=ol{rootfs.ol_ver}_addons \\
               --enablerepo=ol{rootfs.ol_ver}_codeready_builder \\
               --refresh \\
               install {rpms}
        dnf -y --installroot=/rootfs clean all;
        rm -rf /rootfs/var/cache/dnf
    """
    )

    command = [
        "podman",
        "run",
        "--rm",
        "--mount",
        f"type=bind,src={build_dir},dst=/rootfs,relabel=private",
        f"oraclelinux:{rootfs.ol_ver}",
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
        )
        _validate_rootfs(building_dir)
        os.rename(building_dir, final_dir)
    except BaseException:
        _rmtree_rootfs(building_dir)
        raise

    log.done("build rootfs", final_dir)
    return final_dir


def build_rootfses():
    supported_ol_vers = [v.value for v in OLVersion if v.value > 7]
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
        "--rebuild",
        help="Delete old rootfs and rebuild",
        action="store_true",
    )
    parser.add_argument(
        "versions",
        nargs="*",
        type=int,
        choices=supported_ol_vers,
        help=f"OL rootfs version to build (default: {' '.join(map(str, supported_ol_vers))})",
    )
    args = parser.parse_args()
    layout = TestDirectories.create(base_dir=args.base_dir)
    log = VmLogger(args.verbose, False)
    versions = args.versions or supported_ol_vers
    for version in versions:
        rootfs = Rootfs(OLVersion(version), Architecture.host_arch())
        dir_ = layout.rootfs_path(rootfs)
        if args.rebuild and dir_.exists():
            _rmtree_rootfs(dir_)
        ensure_rootfs(rootfs, layout, log)


if __name__ == "__main__":
    build_rootfses()
