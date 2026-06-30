# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Rootfs build and validation for testing.vm."""
import contextlib
import inspect
import os
import shutil
import subprocess
from pathlib import Path

from testing.vm.config import KernelCategory
from testing.vm.config import VmLayout
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
    ol_ver: int,
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
        "python3-pip",
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
        f"oraclelinux-release-el{ol_ver}",
    ]
    if ol_ver == 8:
        rpm_list.extend(
            [
                # For UEK7 module build
                "gcc-toolset-11-gcc",
                "gcc-toolset-11-binutils-devel",
                # For RHCK module build (ORC generation)
                "elfutils-libelf-devel",
            ]
        )
    elif ol_ver == 9:
        rpm_list.extend(
            [
                # For UEK8 module build
                "gcc-toolset-14-gcc",
                "gcc-toolset-14-binutils-devel",
            ]
        )
    if ol_ver >= 9:
        rpm_list.append("fio-engine-libaio")
    rpms = " ".join(rpm_list)
    install_cmd = inspect.cleandoc(
        f"""
        set -euo pipefail
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
    )

    command = [
        "podman",
        "run",
        "--rm",
        "--mount",
        f"type=bind,src={build_dir},dst=/rootfs,relabel=private",
        f"oraclelinux:{ol_ver}",
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
    category: KernelCategory,
    layout: VmLayout,
    log: VmLogger,
    skip_build: bool = False,
) -> Path:
    layout.rootfs_dir.mkdir(parents=True, exist_ok=True)

    final_dir = layout.rootfs_path(category.ol_ver)
    if final_dir.is_dir():
        _validate_rootfs(final_dir)
        log.already_done("build rootfs", final_dir)
        return final_dir

    if skip_build:
        raise RuntimeError(
            f"Rootfs {final_dir} does not exist (disable --skip-rootfs-build)"
        )
    log.working("build rootfs", final_dir)

    building_dir = layout.rootfs_dir / f"ol{category.ol_ver}.building"
    if building_dir.exists():
        _rmtree_rootfs(building_dir)

    try:
        _build_rootfs(
            category.ol_ver,
            building_dir,
            layout.logs_dir / "rootfs" / f"ol{category.ol_ver}.log",
            log,
        )
        _validate_rootfs(building_dir)
        os.rename(building_dir, final_dir)
    except BaseException:
        _rmtree_rootfs(building_dir)
        raise

    log.done("build rootfs", final_dir)
    return final_dir
