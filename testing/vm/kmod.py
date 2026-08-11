# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Kernel module build orchestration for testing.vm."""
import shutil
import subprocess
from pathlib import Path

from testing.chroot import BindMount
from testing.chroot import run_in_rootfs
from testing.config import KERNEL_TOOLSETS
from testing.config import KernelVer
from testing.config import TestDirectories
from testing.vm.logging import VmLogger


def ensure_kmod(
    kernel: KernelVer,
    repo_root: Path,
    layout: TestDirectories,
    log: VmLogger,
    skip_build: bool = False,
) -> Path:
    repo_root = repo_root.absolute()
    source_dir = repo_root / "testing/kmod"
    source_file = source_dir / "drgntools_test.c"
    source_make = source_dir / "Makefile"

    max_mtime = max(source_file.stat().st_mtime, source_make.stat().st_mtime)
    out_path = layout.kmod_path(kernel)
    out_dir = out_path.parent
    if out_path.is_file() and out_path.stat().st_mtime >= max_mtime:
        log.already_done("build kmod", out_path)
        return out_path

    rootfs_dir = layout.rootfs_path(kernel.category.rootfs)
    if not rootfs_dir.is_dir():
        raise RuntimeError(f"Rootfs is missing: {rootfs_dir}")
    if skip_build:
        raise RuntimeError(
            f"Kernel module does not exist: {out_path} "
            "(disable --skip-kmod-build)"
        )
    log.working("build kmod", out_path)

    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_file, out_dir)
    shutil.copy2(source_make, out_dir)

    extract_root = layout.extract_path(kernel)
    kbuild_dir = extract_root / "usr/src/kernels" / kernel.release

    if not kbuild_dir.is_dir():
        raise RuntimeError(f"Kernel build tree not found: {kbuild_dir}")

    command_parts = ["set -euo pipefail"]

    # Source the toolset necessary to build a kmod
    toolset = KERNEL_TOOLSETS.get(kernel.category)
    if toolset:
        command_parts.append(f"source /opt/rh/{toolset}/enable")

    make = (
        f"make -C /mnt/extract/usr/src/kernels/{kernel.release} " "M=/mnt/out"
    )
    command_parts.extend(
        [
            f"{make} clean",
            f"{make} modules",
        ]
    )

    command = " ; ".join(command_parts)
    run_in_rootfs(
        rootfs_dir,
        ["sh", "-c", command],
        binds=[
            BindMount(source=out_dir, destination="/mnt/out", readonly=False),
            BindMount(
                source=extract_root,
                destination="/mnt/extract",
                readonly=True,
            ),
        ],
        stdout=None if log.verbose else subprocess.DEVNULL,
        stderr=None if log.verbose else subprocess.DEVNULL,
    )

    if not out_path.is_file():
        raise RuntimeError(
            "Kernel module build completed but output was not produced: "
            f"{out_path}"
        )
    log.done("build kmod", out_path)
    return out_path
