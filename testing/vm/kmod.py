# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Kernel module build orchestration for testing.vm."""
import shutil
from pathlib import Path

from testing.vm.chroot import BindMount
from testing.vm.chroot import run_in_chroot
from testing.vm.config import KernelVer
from testing.vm.config import VmLayout
from testing.vm.logging import VmLogger


def ensure_kmod(
    rootfs: Path,
    kernel: KernelVer,
    repo_root: Path,
    layout: VmLayout,
    log: VmLogger,
    skip_build: bool = False,
) -> Path:
    repo_root = repo_root.absolute()
    source_dir = repo_root / "testing/kmod"
    source_file = source_dir / "drgntools_test.c"

    release = kernel.release
    out_path = layout.kmod_path(release)
    out_dir = out_path.parent
    if (
        out_path.is_file()
        and out_path.stat().st_mtime >= source_file.stat().st_mtime
    ):
        log.already_present("kernel module", out_path)
        return out_path

    if skip_build:
        raise RuntimeError(
            f"Kernel module does not exist: {out_path} "
            "(disable --skip-kmod-build)"
        )

    out_dir.mkdir(parents=True, exist_ok=True)

    extract_root = layout.extract_dir.absolute()
    kernel_dir = extract_root / release / "usr/src/kernels" / release

    if not kernel_dir.is_dir():
        raise RuntimeError(f"Kernel build tree not found: {kernel_dir}")

    source_module = source_dir / "drgntools_test.ko"
    if source_module.exists():
        source_module.unlink()

    command_parts = ["set -euo pipefail"]

    if kernel.category.ol_ver == 8 and kernel.category.uek_ver == 7:
        command_parts.append("source /opt/rh/gcc-toolset-11/enable")
    elif kernel.category.ol_ver == 9 and kernel.category.uek_ver in (
        8,
        "next",
    ):
        command_parts.append("source /opt/rh/gcc-toolset-14/enable")

    make = (
        f"make -C /mnt/extract/{release}/usr/src/kernels/{release} "
        "M=/mnt/repo/testing/kmod"
    )
    command_parts.extend(
        [
            f"{make} clean",
            f"{make} modules",
        ]
    )

    run_in_chroot(
        rootfs,
        " ; ".join(command_parts),
        binds=[
            BindMount(
                source=repo_root, destination="/mnt/repo", readonly=False
            ),
            BindMount(
                source=extract_root, destination="/mnt/extract", readonly=False
            ),
        ],
        verbose=log.verbose,
    )

    if not source_module.is_file():
        raise RuntimeError(
            "Kernel module build completed but output was not produced: "
            f"{source_module}"
        )

    shutil.copy2(source_module, out_path)
    log.built("kernel module", out_path)

    return out_path
