# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Kernel module build orchestration for testing.vm."""
import shutil
from pathlib import Path

from testing.vm.chroot import BindMount
from testing.vm.chroot import run_in_chroot
from testing.vm.config import VmTarget


def ensure_kmod(
    rootfs: Path,
    target: VmTarget,
    release: str,
    repo_root: Path,
    extract_root: Path,
    out_root: Path,
    skip_build: bool = False,
) -> Path:
    out_dir = out_root / release
    out_path = out_dir / "drgntools_test.ko"
    if out_path.is_file():
        return out_path

    if skip_build:
        raise RuntimeError(
            f"Kernel module does not exist: {out_path} "
            "(disable --skip-kmod-build)"
        )

    out_dir.mkdir(parents=True, exist_ok=True)

    repo_root = repo_root.absolute()
    extract_root = extract_root.absolute()
    source_dir = repo_root / "testing/kmod"
    kernel_dir = extract_root / release / "usr/src/kernels" / release

    if not kernel_dir.is_dir():
        raise RuntimeError(f"Kernel build tree not found: {kernel_dir}")

    source_module = source_dir / "drgntools_test.ko"
    if source_module.exists():
        source_module.unlink()

    command_parts = ["set -euo pipefail"]

    if target.ol_ver == 8 and target.uek_ver == 7:
        command_parts.append("source /opt/rh/gcc-toolset-11/enable")
    elif target.ol_ver == 9 and target.uek_ver in (8, "next"):
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
            BindMount(source=repo_root, destination="/mnt/repo"),
            BindMount(source=extract_root, destination="/mnt/extract"),
        ],
    )

    if not source_module.is_file():
        raise RuntimeError(
            "Kernel module build completed but output was not produced: "
            f"{source_module}"
        )

    shutil.copy2(source_module, out_path)

    return out_path
