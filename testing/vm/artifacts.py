# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Kernel RPM download/extract orchestration for testing.vm."""
import os
import shutil
from pathlib import Path
from typing import NamedTuple

from testing.litevm.rpm import extract_rpms
from testing.litevm.rpm import TestKernel


class KernelArtifacts(NamedTuple):
    release: str
    extract_dir: Path


def ensure_kernel_artifacts(
    kernel: TestKernel,
    extract_root: Path,
    yum_cache_dir: Path,
    skip_fetch: bool = False,
) -> KernelArtifacts:
    kernel.cache_dir = yum_cache_dir
    release = kernel.latest_release()

    out_dir = extract_root / release
    if out_dir.is_dir():
        return KernelArtifacts(release=release, extract_dir=out_dir)

    building_dir = extract_root / f"{release}.building"
    if building_dir.exists():
        if building_dir.is_dir():
            shutil.rmtree(building_dir)
        else:
            building_dir.unlink()

    if skip_fetch:
        raise RuntimeError(
            f"Extracted kernel artifacts do not exist: {out_dir} "
            "(disable --skip-rpm-fetch)"
        )

    extract_root.mkdir(parents=True, exist_ok=True)
    try:
        extract_rpms(kernel.get_rpms(), building_dir, kernel)
        os.rename(building_dir, out_dir)
    except BaseException:
        shutil.rmtree(building_dir)
        raise

    return KernelArtifacts(release=release, extract_dir=out_dir)
