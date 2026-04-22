# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Configuration objects and target matrix for testing.vm."""
from dataclasses import dataclass
from pathlib import Path
from typing import List
from typing import Union

from testing.litevm.rpm import TestKernel
from testing.util import BASE_DIR


@dataclass(frozen=True)
class VmTarget:
    name: str
    ol_ver: int
    uek_ver: Union[int, str]
    arch: str
    kernel: TestKernel


@dataclass(frozen=True)
class VmPaths:
    extract_dir: Path
    yum_cache_dir: Path
    rootfs_dir: Path
    work_dir: Path

    @property
    def kmod_dir(self) -> Path:
        return self.work_dir / "kmod"

    @property
    def logs_dir(self) -> Path:
        return self.work_dir / "logs"

    @property
    def junit_dir(self) -> Path:
        return self.work_dir / "junit"


def default_paths() -> VmPaths:
    work_dir = BASE_DIR / "vm"
    return VmPaths(
        extract_dir=BASE_DIR / "rpmextract",
        yum_cache_dir=BASE_DIR / "yumcache",
        rootfs_dir=work_dir / "rootfs",
        work_dir=work_dir,
    )


def _kernel_for_uek(
    ol_ver: int,
    uek_ver: Union[int, str],
    arch: str,
) -> TestKernel:
    if uek_ver == "next":
        return TestKernel(
            ol_ver,
            uek_ver,
            arch,
            [
                "kernel-ueknext-core",
                "kernel-ueknext-modules",
                "kernel-ueknext-modules-core",
                "kernel-ueknext-devel",
            ],
            yum_fmt=(
                "https://yum.oracle.com/repo/OracleLinux/OL{ol_ver}/"
                "developer/UEK{uek_ver}/{arch}/"
            ),
            pkgbase="kernel-ueknext",
        )
    elif uek_ver == 8:
        return TestKernel(
            ol_ver,
            uek_ver,
            arch,
            [
                "kernel-uek-core",
                "kernel-uek-modules",
                "kernel-uek-modules-core",
                "kernel-uek-devel",
            ],
        )
    elif uek_ver == 7:
        return TestKernel(
            ol_ver,
            uek_ver,
            arch,
            [
                "kernel-uek-core",
                "kernel-uek-modules",
                "kernel-uek-devel",
            ],
        )
    elif uek_ver == 6:
        return TestKernel(
            ol_ver,
            uek_ver,
            arch,
            [
                "kernel-uek",
                "kernel-uek-devel",
            ],
        )
    raise ValueError(f"Unsupported UEK target: UEK{uek_ver}")


def _target(ol_ver: int, uek_ver: Union[int, str], arch: str) -> VmTarget:
    uek_suffix = "ueknext" if uek_ver == "next" else f"uek{uek_ver}"
    name = f"ol{ol_ver}-{uek_suffix}-{arch}"
    return VmTarget(
        name=name,
        ol_ver=ol_ver,
        uek_ver=uek_ver,
        arch=arch,
        kernel=_kernel_for_uek(ol_ver, uek_ver, arch),
    )


TARGETS: List[VmTarget] = [
    _target(10, "next", "x86_64"),
    _target(10, 8, "x86_64"),
    _target(9, "next", "x86_64"),
    _target(9, 8, "x86_64"),
    _target(9, 7, "x86_64"),
    _target(8, 7, "x86_64"),
    _target(8, 6, "x86_64"),
]
