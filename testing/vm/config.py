# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Configuration objects and target matrix for testing.vm."""
from pathlib import Path
from typing import List
from typing import NamedTuple
from typing import Union


SHARED_FS_AUTO = "auto"
SHARED_FS_9P = "9p"
SHARED_FS_VIRTIOFS = "virtiofs"
SHARED_FS_CHOICES = (SHARED_FS_AUTO, SHARED_FS_9P, SHARED_FS_VIRTIOFS)
SUPPORTED_SHARED_FS = (SHARED_FS_9P, SHARED_FS_VIRTIOFS)


class KernelCategory(NamedTuple):
    ol_ver: int
    uek_ver: Union[int, str]
    arch: str

    @property
    def uek_name(self) -> str:
        return "ueknext" if self.uek_ver == "next" else f"uek{self.uek_ver}"

    @property
    def name(self) -> str:
        return f"ol{self.ol_ver}-{self.uek_name}-{self.arch}"

    @property
    def slug(self) -> str:
        return f"ol{self.ol_ver}uek{self.uek_ver}{self.arch}"

    @property
    def rpmbase(self) -> str:
        if self.uek_ver == "next":
            return "kernel-ueknext"
        else:
            return "kernel-uek"

    def rpms(self) -> List[str]:
        if self.uek_ver in ("next", 8):
            subpkgs = ["-core", "-modules", "-modules-core", "-devel"]
        elif self.uek_ver == 7:
            subpkgs = ["-core", "-modules", "-devel"]
        elif self.uek_ver in (4, 5, 6):
            subpkgs = ["", "-devel"]
        else:
            raise ValueError(f"Unsupported UEK target '{self.uek_ver}'")
        return [f"{self.rpmbase}{subpkg}" for subpkg in subpkgs]

    @property
    def shared_fs(self) -> str:
        if self.uek_ver == 6:
            return SHARED_FS_9P
        return SHARED_FS_VIRTIOFS


class KernelVer(NamedTuple):
    category: KernelCategory
    release: str
    urls: List[str]


class VmLayout(NamedTuple):
    base_dir: Path

    @property
    def extract_dir(self) -> Path:
        return self.base_dir / "rpmextract"

    @property
    def yum_cache_dir(self) -> Path:
        return self.base_dir / "yumcache"

    @property
    def work_dir(self) -> Path:
        return self.base_dir / "vm"

    @property
    def rootfs_dir(self) -> Path:
        return self.work_dir / "rootfs"

    @property
    def kmod_dir(self) -> Path:
        return self.work_dir / "kmod"

    @property
    def logs_dir(self) -> Path:
        return self.work_dir / "logs"

    def rootfs_path(self, ol_ver: int) -> Path:
        return self.rootfs_dir / f"ol{ol_ver}"

    def extract_path(self, release: str) -> Path:
        return self.extract_dir / release

    def kmod_path(self, release: str) -> Path:
        return self.kmod_dir / release / "drgntools_test.ko"

    def log_path(self, target_name: str, mode_name: str) -> Path:
        return self.logs_dir / target_name / f"{mode_name}.log"


TARGETS = [
    KernelCategory(10, "next", "x86_64"),
    KernelCategory(10, 8, "x86_64"),
    KernelCategory(9, "next", "x86_64"),
    KernelCategory(9, 8, "x86_64"),
    KernelCategory(9, 7, "x86_64"),
    KernelCategory(8, 7, "x86_64"),
    KernelCategory(8, 6, "x86_64"),
]
