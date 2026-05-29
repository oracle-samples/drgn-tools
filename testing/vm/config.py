# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Configuration objects and target matrix for testing.vm."""
import enum
from pathlib import Path
from typing import List
from typing import NamedTuple


SHARED_FS_AUTO = "auto"
SHARED_FS_9P = "9p"
SHARED_FS_VIRTIOFS = "virtiofs"
SHARED_FS_CHOICES = (SHARED_FS_AUTO, SHARED_FS_9P, SHARED_FS_VIRTIOFS)
SUPPORTED_SHARED_FS = (SHARED_FS_9P, SHARED_FS_VIRTIOFS)


class KernelKind(enum.Enum):
    UEK4 = "uek4"
    UEK5 = "uek5"
    UEK6 = "uek6"
    UEK7 = "uek7"
    UEK8 = "uek8"
    UEKNEXT = "ueknext"
    RHCK = "rhck"


class KernelCategory(NamedTuple):
    ol_ver: int
    kind: KernelKind
    arch: str

    @property
    def uek_ver(self) -> int:
        if self.kind in (KernelKind.UEKNEXT, KernelKind.RHCK):
            raise ValueError(f"{self.kind.name} has no UEK version")
        return int(self.kind.name[3:])

    @property
    def name(self) -> str:
        return f"ol{self.ol_ver}-{self.kind.value}-{self.arch}"

    @property
    def slug(self) -> str:
        return f"ol{self.ol_ver}{self.kind.value}{self.arch}"

    @property
    def rpmbase(self) -> str:
        if self.kind == KernelKind.UEKNEXT:
            return "kernel-ueknext"
        elif self.kind == KernelKind.RHCK:
            return "kernel"
        else:
            return "kernel-uek"

    def rpms(self) -> List[str]:
        if self.kind == KernelKind.RHCK:
            if self.ol_ver == 8:
                subpkgs = ["-core", "-modules", "-devel"]
            else:
                subpkgs = ["-core", "-modules-core", "-devel"]
        elif self.kind in (KernelKind.UEKNEXT, KernelKind.UEK8):
            subpkgs = ["-core", "-modules", "-modules-core", "-devel"]
        elif self.kind == KernelKind.UEK7:
            subpkgs = ["-core", "-modules", "-devel"]
        elif self.kind in (KernelKind.UEK4, KernelKind.UEK5, KernelKind.UEK6):
            subpkgs = ["", "-devel"]
        else:
            raise ValueError(
                f"Unsupported target kernel kind '{self.kind.value}'"
            )
        return [f"{self.rpmbase}{subpkg}" for subpkg in subpkgs]

    @property
    def shared_fs(self) -> str:
        if self.kind == KernelKind.UEK6:
            return SHARED_FS_9P
        elif self.kind in (KernelKind.UEK4, KernelKind.UEK5):
            raise ValueError("VM testing is not supported for UEK4, UEK5")
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
    KernelCategory(10, KernelKind.UEKNEXT, "x86_64"),
    KernelCategory(10, KernelKind.UEK8, "x86_64"),
    KernelCategory(10, KernelKind.RHCK, "x86_64"),
    KernelCategory(9, KernelKind.UEKNEXT, "x86_64"),
    KernelCategory(9, KernelKind.UEK8, "x86_64"),
    KernelCategory(9, KernelKind.UEK7, "x86_64"),
    KernelCategory(9, KernelKind.RHCK, "x86_64"),
    KernelCategory(8, KernelKind.UEK7, "x86_64"),
    KernelCategory(8, KernelKind.UEK6, "x86_64"),
    KernelCategory(8, KernelKind.RHCK, "x86_64"),
]
