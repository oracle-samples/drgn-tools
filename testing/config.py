# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Configuration objects and target matrix for testing.vm."""
import enum
import platform
from pathlib import Path
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Optional


SHARED_FS_9P = "9p"
SHARED_FS_VIRTIOFS = "virtiofs"

# Don't re-fetch repomd.xml until it is at least this old. This helps keep
# things snappy during development, and avoids unexpected new kernel downloads
# during a workday.
YUM_STALE_HOURS = 12

# OCI Object Storage bucket prefix for vmcore storage.
VMCORE_PREFIX = "drgn-tools-vmcores/"

# fmt: off
UEK_YUM = "https://yum{ociregion}.{ocidomain}/repo/OracleLinux/OL{ol_ver}/UEKR{uek_ver}/{arch}/"
UEKNEXT_YUM = "https://yum{ociregion}.{ocidomain}/repo/OracleLinux/OL{ol_ver}/developer/UEKnext/{arch}/"
BASEOS_YUM = "https://yum{ociregion}.{ocidomain}/repo/OracleLinux/OL{ol_ver}/baseos/latest/{arch}/"

DEBUGINFO_URL = "https://oss.oracle.com/ol{ol_ver}/debuginfo/{pkgbase}-debuginfo-{release}.rpm"
# fmt: on

REPO_ROOT = Path(__file__).parent.parent.absolute()
BASE_DIR = REPO_ROOT / "testdata"
"""
Default directory where all testing data object should go. Should
be overridden on the CLI where necessary.
"""


def yumvars_from_host() -> Dict[str, str]:
    """
    The "ocidomain" and "ociregion" can be used to point at OCI regional caches
    of yum, which are less expensive to access. These are configured on OCI
    Oracle Linux host images, and it is in our best interest to copy those
    configurations when we can.
    """
    vars = ("ocidomain", "ociregion")
    defaults = ("oracle.com", "")
    path = Path("/etc/yum/vars/")
    values = {}
    for var, default in zip(vars, defaults):
        file = path / var
        if file.is_file():
            values[var] = file.read_text().strip()
        else:
            values[var] = default
    return values


class KernelKind(enum.Enum):
    """
    Kernel variants on Oracle Linux. Not all are supported.
    """

    UEK4 = "uek4"
    UEK5 = "uek5"
    UEK6 = "uek6"
    UEK7 = "uek7"
    UEK8 = "uek8"
    UEKNEXT = "ueknext"
    RHCK = "rhck"

    def __str__(self):
        return self.value


class OLVersion(enum.Enum):
    """
    Versions of Oracle Linux which on which we may do something with drgn.
    """

    OL7 = 7
    OL8 = 8
    OL9 = 9
    OL10 = 10

    def __str__(self):
        return str(self.value)


class Architecture(enum.Enum):
    """
    Architectures on which Oracle Linux is supported.
    """

    X86_64 = "x86_64"
    AARCH64 = "aarch64"

    def __str__(self):
        return self.value

    @classmethod
    def host_arch(cls):
        return cls(platform.machine())


class Debuginfo(enum.Enum):
    """
    Kernel debuginfo kinds for which we may run tests.
    """

    CTF = "ctf"
    DWARF = "dwarf"

    def __str__(self):
        return self.value


class PythonVer(enum.Enum):
    """
    Python versions on Oracle Linux for which drgn may be built & tested.
    """

    SYSTEM = "python3"
    PY311 = "python3.11"
    PY312 = "python3.12"
    PY314 = "python3.14"

    def __str__(self):
        return self.value


class Rootfs(NamedTuple):
    """
    Represents a root filesystem image we may build for testing.
    """

    ol_ver: OLVersion
    arch: Architecture

    @property
    def name(self) -> str:
        return f"ol{self.ol_ver}-{self.arch.value}"


class KernelCategory(NamedTuple):
    """
    Represents a specific line of kernel versions on Oracle Linux.
    """

    ol_ver: OLVersion
    kind: KernelKind
    arch: Architecture

    @property
    def uek_ver(self) -> int:
        if self.kind in (KernelKind.UEKNEXT, KernelKind.RHCK):
            raise ValueError(f"{self.kind.name} has no UEK version")
        return int(self.kind.name[3:])

    @property
    def name(self) -> str:
        return f"ol{self.ol_ver}-{self.kind}-{self.arch}"

    @property
    def rootfs(self) -> Rootfs:
        return Rootfs(self.ol_ver, self.arch)

    @property
    def rpmbase(self) -> str:
        if self.kind == KernelKind.UEKNEXT:
            return "kernel-ueknext"
        elif self.kind == KernelKind.RHCK:
            return "kernel"
        else:
            return "kernel-uek"

    def yum_repo(self) -> str:
        fmtdict = self._asdict()
        fmtdict.update(yumvars_from_host())
        if self.kind == KernelKind.UEKNEXT:
            fmt = UEKNEXT_YUM
        elif self.kind == KernelKind.RHCK:
            fmt = BASEOS_YUM
        elif (
            self.arch == Architecture.AARCH64
            and self.ol_ver in AARCH64_DEFAULT_UEK
            and self.kind == AARCH64_DEFAULT_UEK[self.ol_ver]
        ):
            # For aarch64, handle the case of the default UEK being placed in
            # baseos/latest repo.
            fmt = BASEOS_YUM
        else:
            fmt = UEK_YUM
            fmtdict["uek_ver"] = self.uek_ver
        return fmt.format_map(fmtdict)

    def rpms(self) -> List[str]:
        if self.kind == KernelKind.RHCK:
            if self.ol_ver == OLVersion.OL8:
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
    """
    Represents a specific Oracle Linux kernel version.
    """

    category: KernelCategory
    release: str
    urls: List[str]


class TestDirectories(NamedTuple):
    base_dir: Path
    vmcore_dir: Path  # may be overridden for CI's external vmcore dir

    @classmethod
    def create(
        cls,
        base_dir: Optional[Path] = None,
        vmcore_dir: Optional[Path] = None,
    ) -> "TestDirectories":
        if not base_dir:
            base_dir = BASE_DIR
        if not vmcore_dir:
            vmcore_dir = base_dir / "vmcores"
        return cls(base_dir.absolute(), vmcore_dir.absolute())

    def rootfs_path(self, rootfs: Rootfs) -> Path:
        return self.base_dir / "rootfs" / rootfs.name

    @property
    def logs_dir(self) -> Path:
        return self.base_dir / "logs"

    def vm_log_path(
        self, cat: KernelCategory, mode: Debuginfo, pyver: PythonVer
    ) -> Path:
        return (
            self.logs_dir
            / f"vm-test-{cat.name}-{mode.value}-{pyver.value}.log"
        )

    def vmcore_log_path(
        self, vmcore: str, mode: str, rootfs: str, pyver: str
    ) -> Path:
        return self.logs_dir / f"vmcore-{vmcore}-{mode}-{rootfs}-{pyver}.log"

    def target_path(self, cat: KernelCategory) -> Path:
        return self.base_dir / "vm" / cat.name

    def yum_cache_dir(self, cat: KernelCategory) -> Path:
        return self.target_path(cat) / "rpmdb"

    def kernel_path(self, ver: KernelVer) -> Path:
        return (
            self.base_dir / "vm" / ver.category.name / "kernel" / ver.release
        )

    def rpm_path(self, ver: KernelVer) -> Path:
        return self.kernel_path(ver) / "rpms"

    def extract_path(self, ver: KernelVer) -> Path:
        return self.kernel_path(ver) / "root"

    def kmod_path(self, ver: KernelVer) -> Path:
        return self.kernel_path(ver) / "kmod/drgntools_test.ko"


# These are the VM testing targets.
# fmt: off
TARGETS = {
    Architecture.X86_64: [
        KernelCategory(OLVersion.OL10, KernelKind.UEKNEXT, Architecture.X86_64),
        KernelCategory(OLVersion.OL10, KernelKind.UEK8, Architecture.X86_64),
        KernelCategory(OLVersion.OL10, KernelKind.RHCK, Architecture.X86_64),
        KernelCategory(OLVersion.OL9, KernelKind.UEKNEXT, Architecture.X86_64),
        KernelCategory(OLVersion.OL9, KernelKind.UEK8, Architecture.X86_64),
        KernelCategory(OLVersion.OL9, KernelKind.UEK7, Architecture.X86_64),
        KernelCategory(OLVersion.OL9, KernelKind.RHCK, Architecture.X86_64),
        KernelCategory(OLVersion.OL8, KernelKind.UEK7, Architecture.X86_64),
        KernelCategory(OLVersion.OL8, KernelKind.UEK6, Architecture.X86_64),
        KernelCategory(OLVersion.OL8, KernelKind.RHCK, Architecture.X86_64),
        KernelCategory(OLVersion.OL7, KernelKind.UEK6, Architecture.X86_64),
    ],
    Architecture.AARCH64: [
        KernelCategory(OLVersion.OL10, KernelKind.UEKNEXT, Architecture.AARCH64),
        KernelCategory(OLVersion.OL10, KernelKind.UEK8, Architecture.AARCH64),
        KernelCategory(OLVersion.OL9, KernelKind.UEKNEXT, Architecture.AARCH64),
        KernelCategory(OLVersion.OL9, KernelKind.UEK8, Architecture.AARCH64),
        KernelCategory(OLVersion.OL9, KernelKind.UEK7, Architecture.AARCH64),
        KernelCategory(OLVersion.OL8, KernelKind.UEK7, Architecture.AARCH64),
        KernelCategory(OLVersion.OL8, KernelKind.UEK6, Architecture.AARCH64),
    ],
}
# fmt: on

# These are the rootfs directories which need to be built for VM and vmcore
# testing.
ROOTFSES = [
    Rootfs(OLVersion.OL8, Architecture.host_arch()),
    Rootfs(OLVersion.OL9, Architecture.host_arch()),
    Rootfs(OLVersion.OL10, Architecture.host_arch()),
]

# Oracle Linux Appstream Python versions for which we currently have support.
# This can be used to automatically test drgn & drgn-tools on all supported
# appstream versions for a particular OL release, for VM & vmcore testing.
# Python 3.11 is not technically in support but has had recent packages built.
APPSTREAM_PYTHONS = {
    OLVersion.OL7: (),
    OLVersion.OL8: (
        PythonVer.PY311,
        PythonVer.PY312,
    ),
    OLVersion.OL9: (
        PythonVer.PY311,
        PythonVer.PY312,
        PythonVer.PY314,
    ),
    OLVersion.OL10: (PythonVer.PY314,),
}

# Some UEK versions use a newer compiler version than the system.
# fmt: off
KERNEL_TOOLSETS = {
    KernelCategory(OLVersion.OL9, KernelKind.UEK8, Architecture.X86_64): "gcc-toolset-14",
    KernelCategory(OLVersion.OL9, KernelKind.UEKNEXT, Architecture.X86_64): "gcc-toolset-14",
    KernelCategory(OLVersion.OL9, KernelKind.UEK8, Architecture.AARCH64): "gcc-toolset-14",
    KernelCategory(OLVersion.OL9, KernelKind.UEKNEXT, Architecture.AARCH64): "gcc-toolset-14",
    KernelCategory(OLVersion.OL8, KernelKind.UEK7, Architecture.X86_64): "gcc-toolset-11",
    KernelCategory(OLVersion.OL8, KernelKind.UEK7, Architecture.AARCH64): "gcc-toolset-11",
}
# fmt: on

# We explicitly do not package or support RHCK on aarch64: only UEK is
# available. So for each aarch64 OL version, one "default" UEK version is
# present in the baseos/latest repo rather than the standard UEK repo. Newer
# UEKs are added in standalone repos as normal.
#
# This seems to no longer be the case for OL10: UEK8 is the only kernel
# provided, and it is provided via repo ol10_UEKR8.
AARCH64_DEFAULT_UEK = {
    OLVersion.OL9: KernelKind.UEK7,
    OLVersion.OL8: KernelKind.UEK6,
    OLVersion.OL7: KernelKind.UEK5,
}
