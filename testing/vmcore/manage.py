# Copyright (c) 2024, 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Download, upload, and synchronize a collection of vmcores
"""
import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from fnmatch import fnmatch
from pathlib import Path
from typing import NamedTuple
from typing import Set

from drgn import Program
from drgn import RelocatableModule

from drgn_tools.corelens import all_corelens_modules
from drgn_tools.debuginfo import CtfCompatibility
from drgn_tools.debuginfo import DebugInfoOptionsExt
from drgn_tools.debuginfo import drgn_prog_set as register_debug_info_finders
from drgn_tools.debuginfo import get_debuginfo_config
from drgn_tools.debuginfo import KernelVersion
from drgn_tools.debuginfo import OracleDebuginfo
from drgn_tools.util import download_file
from testing.config import TestDirectories
from testing.config import VMCORE_PREFIX
from testing.parlib import ParClient


# These are the vmcore names for which we do not want to run CTF
CTF_BLACKLIST = {
    "basic-uek6",
    "ext4_dirlock-uek4",
    "ext4_dirlock-uek5",
    "ext4_dirlock-uek6",
    "md-uek4",
    "nfs-uek4",
    "nfs-uek6",
    "smp_ipi-uek5",
    "smp_ipi-uek6",
}

# These are all the kernel modules we want debuginfo extracted for, if the
# vmcore has them loaded.
# fmt: off
MODULES = {
    "ext4",
    "sunrpc", "nfs", "nfsd", "nfsv3", "nfsv4", "lockd",
    "nvme", "nvme_core",
    "raid0", "raid1", "raid456",
    "rdma_cm", "rds", "rds_rdma", "rds_tcp",
    "ib_cm", "ib_core", "ib_ipoib", "iw_cm",
    "mlx5_ib", "mlx5_core", "mlxfw",
    "virtio",
    "virtio_balloon",
    "virtio_blk",
    "virtio_console",
    "virtio_dma_buf",
    "virtio_crypto",
    "virtio_gpu",
    "virtio_input",
    "virtio_mem",
    "virtio_net",
    "virtio_pci",
    "virtio_pci_legacy_dev",
    "virtio_pci_modern_dev",
    "virtio_pmem",
    "virtio_ring",
    "virtio_rng",
    "virtio_scsi",
    "virtio_vdpa",
    "dm_historical_service_time",
    "dm_io_affinity",
    "dm_mod",
    "dm_multipath",
    "dm_queue_length",
    "dm_round_robin",
    "dm_service_time",
    "xfs",
    "qla2xxx", "lpfc", "megaraid_sas",
}
# fmt: on

PATTERNS = {
    "kvm*",
}
for module in all_corelens_modules().values():
    if module.skip_unless_have_kmods:
        MODULES.update(module.skip_unless_have_kmods)
    PATTERNS.update(module.debuginfo_kmods)


log = logging.getLogger("drgn_tools.debuginfo")
log.setLevel(logging.DEBUG)
log.addHandler(logging.StreamHandler())


def _module_matches(mod: str, patterns: Set[str]) -> bool:
    for pattern in patterns:
        if pattern.startswith("re:") and re.fullmatch(pattern[3:], mod):
            return True
        elif fnmatch(mod, pattern):
            return True
    return False


def need_module(mod: str) -> bool:
    return mod in MODULES or _module_matches(mod, PATTERNS)


class Vmcore(NamedTuple):
    name: str
    path: Path
    release: str
    prog: Program
    arch: str
    kver: KernelVersion
    dbinfo: OracleDebuginfo

    def rpm_name(self) -> str:
        uek_ver = self.kver.uek_version

        if self.kver.is_uek and uek_ver in (4, 5, 6):
            return f"kernel-uek-{self.release}.rpm"
        elif self.kver.is_uek:
            return f"kernel-uek-core-{self.release}.rpm"
        elif self.kver.ol_version >= 8:
            return f"kernel-core-{self.release}.rpm"
        else:
            return f"kernel-{self.release}.rpm"


class VmcoreManager:
    core_dir: Path
    client: ParClient
    prefix: str

    dbinfo_config: DebugInfoOptionsExt

    def __init__(self, core_dir: Path, client: ParClient, prefix: str) -> None:
        self.core_dir = core_dir
        self.client = client
        self.prefix = prefix
        self.dbinfo_config = get_debuginfo_config()
        self.dbinfo_config.enable_download = False
        self.dbinfo_config.enable_extract = False
        self.dbinfo_config.enable_ctf = False
        self.dbinfo_config.disable_dwarf = False
        self.dbinfo_config.rpm_cache = True

    def download_all(self, verbose: bool = False):
        objects = self.client.list_objects_simple(
            prefix=self.prefix, fields="size"
        )
        self.core_dir.mkdir(exist_ok=True)
        for obj in objects:
            name = obj["name"][len(self.prefix) :]
            path = self.core_dir / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_file() and path.stat().st_size == obj["size"]:
                if verbose:
                    print(f"Already exists: {name}")
            else:
                print(f"Download: {name}")
                with path.open("wb") as f:
                    shutil.copyfileobj(self.client.get_object(obj["name"]), f)

    def delete_orphans(self, verbose: bool = False):
        if verbose:
            print("Searching for orphaned files to remove...")
        objs = self.client.list_objects_simple(
            prefix=self.prefix, fields="size"
        )
        keys = set()
        for obj in objs:
            assert obj["name"].startswith(self.prefix)
            name = obj["name"][len(self.prefix) :]
            keys.add(name)

        # Iterate using list() because modifying the directory while iterating it
        # can lead to errors
        for fn in list(self.core_dir.glob("**/*")):
            if not fn.is_file():
                continue
            key = str(fn.relative_to(self.core_dir))
            if key in keys:
                continue
            print(f"Removing orphaned file: {key}")
            fn.unlink()
            parent = fn.parent
            while not list(parent.iterdir()):
                print(f"Removing empty parent: {parent}")
                parent.rmdir()
                parent = parent.parent

    def upload_core(self, core: str, verbose: bool = False) -> None:
        core_path = self.core_dir / core
        vmlinux_path = core_path / "vmlinux"
        vmcore_path = core_path / "vmcore"
        if not vmlinux_path.exists() or not vmcore_path.exists():
            sys.exit("error: missing vmcore or vmlinux file")
        uname = core_path / "UTS_RELEASE"
        if not uname.exists():
            sys.exit("error: missing UTS_RELEASE file")
        uploads = [vmlinux_path, vmcore_path, uname]
        uploads += list(core_path.glob("*.ko.debug"))
        uploads += list(core_path.glob("vmlinux.ctfa*"))
        object_to_size = {
            obj["name"]: obj["size"]
            for obj in self.client.list_objects_simple(fields="size")
        }

        for path in uploads:
            key = self.prefix + str(path.relative_to(self.core_dir))
            existing_size = object_to_size.get(key)
            size = path.stat().st_size
            if existing_size is not None and existing_size == size:
                if verbose:
                    print(f"Already uploaded: {key}")
                continue
            with path.open("rb") as f:
                print(f"Upload: {key}")
                self.client.put_object(key, f)

    def upload_all(self, verbose: bool = False) -> None:
        for subdir in self.core_dir.iterdir():
            if (subdir / "vmcore").is_file():
                self.upload_core(subdir.name, verbose=verbose)

    def _open_vmcore(self, path: Path) -> Vmcore:
        name = path.parent.name
        prog = Program()
        prog.cache["drgn_tools.debuginfo.options"] = self.dbinfo_config
        prog.set_core_dump(path)
        prog.create_loaded_modules()
        if "drgn_tools.debuginfo" not in prog.cache:
            register_debug_info_finders(prog)
        dbinfo = prog.cache["drgn_tools.debuginfo"]

        kver = dbinfo.version
        if kver.arch not in ("x86_64", "aarch64"):
            raise Exception("unsupported arch")
        arch = kver.arch

        uname = path.parent / "UTS_RELEASE"
        if not uname.exists():
            with uname.open("w") as f:
                print(f"Write UTS_RELEASE for vmcore {name}")
                f.write(kver.original)

        ctf_sup = CtfCompatibility.get(kver, host_ol=9)
        print(f"VMCORE {name} {kver.original} CTF: {ctf_sup}")
        ctf_sup = CtfCompatibility.get(kver, host_ol=7)
        print(f"VMCORE {name} {kver.original} CTF OL 7: {ctf_sup}")
        if name in CTF_BLACKLIST:
            print(f"VMCORE {name} blacklisted for CTF testing")

        return Vmcore(name, path, kver.original, prog, arch, kver, dbinfo)

    def _fetch_ctfa(self, vmcore: Vmcore) -> None:
        print(f"CTF for VMCORE: {vmcore.name}")
        if vmcore.name in CTF_BLACKLIST:
            print("     => Skip CTF (blacklist)")
            return
        dst = vmcore.path.parent / "vmlinux.ctfa"
        if dst.is_file():
            print("     => CTF Already exists!")
            return
        rpm = vmcore.rpm_name()
        url = f"https://yum.oracle.com/repo/OracleLinux/OL{vmcore.kver.ol_version}/UEKR{vmcore.kver.uek_version}/{vmcore.kver.arch}/getPackage/{rpm}"
        print(f"URL   : {url}")
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            rpm_path = tdp / rpm
            with open(rpm_path, "wb") as f:
                download_file(url, f, quiet=False)
            subprocess.run(
                f"rpm2cpio {rpm_path} | cpio -id --quiet '*/vmlinux.ctfa'",
                shell=True,
                check=True,
                cwd=tdp,
            )
            src = tdp / f"lib/modules/{vmcore.release}/kernel/vmlinux.ctfa"
            shutil.move(src, dst)

    def _fetch_dwarf(self, vmcore: Vmcore) -> None:
        print(f"DWARF for VMCORE: {vmcore.name}")
        dst = vmcore.path.parent / "vmlinux"
        repo_dir = Path(
            self.dbinfo_config.repo_paths[-1].format(
                **vmcore.kver.format_params()
            )
        )

        # Fetch vmlinux if not available. This would download and temporarily cache
        # the RPM. If it doesn't happen now, it'll happen below, if necessary.
        vmcore.dbinfo.ol_vmlinux_repo_finder([vmcore.prog.main_module()])
        if not vmcore.prog.main_module().debug_file_path:
            print("     => DWARF vmlinux not yet available, fetching...")
            vmcore.dbinfo.ol_download_finder([vmcore.prog.main_module()])
        else:
            print("     => DWARF exists for vmlinux!")

        # Now identify modules required for vmcore tests.
        mods_to_fetch = []
        for mod in vmcore.prog.modules():
            if not isinstance(mod, RelocatableModule):
                continue
            name = mod.name.replace("-", "_")
            if need_module(name):
                mods_to_fetch.append(mod)

        # If necessary, fetch the additional modules. The RPM will remain cached
        # here, so we won't incur a double-download. If they already exist
        # locally, then no download will happen.
        if mods_to_fetch:
            print("     => Fetching modules")
            vmcore.dbinfo.ol_vmlinux_repo_finder(mods_to_fetch)
            vmcore.dbinfo.ol_download_finder(mods_to_fetch)

        # Now, the modules should all be local. Ensure all files are present in
        # the vmcore directory.
        for mod in [vmcore.prog.main_module()] + mods_to_fetch:
            name = mod.name.replace("-", "_")
            if mod.name == "kernel":
                file = "vmlinux"
            else:
                file = f"{name}.ko.debug"

            repo = repo_dir / file
            dst = vmcore.path.parent / file

            if dst.is_file() and repo.is_file():
                if dst.stat().st_ino != repo.stat().st_ino:
                    os.unlink(dst)
                    os.link(repo, dst)
                    print(
                        f"     => Remove duplicate {name} ({vmcore.release})"
                    )
                else:
                    pass  # This is the ideal: module is a hard link from the vmlinux repo.
            elif not dst.is_file() and repo.is_file():
                # vmlinux repo has the file, but not vmcore directory. Link it
                # now.
                os.link(repo, dst)
                print(f"     => Link {name} ({vmcore.release})")
                os.rename(dst, repo)
            else:
                print("    ERROR!")

    def dbinfo_all(self) -> None:
        for subdir in self.core_dir.iterdir():
            core_path = subdir / "vmcore"
            if not core_path.is_file():
                continue
            vmcore = self._open_vmcore(core_path)
            self._fetch_ctfa(vmcore)
            self._fetch_dwarf(vmcore)


def main():
    parser = argparse.ArgumentParser(
        description="manages drgn-tools vmcores",
    )
    parser.add_argument(
        "action",
        choices=["download", "upload", "dbinfo-all"],
        help="choose which operation",
    )
    parser.add_argument(
        "--upload-core",
        type=str,
        help="choose name of the vmcore to upload",
    )
    parser.add_argument(
        "--upload-all",
        action="store_true",
        help="upload all cores in the core dir",
    )
    parser.add_argument(
        "--core-directory",
        type=Path,
        default=None,
        help="override the default vmcore directory",
    )
    parser.add_argument(
        "--par-url",
        type=str,
        default=os.environ.get("OCI_PAR_URL"),
        help="pre authenticated request URL",
    )
    parser.add_argument(
        "--prefix",
        type=str,
        default=VMCORE_PREFIX,
        help=f"prefix for vmcores in object storage (default: {VMCORE_PREFIX})",
    )
    parser.add_argument(
        "--delete-orphan",
        action="store_true",
        help="delete any files which are not listed on block storage",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="output verbose information about what is happening",
    )
    args = parser.parse_args()
    layout = TestDirectories.create(vmcore_dir=args.core_directory)
    if not args.par_url:
        sys.exit("error: either --par-url or $OCI_PAR_URL is required")
    client = ParClient(args.par_url)
    mgr = VmcoreManager(layout.vmcore_dir, client, args.prefix)
    if args.action == "download":
        mgr.download_all(verbose=args.verbose)
        if args.delete_orphan:
            mgr.delete_orphans(verbose=args.verbose)
    elif args.action == "upload":
        if args.upload_all:
            mgr.upload_all(verbose=args.verbose)
        elif args.upload_core:
            mgr.upload_core(args.upload_core, verbose=args.verbose)
        else:
            sys.exit(
                "error: one of --upload-core or --upload-all is required "
                "for upload operation"
            )
    elif args.action == "dbinfo-all":
        mgr.dbinfo_all()


if __name__ == "__main__":
    main()
