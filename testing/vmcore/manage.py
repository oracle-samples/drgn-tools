# Copyright (c) 2024, 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Download, upload, and synchronize a collection of vmcores
"""
import argparse
import os
import shutil
import sys
from pathlib import Path

from testing.parlib import ParClient
from testing.vm.config import TestDirectories
from testing.vm.config import VMCORE_PREFIX


class VmcoreManager:
    core_dir: Path
    client: ParClient
    prefix: str

    def __init__(self, core_dir: Path, client: ParClient, prefix: str) -> None:
        self.core_dir = core_dir
        self.client = client
        self.prefix = prefix

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


def main():
    parser = argparse.ArgumentParser(
        description="manages drgn-tools vmcores",
    )
    parser.add_argument(
        "action",
        choices=["download", "upload"],
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


if __name__ == "__main__":
    main()
