# Copyright (c) 2024, Oracle and/or its affiliates.
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
from testing.util import BASE_DIR

# May be overridden by the CLI
CORE_DIR = BASE_DIR / "vmcores"
CORE_PFX = "drgn-tools-vmcores/"


def download_all(client: ParClient):
    objects = client.list_objects_simple(prefix=CORE_PFX, fields="size")
    CORE_DIR.mkdir(exist_ok=True)
    for obj in objects:
        name = obj["name"][len(CORE_PFX) :]
        path = CORE_DIR / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file() and path.stat().st_size == obj["size"]:
            print(f"Already exists: {name}")
        else:
            print(f"Download: {name}")
            with path.open("wb") as f:
                shutil.copyfileobj(client.get_object(obj["name"]), f)


def delete_orphans(client: ParClient):
    print("Searching for orphaned files to remove...")
    objs = client.list_objects_simple(prefix=CORE_PFX, fields="size")
    keys = set()
    for obj in objs:
        assert obj["name"].startswith(CORE_PFX)
        name = obj["name"][len(CORE_PFX) :]
        keys.add(name)

    # Iterate using list() because modifying the directory while iterating it
    # can lead to errors
    for fn in list(CORE_DIR.glob("**/*")):
        if not fn.is_file():
            continue
        key = str(fn.relative_to(CORE_DIR))
        if key in keys:
            continue
        print(f"Remove orphaned file: {key}")
        fn.unlink()
        parent = fn.parent
        while not list(parent.iterdir()):
            print(f"Remove empty parent: {parent}")
            parent.rmdir()
            parent = parent.parent


def upload_all(client: ParClient, core: str) -> None:
    core_path = CORE_DIR / core
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
        for obj in client.list_objects_simple(fields="size")
    }

    for path in uploads:
        key = CORE_PFX + str(path.relative_to(CORE_DIR))
        existing_size = object_to_size.get(key)
        size = path.stat().st_size
        if existing_size is not None and existing_size == size:
            print(f"Already uploaded: {key}")
            continue
        with path.open("rb") as f:
            print(f"Upload: {key}")
            client.put_object(key, f)


def main():
    global CORE_DIR, CORE_PFX
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
        "--core-directory",
        type=Path,
        help=f"where to store vmcores (default: {str(CORE_DIR)})",
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
        default=None,
        help=f"prefix for vmcores in object storage (default: {CORE_PFX})",
    )
    parser.add_argument(
        "--delete-orphan",
        action="store_true",
        help="delete any files which are not listed on block storage",
    )
    args = parser.parse_args()
    if args.core_directory:
        CORE_DIR = args.core_directory.absolute()
    if args.prefix:
        CORE_PFX = args.core_directory.absolute()
    if not args.par_url:
        sys.exit("error: either --par-url or $OCI_PAR_URL is required")
    client = ParClient(args.par_url)
    if args.action == "download":
        download_all(client)
        if args.delete_orphan:
            delete_orphans(client)
    elif args.action == "upload":
        if not args.upload_core:
            sys.exit("error: --upload-core is required for upload operation")
        upload_all(client, args.upload_core)


if __name__ == "__main__":
    main()
