# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Manager for test vmcores - downloaded from OCI block storage
"""
import argparse
import fnmatch
import os
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import as_completed
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from tempfile import NamedTemporaryFile
from threading import Event
from typing import Any
from typing import List
from typing import Tuple

import oci.config
from oci.exceptions import ConfigFileNotFound
from oci.object_storage import ObjectStorageClient
from oci.object_storage import UploadManager
from oci.pagination import list_call_get_all_results_generator
from rich.progress import BarColumn
from rich.progress import DownloadColumn
from rich.progress import Progress
from rich.progress import TaskID
from rich.progress import TextColumn
from rich.progress import TimeRemainingColumn
from rich.progress import TransferSpeedColumn

from drgn_tools.debuginfo import CtfCompatibility
from drgn_tools.debuginfo import KernelVersion
from testing.util import combine_junit_xml

CORE_DIR = Path.cwd() / "testdata/vmcores"

CHUNK_SIZE = 16 * 4096
UPLOAD_PART_SIZE = 16 * 1024 * 1024

SIGTERM_EVENT = Event()
signal.signal(signal.SIGTERM, lambda: SIGTERM_EVENT.set())  # type: ignore


def get_oci_bucket_info() -> Tuple[str, str, str]:
    namespace = os.environ.get("VMCORE_NAMESPACE")
    bucket = os.environ.get("VMCORE_BUCKET")
    prefix = os.environ.get("VMCORE_PREFIX")
    if not (namespace and bucket and prefix):
        raise Exception(
            "Please set VMCORE_NAMESPACE, VMCORE_BUCKET, and VMCORE_PREFIX to "
            "point to the OCI object storage location for the vmcore repo."
        )
    return namespace, bucket, prefix


def download_file(
    client: ObjectStorageClient,
    progress: Progress,
    name: str,
    key: str,
    path: Path,
    size: int,
):
    progress.print(f"Downloading {name}")
    task_id = progress.add_task(
        "download",
        filename=name,
        total=size,
        start=True,
    )
    namespace, bucket, _ = get_oci_bucket_info()
    response = client.get_object(namespace, bucket, key)
    relpath = path.relative_to(CORE_DIR)
    with path.open("wb") as f:
        for content_bytes in response.data.iter_content(chunk_size=CHUNK_SIZE):
            f.write(content_bytes)
            progress.update(task_id, advance=len(content_bytes))
            if SIGTERM_EVENT.is_set():
                progress.print(f"[red]Download interrupted[/red]: {relpath}")
                return
    progress.print(f"Download completed: {relpath}")
    progress.remove_task(task_id)


def all_objects(client: ObjectStorageClient) -> List[Any]:
    objects = []
    namespace, bucket, prefix = get_oci_bucket_info()
    gen = list_call_get_all_results_generator(
        client.list_objects,
        "response",
        namespace,
        bucket,
        prefix=prefix,
        fields="size",
    )
    for response in gen:
        objects.extend(response.data.objects)
    return objects


def download_all(client: ObjectStorageClient):
    _, _, prefix = get_oci_bucket_info()
    progress = Progress(
        TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.1f}%",
        "•",
        DownloadColumn(),
        "•",
        TransferSpeedColumn(),
        "•",
        TimeRemainingColumn(),
    )
    objects = all_objects(client)
    CORE_DIR.mkdir(exist_ok=True)
    with progress, ThreadPoolExecutor(max_workers=8) as pool:
        futures = []
        for obj in objects:
            assert obj.name.startswith(prefix)
            name = obj.name[len(prefix) :]
            path = CORE_DIR / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_file() and path.stat().st_size == obj.size:
                progress.print(f"Already exists: {name}")
            else:
                futures.append(
                    pool.submit(
                        download_file,
                        client,
                        progress,
                        name,
                        obj.name,
                        path,
                        obj.size,
                    )
                )
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(e)


def delete_orphans(client: ObjectStorageClient):
    print("Searching for orphaned files to remove...")
    objs = all_objects(client)
    keys = set()
    _, _, prefix = get_oci_bucket_info()
    for obj in objs:
        assert obj.name.startswith(prefix)
        name = obj.name[len(prefix) :]
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


def upload_file(
    client: ObjectStorageClient,
    progress: Progress,
    task_id: TaskID,
    key: str,
    path: Path,
) -> None:
    def cb(nbytes: int) -> None:
        progress.update(task_id, advance=nbytes)

    namespace, bucket, _ = get_oci_bucket_info()
    progress.start_task(task_id)
    manager = UploadManager(client)
    manager.upload_file(
        namespace,
        bucket,
        key,
        str(path),
        progress_callback=cb,
    )


def upload_all(client: ObjectStorageClient, core: str) -> None:
    _, _, prefix = get_oci_bucket_info()
    progress = Progress(
        TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.1f}%",
        "•",
        DownloadColumn(),
        "•",
        TransferSpeedColumn(),
        "•",
        TimeRemainingColumn(),
    )
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
    object_to_size = {obj.name: obj.size for obj in all_objects(client)}
    with progress, ThreadPoolExecutor(max_workers=4) as pool:
        futures = []
        for path in uploads:
            key = prefix + str(path.relative_to(CORE_DIR))
            existing_size = object_to_size.get(key)
            size = path.stat().st_size
            if existing_size is not None and existing_size == size:
                progress.print(f"Already uploaded: {key}")
                continue
            task_id = progress.add_task(
                "upload",
                filename=key,
                total=path.stat().st_size,
                start=False,
            )
            fut = pool.submit(
                upload_file,
                client,
                progress,
                task_id,
                key,
                path,
            )
            futures.append(fut)
        for future in as_completed(futures):
            future.result()


def _test_job(
    core_name: str, cmd: List[str], xml: str
) -> Tuple[str, bool, ET.ElementTree]:
    # Runs the test silently, but prints the stdout/stderr on failure.
    with NamedTemporaryFile("w+t") as f:
        print(f"Begin testing {core_name}")
        start = time.time()
        res = subprocess.run(cmd, stdout=f, stderr=f)
        if res.returncode != 0:
            print(f"=== FAILURE: {core_name} ===")
            f.seek(0)
            sys.stdout.write(f.read())
        runtime = time.time() - start
        print(f"Completed testing {core_name} in {runtime:.1f}")
        run_data = ET.parse(xml)
    return (core_name, res.returncode == 0, run_data)


def _skip_ctf(ctf: bool, uname: str) -> bool:
    if ctf:
        host_ol = 9  # OL8 or 9 work here, tests aren't supported for OL7
        kver = KernelVersion.parse(uname)
        compat = CtfCompatibility.get(kver, host_ol)
        # Skip test when CTF is fully unsupported, or when it would require a
        # /proc/kallsyms.
        return compat in (
            CtfCompatibility.NO,
            CtfCompatibility.LIMITED_PROC,
        )
    return False  # don't skip when non-CTF


def test(
    vmcore_list: List[str],
    ctf: bool = False,
    parallel: int = 1,
) -> None:
    def should_run_vmcore(name: str) -> bool:
        if not vmcore_list:
            return True
        for pat in vmcore_list:
            if fnmatch.fnmatch(name, pat):
                return True
        return False

    failed = []
    passed = []
    skipped = []
    xml = None

    with ExitStack() as es:
        pool = es.enter_context(ThreadPoolExecutor(max_workers=parallel))
        futures = []
        for path in CORE_DIR.iterdir():
            core_name = path.name
            if not should_run_vmcore(core_name):
                continue
            uname = (path / "UTS_RELEASE").read_text().strip()
            if _skip_ctf(ctf, uname):
                skipped.append(core_name)
                continue
            xml_run = es.enter_context(
                NamedTemporaryFile("w", suffix=".xml", delete=False)
            )
            xml_run.close()  # not deleted until context is ended
            cmd = [
                sys.executable,
                "-m",
                "pytest",
                f"--vmcore={core_name}",
                f"--vmcore-dir={str(CORE_DIR)}",
                f"--junitxml={xml_run.name}",
                "-o",
                "junit_logging=all",
            ]
            if ctf:
                if not (path / "vmlinux.ctfa").is_file():
                    skipped.append(core_name)
                    continue
                cmd.append("--ctf")
            futures.append(
                pool.submit(_test_job, core_name, cmd, xml_run.name)
            )

        for future in futures:
            core_name, test_passed, run_data = future.result()
            xml = combine_junit_xml(xml, run_data)
            if test_passed:
                passed.append(core_name)
            else:
                failed.append(core_name)

    if xml is not None:
        xml.write("vmcore.xml")
    print("Complete test logs: vmcore.xml")
    print("Vmcore Test Summary -- Passed:")
    print("\n".join(f"- {n}" for n in passed))
    if skipped:
        print("Vmcore Test Summary -- Skipped (missing CTF):")
        print("\n".join(f"- {n}" for n in skipped))
    if failed:
        print("Vmcore Test Summary -- FAILED:")
        print("\n".join(f"- {n}" for n in failed))
        sys.exit(1)


def get_client() -> ObjectStorageClient:
    try:
        config = oci.config.from_file()
        return ObjectStorageClient(config)
    except ConfigFileNotFound:
        sys.exit(
            "error: You need to configure OCI!\n"
            'Try running "oci setup bootstrap"'
        )


def main():
    global CORE_DIR
    parser = argparse.ArgumentParser(
        description="manages drgn-tools vmcores",
    )
    parser.add_argument(
        "action",
        choices=["download", "upload", "test"],
        help="choose which operation",
    )
    parser.add_argument(
        "--upload-core",
        type=str,
        help="choose name of the vmcore to upload",
    )
    parser.add_argument(
        "--core-directory", type=Path, help="where to store vmcores"
    )
    parser.add_argument(
        "--delete-orphan",
        action="store_true",
        help="delete any files which are not listed on block storage",
    )
    parser.add_argument(
        "--vmcore",
        action="append",
        default=[],
        help="only run tests on the given vmcore(s). you can use this "
        "multiple times to specify multiple vmcore names. You can also "
        "use fnmmatch patterns to specify several cores at once.",
    )
    parser.add_argument(
        "--ctf",
        action="store_true",
        help="Use CTF debuginfo for tests rather than DWARF (skips vmcores "
        "without a vmlinux.ctfa file)",
    )
    parser.add_argument(
        "--parallel",
        "-j",
        type=int,
        default=1,
        help="Run the tests in parallel with the given number of threads",
    )
    args = parser.parse_args()
    if args.core_directory:
        CORE_DIR = args.core_directory.absolute()
    if args.action == "download":
        client = get_client()
        download_all(client)
        if args.delete_orphan:
            delete_orphans(client)
    elif args.action == "upload":
        if not args.upload_core:
            sys.exit("error: --upload-core is required for upload operation")
        upload_all(get_client(), args.upload_core)
    elif args.action == "test":
        test(
            args.vmcore,
            ctf=args.ctf,
            parallel=args.parallel,
        )


if __name__ == "__main__":
    main()
