# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""VM boot and in-guest command execution for testing.vm."""
import bz2
import contextlib
import gzip
import lzma
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Optional
from typing import Tuple

from testing.vm.config import KernelVer
from testing.vm.config import SHARED_FS_VIRTIOFS
from testing.vm.config import SUPPORTED_SHARED_FS
from testing.vm.config import VmLayout
from testing.vm.logging import VmLogger


INITRD_DIRS = [
    "bin",
    "dev",
    "etc",
    "lib/modules",
    "proc",
    "sys",
    "tmp",
    "usr/bin",
    "usr/sbin",
]

# Keep this list intentionally small and let dependency expansion add the rest.
COMMON_INITRD_MODULES = [
    "overlay",
    "virtio_pci",
    "virtio_blk",
    "ext4",
]

VIRTIOFS_INITRD_MODULES = [
    "virtiofs",
    "fuse",
]

NINEP_INITRD_MODULES = [
    "9p",
    "9pnet_virtio",
]


INIT_SCRIPT = """#!/bin/sh
set -eu

result=FAIL
cleanup() {{
    echo DRGN_VMTEST: $result
    echo b >/proc/sysrq-trigger
}}
trap cleanup EXIT

mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t tmpfs tmpfs /tmp

{module_load}

mkdir -p /host
{mount_host}

mkdir -p /tmp/upper /tmp/work /tmp/root
mount -t overlay overlay \\
      -o lowerdir={rootfs_host_path},upperdir=/tmp/upper,workdir=/tmp/work \\
      /tmp/root

mkdir -p /tmp/root/proc /tmp/root/sys /tmp/root/dev /tmp/root/host
mount -t proc proc /tmp/root/proc
mount -t sysfs sys /tmp/root/sys
mount -t devtmpfs dev /tmp/root/dev
mount --bind /host /tmp/root/host

{pre_chroot_setup}

hostname {hostname}
exec switch_root /tmp/root /usr/bin/setsid -c /bin/sh -lc {guest_command}
"""


def _validate_shared_fs(shared_fs: str) -> None:
    if shared_fs not in SUPPORTED_SHARED_FS:
        raise RuntimeError(
            "Unsupported shared filesystem {!r}; expected one of {}".format(
                shared_fs,
                ", ".join(SUPPORTED_SHARED_FS),
            )
        )


def _initrd_modules(shared_fs: str) -> List[str]:
    _validate_shared_fs(shared_fs)
    modules = list(COMMON_INITRD_MODULES)
    if shared_fs == SHARED_FS_VIRTIOFS:
        modules.extend(VIRTIOFS_INITRD_MODULES)
    else:
        modules.extend(NINEP_INITRD_MODULES)
    return modules


def _host_mount_command(shared_fs: str) -> str:
    _validate_shared_fs(shared_fs)
    if shared_fs == SHARED_FS_VIRTIOFS:
        return "mount -t virtiofs -o ro hostfs /host"
    return (
        "mount -t 9p "
        "-o ro,trans=virtio,cache=loose,msize=1048576 "
        "hostfs /host"
    )


def _guest_path(path: Path, shared_dir: Path) -> str:
    rel = path.absolute().relative_to(shared_dir)
    return "/host/" + str(rel)


def _find_qemu(arch: str) -> str:
    if os.path.exists("/usr/libexec/qemu-kvm"):
        return "/usr/libexec/qemu-kvm"
    name = f"qemu-system-{arch}"
    path = shutil.which(name)
    if path:
        return path
    raise RuntimeError(f"Unable to locate qemu executable: {name}")


def _find_virtiofsd() -> str:
    for path in (
        shutil.which("virtiofsd"),
        "/usr/libexec/virtiofsd",
        "/usr/lib/qemu/virtiofsd",
    ):
        if path and os.path.exists(path):
            return path
    raise RuntimeError("Unable to locate virtiofsd executable")


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"Required tool is missing: {name}")
    return path


def _topological_sort(
    graph: Dict[str, List[str]],
    start: Optional[Iterable[str]] = None,
) -> List[str]:
    order = []
    seen = set()

    def rec(node: str) -> None:
        if node in seen:
            return
        seen.add(node)
        for desc in graph[node]:
            rec(desc)
        order.append(node)

    if not start:
        start = graph.keys()

    for node in start:
        rec(node)
    return order


def _read_modules_dep(path: Path) -> Dict[str, List[str]]:
    modules_dep = {}
    with path.open() as f:
        for line in f:
            key, value = line.split(":", 1)
            modules_dep[key.strip()] = value.split()
    return modules_dep


def _module_name(path: str) -> str:
    return path.split("/")[-1].split(".")[0]


def _decompress_zstd(src_file: Path) -> bytes:
    zstd = shutil.which("zstd")
    if not zstd:
        raise RuntimeError(
            "Kernel module is compressed with zstd but `zstd` was not "
            f"found: {src_file}"
        )
    result = subprocess.run(
        [zstd, "-d", "-q", "-c", str(src_file)],
        check=True,
        stdout=subprocess.PIPE,
    )
    return result.stdout


def _read_module_payload(src_file: Path, rel_path: str) -> Tuple[str, bytes]:
    if rel_path.endswith(".ko.xz"):
        return rel_path[:-3], lzma.decompress(src_file.read_bytes())
    if rel_path.endswith(".ko.gz"):
        return rel_path[:-3], gzip.decompress(src_file.read_bytes())
    if rel_path.endswith(".ko.bz2"):
        return rel_path[:-4], bz2.decompress(src_file.read_bytes())
    if rel_path.endswith(".ko.zst"):
        return rel_path[:-4], _decompress_zstd(src_file)
    return rel_path, src_file.read_bytes()


def _copy_initrd_modules(
    release: str, extract_dir: Path, initrd_dir: Path, shared_fs: str
) -> List[str]:
    initrd_mod_dir = initrd_dir / "lib/modules" / release
    root_mod_dir = extract_dir / "lib/modules" / release

    all_modules = _read_modules_dep(root_mod_dir / "modules.dep")
    name_to_path = {_module_name(mod): mod for mod in all_modules.keys()}
    requested = [
        name_to_path[m]
        for m in _initrd_modules(shared_fs)
        if m in name_to_path
    ]
    needed_paths = _topological_sort(all_modules, requested)

    load_paths = []
    initrd_mod_dir.mkdir(parents=True, exist_ok=True)
    for mod_path in needed_paths:
        src = root_mod_dir / mod_path
        out_rel_path, payload = _read_module_payload(src, mod_path)
        dst = initrd_mod_dir / out_rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(payload)
        load_paths.append(out_rel_path)

    return load_paths


def _find_vmlinuz(release: str, extract_dir: Path) -> Path:
    path_in_modules = extract_dir / "lib/modules" / release / "vmlinuz"
    if path_in_modules.is_file():
        return path_in_modules
    path_in_boot = extract_dir / "boot" / f"vmlinuz-{release}"
    if path_in_boot.is_file():
        return path_in_boot
    raise RuntimeError(f"Unable to locate vmlinuz for release {release}")


def _create_guest_command(
    repo_root: Path,
    kmod_path: Optional[Path],
    shared_dir: Path,
    command: List[str],
) -> str:
    cmd = " ".join(shlex.quote(arg) for arg in command)
    repo_guest = _guest_path(repo_root, shared_dir)

    lines = [
        "set -euo pipefail",
        'cleanup() { [ "$?" -eq 0 ] && echo "DRGN_VMTEST: PASS" || echo "DRGN_VMTEST: FAIL" ; sleep 0.1; echo b >/proc/sysrq-trigger; }',
        "trap cleanup EXIT",
        "export PATH=/sbin:/usr/sbin:/bin:/usr/bin",
        "export DRGNTOOLS_BLOCK_TEST_DIR=/mnt",
        f"cd {shlex.quote(repo_guest)}",
    ]
    if kmod_path is not None:
        kmod_guest = _guest_path(kmod_path, shared_dir)
        lines.append(f"export DRGNTOOLS_TEST_KMOD={shlex.quote(kmod_guest)}")
    lines.append(cmd)
    return " ; ".join(lines)


def _create_pre_chroot_setup(
    release: str,
    extract_dir: Path,
    kmod_path: Optional[Path],
    shared_dir: Path,
) -> str:
    extract_guest = _guest_path(extract_dir, shared_dir)
    mod_src = f"{extract_guest}/lib/modules/{release}"
    dbg_src = f"{extract_guest}/usr/lib/debug/lib/modules/{release}"

    lines = [
        f"mkdir -p /tmp/root/lib/modules/{release}",
        (
            f"mount --bind {shlex.quote(mod_src)} "
            f"/tmp/root/lib/modules/{release}"
        ),
        f"mkdir -p /tmp/root/usr/lib/debug/lib/modules/{release}",
        (
            f"mount --bind {shlex.quote(dbg_src)} "
            f"/tmp/root/usr/lib/debug/lib/modules/{release}"
        ),
        "mke2fs -F /dev/vda >/dev/null",
        "mkdir -p /tmp/root/mnt",
        "mount /dev/vda /tmp/root/mnt",
    ]
    if kmod_path is not None:
        kmod_guest = _guest_path(kmod_path, shared_dir)
        lines.insert(-3, f"insmod {shlex.quote(kmod_guest)}")

    terminal_size = shutil.get_terminal_size((0, 0))
    if terminal_size.columns or terminal_size.lines:
        lines.append(
            f"stty cols {terminal_size.columns} rows {terminal_size.lines}"
        )

    return "\n".join(lines)


def _create_initrd(
    kernel: KernelVer,
    extract_dir: Path,
    rootfs_dir: Path,
    shared_dir: Path,
    pre_chroot_setup: str,
    guest_command: str,
    shared_fs: str,
) -> Path:
    _require_tool("cpio")
    _require_tool("gzip")

    with TemporaryDirectory() as tempdir:
        td = Path(tempdir)
        for path in INITRD_DIRS:
            (td / path).mkdir(parents=True, exist_ok=True)

        initrd_modules = _copy_initrd_modules(
            kernel.release, extract_dir, td, shared_fs
        )

        busybox_path = _require_tool("busybox")
        busybox = td / "bin/busybox"
        shutil.copy(busybox_path, busybox)
        subprocess.run(
            [str(busybox), "--install", str(td / "bin")],
            check=True,
        )

        module_load = "\n".join(
            "insmod {} || true".format(
                shlex.quote(f"/lib/modules/{kernel.release}/{mod_path}")
            )
            for mod_path in initrd_modules
        )

        init = td / "init"
        init.write_text(
            INIT_SCRIPT.format(
                hostname=kernel.category.name,
                module_load=module_load,
                mount_host=_host_mount_command(shared_fs),
                rootfs_host_path=shlex.quote(
                    _guest_path(rootfs_dir, shared_dir)
                ),
                pre_chroot_setup=pre_chroot_setup,
                guest_command=shlex.quote(guest_command),
            )
        )
        init.chmod(0o755)

        out_path = (
            extract_dir / "boot" / f"drgn-tools-initramfs-{kernel.release}.img"
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("wb") as f:
            subprocess.run(
                "find . -print0 "
                "| cpio --null --format=newc --create --quiet "
                "| gzip --best --no-name",
                cwd=td,
                check=True,
                shell=True,
                stdout=f,
            )
        return out_path


def _run_qemu(
    args: List[str],
    log_path: Optional[Path],
    verbose: bool,
    stdin: Optional[int],
) -> int:
    if log_path is None:
        result = subprocess.run(
            args,
            check=False,
            stdin=stdin,
        )
        return result.returncode

    if not verbose:
        with log_path.open("wb") as f:
            result = subprocess.run(
                args,
                check=False,
                stdout=f,
                stderr=f,
                stdin=stdin,
            )
        return result.returncode

    with log_path.open("wb") as log_file:
        proc = subprocess.Popen(
            args,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        assert proc.stdout is not None
        for chunk in iter(lambda: proc.stdout.read(4096), b""):  # type: ignore
            log_file.write(chunk)
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        return proc.wait()


@contextlib.contextmanager
def _create_block_image(size_mb: int = 400) -> Iterator[Path]:
    with TemporaryDirectory() as tempdir:
        img = Path(tempdir) / "disk.img"
        with img.open("wb") as f:
            f.truncate(size_mb * 1024 * 1024)
        yield img


@contextlib.contextmanager
def _start_virtiofsd(socket_path: Path, shared_dir: Path) -> Iterator[None]:
    virtiofsd = _find_virtiofsd()
    proc = subprocess.Popen(
        [
            virtiofsd,
            "--socket-path",
            str(socket_path),
            "--shared-dir",
            str(shared_dir),
            "--sandbox=none",
            "--cache=auto",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,  # text=True for 3.7+
    )
    try:
        # The socket appears almost immediately; keep the check simple.
        for _ in range(100):
            if socket_path.exists():
                break
            if proc.poll() is not None:
                stderr = proc.stderr.read() if proc.stderr else ""
                msg = stderr.strip() or "no stderr"
                raise RuntimeError(f"virtiofsd exited unexpectedly: {msg}")
            time.sleep(0.02)
        else:
            raise RuntimeError("virtiofsd socket was not created")
        yield
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


def _qemu_memory_args(shared_fs: str) -> List[str]:
    _validate_shared_fs(shared_fs)
    if shared_fs == SHARED_FS_VIRTIOFS:
        return [
            # memfd backend is necessary for virtiofsd.
            "-object",
            "memory-backend-memfd,id=mem,size=2048M,share=on",
            "-machine",
            "q35,memory-backend=mem",
            "-m",
            "2048",
        ]
    return [
        "-machine",
        "q35",
        "-m",
        "2048",
    ]


def _qemu_host_share_args(
    shared_fs: str,
    shared_dir: Path,
    socket_path: Optional[Path],
) -> List[str]:
    _validate_shared_fs(shared_fs)
    if shared_fs == SHARED_FS_VIRTIOFS:
        if socket_path is None:
            raise RuntimeError("virtiofs requires a virtiofsd socket path")
        return [
            "-device",
            "vhost-user-fs-pci,chardev=char0,tag=hostfs",
            "-chardev",
            f"socket,id=char0,path={socket_path}",
        ]
    return [
        "-fsdev",
        (
            f"local,id=hostfs,path={shared_dir},security_model=none,"
            "readonly=on,multidevs=remap"
        ),
        "-device",
        "virtio-9p-pci,fsdev=hostfs,mount_tag=hostfs",
    ]


def run_in_vm(
    kernel: KernelVer,
    rootfs_dir: Path,
    layout: VmLayout,
    repo_root: Path,
    command: List[str],
    log_path: Optional[Path],
    log: VmLogger,
    kmod_path: Optional[Path] = None,
    shared_fs: Optional[str] = None,
) -> None:
    if shared_fs is None:
        shared_fs = kernel.category.shared_fs
    _validate_shared_fs(shared_fs)

    extract_dir = layout.extract_path(kernel.release)
    qemu = _find_qemu(kernel.category.arch)

    repo_root = repo_root.absolute()
    base_dir = layout.base_dir.absolute()
    rootfs_dir = rootfs_dir.absolute()
    extract_dir = extract_dir.absolute()
    if kmod_path is not None:
        kmod_path = kmod_path.absolute()
    shared_dir = Path(os.path.commonpath([str(repo_root), str(base_dir)]))

    if not rootfs_dir.is_dir():
        raise RuntimeError(f"Rootfs is missing: {rootfs_dir}")
    paths = [rootfs_dir, extract_dir]
    if kmod_path is not None:
        paths.append(kmod_path)
    for path in paths:
        try:
            path.relative_to(shared_dir)
        except ValueError as e:
            raise RuntimeError(
                "Path must be inside shared repository root "
                f"{shared_dir}: {path}"
            ) from e

    guest_command = _create_guest_command(
        repo_root,
        kmod_path,
        shared_dir,
        command,
    )
    pre_chroot_setup = _create_pre_chroot_setup(
        kernel.release,
        extract_dir,
        kmod_path,
        shared_dir,
    )
    initrd = _create_initrd(
        kernel,
        extract_dir,
        rootfs_dir,
        shared_dir,
        pre_chroot_setup,
        guest_command,
        shared_fs,
    )
    vmlinuz = _find_vmlinuz(kernel.release, extract_dir)

    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)

    with contextlib.ExitStack() as stack:
        block_img = stack.enter_context(_create_block_image())
        tempdir = stack.enter_context(tempfile.TemporaryDirectory())
        stdin = None
        if log_path is not None:
            stdin = subprocess.DEVNULL
        sock: Optional[Path] = None
        if shared_fs == SHARED_FS_VIRTIOFS:
            sock = Path(tempdir) / "virtiofs.sock"
            stack.enter_context(_start_virtiofsd(sock, shared_dir))
        args = [qemu]
        if os.access("/dev/kvm", os.R_OK | os.W_OK):
            args += ["--enable-kvm", "-cpu", "host"]

        if log_path:
            serial_args = ["-serial", "stdio", "-monitor", "none"]
        else:
            serial_args = ["-serial", "stdio", "-monitor", "none"]

        kernel_cmdline = "console=ttyS0,115200 panic=-1"
        if not log.verbose:
            kernel_cmdline = "quiet loglevel=1 " + kernel_cmdline

        args += [
            # fmt: off
            "-display", "none",
            "-nodefaults",
            "-no-reboot",

            "-kernel", str(vmlinuz),
            "-initrd", str(initrd),
            "-append", kernel_cmdline,

            "-smp", "2",
            *_qemu_memory_args(shared_fs),

            *serial_args,
            "-device", "virtio-rng",
            "-device", "vmcoreinfo",
            *_qemu_host_share_args(shared_fs, shared_dir, sock),
            "-drive", f"file={block_img},if=virtio,format=raw",
            # fmt: on
        ]

        result = _run_qemu(
            args,
            log_path,
            log.verbose,
            stdin,
        )
        if result != 0:
            if log_path:
                raise RuntimeError(
                    f"qemu exited with {result}, see log: {log_path}"
                )
            else:
                raise RuntimeError(f"qemu exited with {result}")

    if log_path:
        output = log_path.read_bytes()
        if b"DRGN_VMTEST: PASS" not in output:
            raise RuntimeError(
                f"VM test run did not succeed, see log: {log_path}"
            )
