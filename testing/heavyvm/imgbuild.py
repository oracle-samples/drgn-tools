# Copyright (c) 2023-2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Build QEMU virtual machine images with OL & UEK debuginfo.

This tool builds virtual machine images that are used for the "heavyvm" tests.
These VM images are the full Oracle Linux userspace, with the official drgn RPMs
& kernel-uek-debuginfo installed. This means they are the most accurate
representation of a customer system, though they are heavyweight. The images
need to be kept up-to-date, and the most reliable way to do this is to rebuild
them periodically. Thus, it's important to have a fully automatic build process,
which is implemented here.

VM images are built on top of the KVM cloud image templates found on
yum.oracle.com. We use cloud-init to configure users, and connect via SSH to
configure the VMs.
"""
import argparse
import contextlib
import dataclasses
import http.server
import logging
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait
from pathlib import Path
from typing import Dict
from typing import List
from typing import Optional
from typing import TextIO

from paramiko.client import MissingHostKeyPolicy
from paramiko.client import SSHClient
from paramiko.ssh_exception import NoValidConnectionsError
from paramiko.ssh_exception import SSHException

from drgn_tools.debuginfo import _UEK_VER
from drgn_tools.util import download_file
from testing.heavyvm.images import CONFIGURATIONS
from testing.heavyvm.images import ImageInfo
from testing.heavyvm.images import NAME_TO_CONFIGURATION
from testing.heavyvm.qemu import QemuRunner
from testing.util import BASE_DIR


KS_DIR = Path(__file__).parent / "ks"
DOWNLOAD_LOCK = threading.Lock()
DOWNLOADS: Dict[Path, threading.Event] = {}


class FileServer:
    def __init__(self, host: str, port: int = 8325) -> None:
        self.port = port
        self.host = host
        self.server = socketserver.TCPServer(
            ("", port), http.server.SimpleHTTPRequestHandler
        )
        self.thread = threading.Thread(target=self.run)

    def url_for(self, path: Path) -> str:
        rel = str(path.relative_to(Path.cwd()))
        return f"http://{self.host}:{self.port}/{rel}"

    def run(self) -> None:
        with self.server:
            self.server.serve_forever()

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.thread.join()


@dataclasses.dataclass
class Context:
    image_info: ImageInfo
    base_image_dir: Path
    image_dir: Path
    file_server: FileServer
    tmp_dir: Path
    overwrite: bool
    log: logging.Logger

    def cmdlog(self) -> TextIO:
        return open(self.tmp_dir / "output.log", "a")


def download_base_image(ctx: Context) -> None:
    # This is complicated by the fact that several threads could be racing to
    # download the same image. While we could atomically open the file with
    # O_CREAT|O_EXCL (or catch the EEXIST), the threads which lose the race
    # would not know when the download is completed. So, we need to have some
    # signalling. For each download, we have an event, and we protect the
    # mapping of file to event with a lock. Threads that win the race create the
    # event, do the download, and trigger the event. Threads that lose the race
    # wait on the event.
    output_file = ctx.base_image_dir / ctx.image_info.base_image_name
    output_file = output_file.absolute()
    partial = ctx.base_image_dir / f"{ctx.image_info.base_image_name}.part"

    if output_file.exists():
        ctx.log.info("Base image %s already downloaded", str(output_file))
        return

    event: Optional[threading.Event] = None
    wait_event: Optional[threading.Event] = None
    with DOWNLOAD_LOCK:
        wait_event = DOWNLOADS.get(output_file)
        if not wait_event:
            event = threading.Event()
            DOWNLOADS[output_file] = event

    if wait_event:
        # Somebody beat us to it, we now wait and then return
        ctx.log.info("Waiting for download of image ...")
        wait_event.wait()
        ctx.log.info("Finished waiting for image download!")
    else:
        # We are responsible for downloading and then signaling
        assert event is not None
        ctx.log.info("Downloading image...")
        ctx.base_image_dir.mkdir(exist_ok=True)
        with partial.open("wb") as f:
            download_file(ctx.image_info.image_url, f)
        ctx.log.info("Finished downloading!")
        os.rename(partial, output_file)
        with DOWNLOAD_LOCK:
            del DOWNLOADS[output_file]
        event.set()


def make_image(ctx: Context) -> None:
    # Create a qcow2 image based on the base image as a backing store.
    base_image_path = ctx.base_image_dir / ctx.image_info.base_image_name
    image_path = ctx.image_dir / ctx.image_info.disk_name
    image_path.parent.mkdir(parents=True, exist_ok=True)
    if image_path.exists():
        if ctx.overwrite:
            ctx.log.info(
                "Already had an image, deleting and creating a new one"
            )
            image_path.unlink()
        else:
            raise Exception(
                "VM image already existed, use --overwrite to replace"
            )
    subprocess.run(
        [
            "qemu-img",
            "create",
            "-b",
            str(base_image_path),
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            str(image_path),
            "100G",
        ],
        check=True,
        stdout=ctx.cmdlog(),
        stderr=subprocess.STDOUT,
    )


def build_cloud_init_disk(ctx: Context) -> Path:
    # Create an ISO which cloud-init will recognize and use as configuration for
    # the VM. We're using some things that are "deprecated" in cloud-init, but
    # are necessary to maintain compatibility from OL7 through OL10.
    ci_img = ctx.tmp_dir / "cloudinit.iso"
    ci_builddir = ctx.tmp_dir / "cloudinit"
    if ci_builddir.exists():
        shutil.rmtree(ci_builddir)
    ci_builddir.mkdir(parents=True)
    (ci_builddir / "network-config").touch()
    (ci_builddir / "meta-data").touch()
    with (ci_builddir / "user-data").open("w") as f:
        # It's probably a good thing that it's difficult to configure an admin
        # with SSH password authentication. However, this is a totally valid use
        # case.
        #
        # I haven't had much luck getting cloud-init to set the root password
        # and allow root password login via SSH. Fortunately we can just create
        # a user empowered to sudo without password, and allow password login
        # via SSH to that account.
        f.write(
            "\n".join(
                [
                    "#cloud-config",
                    "users:",
                    "    - name: ci",
                    "      groups: [users, wheel]",
                    '      sudo: "ALL=(ALL) NOPASSWD:ALL"',
                    "      lock_passwd: false",
                    "chpasswd:",
                    "  expire: false",
                    "  list: |",
                    "    root:password",
                    "    ci:password",
                    "ssh_pwauth: true",
                    "disable_root: false",
                    "resize_rootfs: true",
                    "\n",
                ]
            )
        )
    args = [
        "genisoimage",
        "-output",
        str(ci_img.absolute()),
        "-volid",
        "cidata",
        "-rational-rock",
        "-joliet",
        "user-data",
        "meta-data",
        "network-config",
    ]
    ctx.log.info("Building cloud-init ISO: %r", args)
    proc = subprocess.run(args, cwd=ci_builddir, capture_output=True)  # novm
    ctx.log.debug(
        "Image build result: code %d\nstderr: %r\nstdout:%r",
        proc.returncode,
        proc.stderr,
        proc.stdout,
    )
    proc.check_returncode()
    return ci_img


class AutoAcceptPolicy(MissingHostKeyPolicy):
    """
    Accept SSH host keys without verification.

    We're only connecting to local VMs, and if another process on our machine is
    maliciously impersonating our test VM, we have bigger problems :)
    """

    def missing_host_key(self, client, hostname, key):
        return key


def wait_ssh(
    ctx: Context,
    hostname: str,
    port: int,
    username: str,
    password: str,
    timeout: int = 120,
) -> SSHClient:
    # Wait until a VM is accessible via SSH, and then return a connection.
    end = time.time() + timeout
    while time.time() < end:
        try:
            ctx.log.debug(f"Try ssh {hostname}:{port}")
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAcceptPolicy)
            client.connect(
                hostname,
                port,
                username=username,
                password=password,
                timeout=5,
                banner_timeout=5,
                auth_timeout=5,
                allow_agent=False,
                look_for_keys=False,
            )
            return client
        except (NoValidConnectionsError, TimeoutError):
            client.close()
            pass
        except SSHException as e:
            if "No existing session" in str(
                e
            ) or "Error reading SSH protocol banner" in str(e):
                client.close()
                pass
            else:
                raise
        time.sleep(1)
    raise TimeoutError("could not connect to SSH")


def run_cmd(
    client: SSHClient, ctx: Context, cmd: str, check: bool = True
) -> str:
    # Run a command on the VM and return its output.
    ctx.log.info(f"Running remote command: {cmd}")
    transport = client.get_transport()
    assert transport is not None
    channel = transport.open_session()
    channel.set_combine_stderr(True)
    channel.exec_command(cmd)
    data = bytearray()
    while True:
        new = channel.recv(4096)
        if len(new) == 0:
            break
        data.extend(new)
    status = channel.recv_exit_status()
    result = data.decode("utf-8", errors="replace")
    ctx.log.debug(f"Remote command: {cmd} => {status}:\n===\n{result}\n===")
    if check and status != 0:
        raise Exception(
            f"SSH Command '{cmd}' failed (code {status}):\n{result}"
        )
    return result


def configure_vm(ctx: Context) -> None:
    # Install drgn and the appropriate kernel with debuginfo. Apply any other
    # configuration tweaks necessary for the heavyvm runner to work nicely.
    cloud_init_iso = build_cloud_init_disk(ctx)
    ctx.log.info("Booting image and waiting for login...")
    seriallog = str(ctx.tmp_dir / "install.log")
    qemu = (
        QemuRunner(2, 4096)
        .hd(str(ctx.image_dir / ctx.image_info.disk_name))
        .net_user(ssh=True)
        .set_serial("socket")
        .cdrom(str(cloud_init_iso))
    )
    assert qemu.ssh_port is not None  # to satisfy mypy
    qemu.serial.log(seriallog)
    ctx.log.debug(f"Qemu command: {qemu.get_cmd()}")
    stack = contextlib.ExitStack()
    with stack:
        ctx.log.info(f"View serial output: {seriallog}")
        stack.enter_context(qemu.run_errkill())

        # Connect via SSH
        client = stack.enter_context(
            wait_ssh(ctx, "localhost", qemu.ssh_port, "ci", "password")
        )
        ol = ctx.image_info.ol
        if ol == 7:
            dnf = "yum"
            cfgman = "yum-config-manager"
        else:
            dnf = "dnf"
            cfgman = "dnf config-manager"
        run_cmd(client, ctx, f"sudo {cfgman} --enable ol{ol}_addons")

        install_packages = [
            "python3-pip",
            "fio",
        ]
        if ol >= 9:
            # Starting in OL9, it looks like fio engines are packaged separately
            install_packages.append("fio-engine-libaio")
        if not ctx.image_info.rpms:
            install_packages.append("drgn")
        for filename in ctx.image_info.rpms:
            install_packages.append(
                ctx.file_server.url_for(Path(filename).absolute())
            )

        # Specify the UEK version by enabling the corresponding yum repo
        if not ctx.image_info.is_default_uek():
            run_cmd(
                client,
                ctx,
                f"sudo {cfgman} --disable ol{ol}_UEKR{ctx.image_info.default_uek()}",
            )
            run_cmd(
                client,
                ctx,
                f"sudo {cfgman} --enable ol{ol}_UEKR{ctx.image_info.uek}",
            )

        # Run a full upgrade, and install drgn & test dependencies.
        run_cmd(client, ctx, f"sudo {dnf} upgrade -y")
        run_cmd(
            client, ctx, f"sudo {dnf} install -y " + " ".join(install_packages)
        )
        run_cmd(client, ctx, "sudo python3 -m pip install 'pytest<7.1'")

        # Install kernel-uek from the repo established above:
        run_cmd(client, ctx, f"sudo {dnf} install -y kernel-uek")

        # Determine the kernel release
        ver_to_tup = {v: k for k, v in _UEK_VER.items()}
        uektup = ver_to_tup[ctx.image_info.uek]
        uname = run_cmd(
            client,
            ctx,
            f"ls /boot/vmlinuz-{uektup}*uek* | sed 's/^.*vmlinuz-//' | sort -V | tail -n 1",
        ).strip()

        # Set this as the default boot kernel, and ensure console output goes to
        # the serial port.
        run_cmd(
            client,
            ctx,
            f"sudo grubby --update-kernel /boot/vmlinuz-{uname} "
            "--args=console=ttyS0",
        )
        run_cmd(
            client, ctx, f"sudo grubby --set-default /boot/vmlinuz-{uname}"
        )

        # We may encounter an issue here. At least on the OL8 cloud images,
        # /boot/grub2/grubenv is a symlink, which GRUB seems unable to follow
        # because its target is on a different filesystem. The grubenv file is
        # where the saved kernel preference is stored. Replace this symlink
        # with a copy of the target.
        run_cmd(
            client,
            ctx,
            "sudo sh -c 'test -L  /boot/grub2/grubenv && "
            "cp --remove-destination $(readlink -f /boot/grub2/grubenv) "
            "/boot/grub2/grubenv'",
            check=False,
        )

        # Remove any restriction on root SSH login. Cloud-init cannot handle
        # this reliably for the first boot, but we do want to be able to
        # directly login as root for the test runs, so handle it now.
        run_cmd(
            client,
            ctx,
            "sudo rm -f /etc/ssh/sshd_config.d/01-permitrootlogin.conf",
        )
        run_cmd(
            client,
            ctx,
            "sudo sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config",
        )
        run_cmd(
            client,
            ctx,
            "sudo sh -c 'echo PermitRootLogin yes >>/etc/ssh/sshd_config'",
        )

        # Install debuginfo
        ctx.log.info(f"Installing debuginfo for {uname}")
        url_base = (
            f"https://oss.oracle.com/ol{ol}/debuginfo/kernel-uek-debuginfo"
        )
        run_cmd(
            client,
            ctx,
            f"sudo {dnf} install -y {url_base}-{uname}.rpm {url_base}-common-{uname}.rpm",
        )
        # This returns non-zero, probably because the SSH session is immediately
        # torn down. So don't check its output.
        ctx.log.info("Completed debuginfo installation, now shutting down")
        run_cmd(client, ctx, "sudo shutdown now", check=False)
        qemu.wait()
        ctx.log.info("All done!")


def do_imgbuild(ctx: Context) -> None:
    # Run the full image creation process for a single image.
    download_base_image(ctx)
    make_image(ctx)
    configure_vm(ctx)


def validate_rpms(images: List[ImageInfo]) -> None:
    # Before we do a build, ensure that all local RPMs we will install are
    # available.
    missing = defaultdict(list)
    for image in images:
        for rpm in image.rpms:
            if not os.path.exists(rpm):
                missing[rpm].append(image)

    if missing:
        print("error: missing RPM files required for build:")
        for fn, imgs in missing.items():
            names = ", ".join(i.name for i in imgs)
            print(f"  {fn}: required for {names}")
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automated OL ISO installer to qcow2 image"
    )
    parser.add_argument(
        "--base-image-dir",
        type=Path,
        default=BASE_DIR / "iso",
        help="Directory to store base images in",
    )
    parser.add_argument(
        "--image-dir",
        type=Path,
        default=BASE_DIR / "images",
        help="Directory to store QEMU images in",
    )
    parser.add_argument(
        "-n",
        "--num-workers",
        default=10,
        type=int,
        help="Number of parallel workers to use",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Don't wait for viewing tmpdir contents on error",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing images",
    )
    parser.add_argument(
        "images",
        nargs="*",
        help="Images to create",
    )

    args = parser.parse_args()
    if args.images:
        info = [NAME_TO_CONFIGURATION[name] for name in args.images]
    else:
        info = CONFIGURATIONS.copy()

    validate_rpms(info)

    srv = FileServer("10.0.2.2")
    srv.start()
    errh = logging.StreamHandler()
    errh.setLevel(logging.INFO)
    errh.addFilter(lambda r: not r.name.startswith("paramiko"))
    logging.basicConfig(level=logging.DEBUG, handlers=[errh])
    ret = 0
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        tpe = ThreadPoolExecutor(max_workers=args.num_workers)
        futures = []
        for image_info in info:
            tmp_sub_dir = tmp_dir / image_info.name
            tmp_sub_dir.mkdir()
            log = logging.getLogger(image_info.name)
            hdlr = logging.FileHandler(tmp_sub_dir / "debug.log")
            hdlr.setLevel(logging.DEBUG)
            log.addHandler(hdlr)
            log.info("Launching with tmpdir: %s", tmp_sub_dir)
            ctx = Context(
                image_info,
                args.base_image_dir,
                args.image_dir,
                srv,
                tmp_sub_dir,
                args.overwrite,
                log,
            )
            futures.append(tpe.submit(do_imgbuild, ctx))
        wait(futures, return_when="ALL_COMPLETED")
        for f in futures:
            try:
                f.result()
            except Exception:
                traceback.print_exc()
                ret += 1
        if ret == 1:
            print(f"Completed with with {ret} errors")
            if not args.no_wait:
                print(f"Tmpdir: {td}")
                input("Hit enter when done examining tmpdir")
            else:
                # Tar up the temporary directory for debugging and then fail.
                logbundle = Path.cwd() / "imgbuild-logs.tar.gz"
                subprocess.run(
                    ["tar", "-czvf", str(logbundle.absolute()), "."],
                    cwd=str(tmp_dir),
                    check=False,
                )
    srv.stop()
    sys.exit(ret)


if __name__ == "__main__":
    main()
