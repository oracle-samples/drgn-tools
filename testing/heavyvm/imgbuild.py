# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Build QEMU virtual machine images with OL & UEK debuginfo.

Requires packages qemu-kvm, qemu-img, genisoimage, python38 on OL8. (Note that
this imgbuild script uses python 3.8, but drgn-tools in general does not.)

Getting a basic virtual machine image for testing from an ISO file is not
exactly an automatic process. Most people resign themselves to launching the
installer in their VM program, clicking through the GUI, and then using the
resulting VM image.

However, Oracle Linux uses the "anaconda" installer which allows for
"kickstart" files to script the installation of a system. This is pretty darn
cool, but the downside is that even if you prepare a kickstart file, you need
to manually change the boot command line in GRUB. Unfortunately, qemu can't
change the boot command line, and you can only access the GRUB menus via VNC.

This script circumvents the problem by extracting the vmlinux and initrd for
the installer right out of the ISO file, so that we can give them to QEMU
directly, and provide a command line. We grep the kernel command line out of
the ISO configurations, modify it to suit our automatic installer script, and
launch a QEMU with all the right parameters to create a newly installed image.
"""
import argparse
import dataclasses
import http.server
import logging
import os
import re
import socketserver
import subprocess
import sys
import tempfile
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait
from pathlib import Path
from typing import Dict
from typing import List
from typing import Optional
from typing import TextIO

from drgn_tools.util import download_file
from testing.heavyvm.images import CONFIGURATIONS
from testing.heavyvm.images import ImageInfo
from testing.heavyvm.images import NAME_TO_CONFIGURATION
from testing.heavyvm.qemu import QemuRunner
from testing.util import BASE_DIR


KS_DIR = Path(__file__).parent / "ks"
DOWNLOAD_LOCK = threading.Lock()
DOWNLOADS: Dict[Path, threading.Event] = {}


@dataclasses.dataclass
class Context:
    image_info: ImageInfo
    iso_dir: Path
    image_dir: Path
    ks_dir: Path
    ks_url: str
    ks_srv: "KickstartServer"
    tmp_dir: Path
    overwrite: bool
    interactive: bool
    log: logging.Logger

    def cmdlog(self) -> TextIO:
        return open(self.tmp_dir / "output.log", "a")


def download_image(ctx: Context) -> None:
    # This is complicated by the fact that several threads could be racing to
    # download the same ISO. While we could atomically open the file with
    # O_CREAT|O_EXCL (or catch the EEXIST), the threads which lose the race
    # would not know when the download is completed. So, we need to have some
    # signalling. For each download, we have an event, and we protect the
    # mapping of file to event with a lock. Threads that win the race create the
    # event, do the download, and trigger the event. Threads that lose the race
    # wait on the event.
    output_file = ctx.iso_dir / ctx.image_info.iso_name
    output_file = output_file.absolute()
    partial = ctx.iso_dir / f"{ctx.image_info.iso_name}.part"

    if output_file.exists():
        ctx.log.info("ISO already downloaded")
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
        ctx.log.info("Waiting for download of ISO ...")
        wait_event.wait()
        ctx.log.info("Finished waiting for ISO download!")
    else:
        # We are responsible for downloading and then signaling
        assert event is not None
        ctx.log.info("Downloading ISO...")
        ctx.iso_dir.mkdir(exist_ok=True)
        with partial.open("wb") as f:
            download_file(ctx.image_info.iso_url, f)
        ctx.log.info("Finished downloading!")
        os.rename(partial, output_file)
        with DOWNLOAD_LOCK:
            del DOWNLOADS[output_file]
        event.set()


def extract_boot_info(ctx: Context) -> List[str]:
    """
    Extract vmlinux and initrd.img to tmp_dir, and return the kernel cmdline.
    """
    iso_path_str = str(ctx.iso_dir / ctx.image_info.iso_name)

    with tempfile.TemporaryDirectory() as td:
        subprocess.run(
            [
                "7z",
                "x",
                iso_path_str,
                "isolinux/vmlinuz",
                "isolinux/initrd.img",
                "isolinux/isolinux.cfg",
            ],
            cwd=td,
            stdout=ctx.cmdlog(),
            check=True,
        )
        tdpath = Path(td)
        os.rename(tdpath / "isolinux/vmlinuz", ctx.tmp_dir / "vmlinuz")
        os.rename(tdpath / "isolinux/initrd.img", ctx.tmp_dir / "initrd.img")
        isolinux_cfg = tdpath / "isolinux/isolinux.cfg"
        with isolinux_cfg.open() as f:
            cfg = f.read()

    ctx.log.info("Extracted vmlinuz, initrd.img, and isolinux.cfg from ISO")

    for line in cfg.split("\n"):
        if "initrd=initrd.img" in line:
            args = line.strip().split()
            args.remove("append")
            args.remove("initrd=initrd.img")
            ctx.log.info("ISO cmdline: %s", " ".join(args))
            return args
    raise Exception("Could not find kernel cmdline in ISO")


def make_empty_image(ctx: Context) -> None:
    image_path = ctx.image_dir / ctx.image_info.image_name
    image_path.parent.mkdir(parents=True, exist_ok=True)
    if image_path.exists():
        if ctx.overwrite:
            ctx.log.info(
                "Already had an image, deleting and creating a new one"
            )
            image_path.unlink()
        else:
            raise Exception(
                "Image already existed, use --overwrite to replace"
            )
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(image_path), "100G"],
        check=True,
        stdout=ctx.cmdlog(),
        stderr=subprocess.STDOUT,
    )


class KickstartServer:
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


def get_qemu(ctx: Context) -> QemuRunner:
    qemu = (
        QemuRunner(2, 4096)
        .hd(str(ctx.image_dir / ctx.image_info.image_name))
        .net_user()
    )
    return qemu


def run_installer(ctx: Context, cmdline: List[str]) -> None:
    """
    Assuming we have the following:
    - iso downloaded to iso_dir
    - kickstart.img in tmp_dir
    - vmlinuz and initrd.img in tmp_dir

    Run the installer.
    """
    cmdline += [
        f"inst.ks={ctx.ks_url}",
        "console=ttyS0",
    ]
    qemu = get_qemu(ctx)
    qemu.cdrom(str(ctx.iso_dir / ctx.image_info.iso_name))
    if ctx.interactive:
        qemu.mon_serial()
        qemu.vnc()
    else:
        logfile = str(ctx.tmp_dir / "install.log")
        qemu.serial.log(logfile)
        ctx.log.info(f"View installer progress at {logfile}")
    qemu.kernel(
        str(ctx.tmp_dir / "vmlinuz"),
        initrd=str(ctx.tmp_dir / "initrd.img"),
        cmdline=" ".join(cmdline),
    )
    ctx.log.info("command: %r", qemu.get_cmd())
    qemu.run()
    qemu.wait()
    ctx.log.info("Finished installing")


def run_post_install(ctx: Context) -> None:
    """
    Install drgn and kernel-uek-debuginfo, then shut down.
    """
    ctx.log.info("Rebooting and waiting for login")
    qemu = get_qemu(ctx).set_serial("socket")
    ctx.log.info("qemu command: %r", qemu.get_cmd())
    qemu.run()
    ser = qemu.serial.get_repl()
    ser.set_logger(str(ctx.tmp_dir / "post_install.log"))
    ser.read_until(b"\nlocalhost login: ")
    ctx.log.info("Login prompt is available")
    # log in
    ser.cmd(b"root")
    ser.prompt = ser.ROOT_PROMPT
    ser.cmd(b"password")
    ctx.log.info("Logged in as root, installing drgn")
    # install dependent packages
    if ctx.image_info.ol > 7:
        ser.cmd(
            f"dnf config-manager --enable ol{ctx.image_info.ol}_appstream".encode()
        )
        ser.cmd(
            f"dnf config-manager --enable ol{ctx.image_info.ol}_addons".encode()
        )

    install_packages = [
        "python3-pip",
        "fio",
    ]
    if ctx.image_info.ol >= 9:
        # Starting in OL9, it looks like fio engines are packaged separately
        install_packages.append("fio-engine-libaio")

    # Install drgn from RPMs hosted on kickstart server
    for filename in ctx.image_info.rpms:
        install_packages.append(ctx.ks_srv.url_for(Path(filename).absolute()))

    ser.cmd(
        b"yum install -y " + b" ".join(s.encode() for s in install_packages)
    )

    # Install the pytest dependency
    ser.cmd(b"python3 -m pip install 'pytest<7.1'")

    # OL9 disables root login fia SSH. That's probably good for most cases but
    # not here!
    if ctx.image_info.ol == 9:
        ser.cmd(b"echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config")

    # get uname and download debuginfo
    uname_output = ser.cmd(b"uname -r")
    res = re.search(rb"\d+\.\d+\.\d+-.*el\d+uek\.\w+", uname_output)
    assert res, uname_output
    uname = res.group()
    ctx.log.info(
        f"Installed drgn, now installing debuginfo for {uname.decode('utf-8')}"
    )
    url_base = (
        b"https://oss.oracle.com/ol%d/debuginfo/kernel-uek-debuginfo"
        % (ctx.image_info.ol)
    )
    ser.cmd(
        b"yum install -y %s-%s.rpm %s-common-%s.rpm"
        % (url_base, uname, url_base, uname)
    )
    ctx.log.info("Completed debuginfo installation, now shutting down")
    ser.send_cmd(b"shutdown now")
    ser.read_until(b"Power down")
    ser.close()
    qemu.wait()
    ctx.log.info("All done!")


def do_imgbuild(ctx: Context) -> None:
    download_image(ctx)
    cmdline = extract_boot_info(ctx)
    make_empty_image(ctx)
    run_installer(ctx, cmdline)
    run_post_install(ctx)


def validate_rpms(images: List[ImageInfo]) -> None:
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
        "--iso-dir",
        type=Path,
        default=BASE_DIR / "iso",
        help="Directory to store ISOs in",
    )
    parser.add_argument(
        "--image-dir",
        type=Path,
        default=BASE_DIR / "images",
        help="Directory to store QEMU images in",
    )
    parser.add_argument(
        "--ks-dir",
        type=Path,
        default=KS_DIR,
        help="Directory to find kickstart scripts in",
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
        "--interactive",
        action="store_true",
        help="Show serial on stdout to allow interaction (forces -n 1)",
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

    if args.interactive:
        print(
            "Interactive mode, you'll be able to interact with the installer"
        )
        print("over serial port. Limited to one task at a time.")
        args.num_workers = 1

    validate_rpms(info)

    srv = KickstartServer("10.0.2.2")
    srv.start()
    logging.basicConfig(level=logging.INFO)
    ret = 0
    with tempfile.TemporaryDirectory() as td:
        tmp_dir = Path(td)
        tpe = ThreadPoolExecutor(max_workers=args.num_workers)
        futures = []
        for image_info in info:
            log = logging.getLogger(image_info.name)
            tmp_sub_dir = tmp_dir / image_info.name
            tmp_sub_dir.mkdir()
            log.info("Launching with tmpdir: %s", tmp_sub_dir)
            ks_url = srv.url_for(args.ks_dir / image_info.ks_name)
            ctx = Context(
                image_info,
                args.iso_dir,
                args.image_dir,
                args.ks_dir,
                ks_url,
                srv,
                tmp_sub_dir,
                args.overwrite,
                args.interactive,
                log,
            )
            futures.append(tpe.submit(do_imgbuild, ctx))
        wait(futures, return_when="ALL_COMPLETED")
        for f in futures:
            if f.exception() is not None:
                ret = 1
                # f.result()
                print(f.exception())
        if ret == 1:
            print("Completed with with errors")
            if not args.no_wait:
                print(f"Tmpdir: {td}")
                input("Hit enter when done examining tmpdir")
    srv.stop()
    sys.exit(ret)


if __name__ == "__main__":
    main()
