# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Module which facilitates running Qemu and interacting with VMs.
"""
import argparse
import os
import queue
import random
import re
import select
import socket
import subprocess
import threading
import time
import typing as t
from abc import ABC
from abc import abstractmethod
from pathlib import Path


def choose_ssh_port(start: int = 10000, end: int = 30000) -> int:
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
    )
    # Ensure that after closing the socket, we can reuse it immediately.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tries = 50
    for _ in range(tries):
        port = random.randrange(start, end)
        try:
            sock.bind(("127.0.0.1", port))
            sock.close()
            return port
        except OSError:
            pass
    raise Exception("Couldn't select a unique SSH port after {tries} tries")


class _ThreadIdRegistry:
    """
    Register threads with a unique index starting at 0 .

    This is useful to make sure threads won't collide with their filename or
    port choices.
    """

    current: int
    tls: threading.local
    lock: threading.Lock

    def __init__(self):
        self.current = 0
        self.tls = threading.local()
        self.lock = threading.Lock()

    def get(self) -> int:
        if not hasattr(self.tls, "id"):
            with self.lock:
                self.tls.id = self.current
                self.current += 1
        return self.tls.id


THREAD_ID = _ThreadIdRegistry()


class Repl(ABC):
    GENERIC_PROMPT = rb"\n.*[:$#>)] "
    QEMU_PROMPT = rb"\n(qemu) "
    ROOT_PROMPT = rb"\[root@localhost [^\]]*\]# "

    prompt: bytes
    """A bytes interpreted as regexp which matches the REPL prompt"""

    @abstractmethod
    def read_until(
        self, pattern: bytes, timeout: t.Optional[int] = None
    ) -> bytes:
        """Return output until is encountered or timeout expires"""

    @abstractmethod
    def read_all(self) -> bytes:
        """Return whatever output is buffered, without waiting."""

    @abstractmethod
    def send_cmd(self, cmd: bytes) -> None:
        """Send a command to the REPL and return immediately."""

    @abstractmethod
    def close(self) -> None:
        """Close all resources held by the repl"""

    def cmd(self, cmd: bytes, timeout: t.Optional[int] = None) -> bytes:
        """Send a command and wait for its result."""
        self.send_cmd(cmd)
        return self.read_until(self.prompt, timeout=timeout)

    @abstractmethod
    def set_logger(self, filename: str) -> None:
        """Log all data read from the serial port to filename."""


class UnixSocketRepl(Repl):
    _old: bytes
    path: str
    sock: socket.socket
    q: queue.Queue
    _exitrfd: int
    _exitwfd: int
    _thread: threading.Thread
    prompt: bytes
    _logfile: t.Optional[t.BinaryIO]

    def __init__(self, path: str, prompt: bytes):
        self.path = path
        self.prompt = prompt
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)
        self._old = b""
        self.q = queue.Queue(maxsize=0)
        self._exitrfd, self._exitwfd = os.pipe()
        self._logfile = None
        self._thread = threading.Thread(target=self._reader_thread)
        self._thread.start()

    def _reader_thread(self) -> None:
        while True:
            r, _, _ = select.select(
                [self.sock.fileno(), self._exitrfd], [], []
            )
            if self._exitrfd in r:
                break
            if self.sock.fileno() not in r:
                continue
            data = self.sock.recv(4096)
            if data:
                self.q.put(data)
                if self._logfile:
                    self._logfile.write(data)
        if self._logfile:
            self._logfile.close()

    def close(self) -> None:
        os.write(self._exitwfd, b"x")
        self._thread.join()
        self.sock.close()

    def read_all(self) -> bytes:
        data = self._old
        self._old = b""
        try:
            while True:
                data += self.q.get(block=False)
        except queue.Empty:
            return data

    def read_until(
        self, pattern: bytes, timeout: t.Optional[float] = None
    ) -> bytes:
        expr = re.compile(pattern)
        result = self._old
        self._old = b""
        if timeout is not None:
            end_time = time.time() + timeout
        while True:
            # Check timeout and set what we will use for select below.
            if timeout is not None:
                timeout = end_time - time.time()
                if timeout <= 0:
                    self._old = result
                    raise TimeoutError("Timed out waiting for pattern")

            # Check for match in result
            m = expr.search(result)
            if m is not None:
                self._old = result[m.end() :]
                return result[: m.end()]

            # Wait for data
            data = self.q.get(block=True, timeout=timeout)
            result += data

    def send_cmd(self, cmd: bytes) -> None:
        self.sock.send(cmd + b"\n")

    def set_logger(self, filename: str) -> None:
        self._logfile = open(filename, "wb")


class ConfiguredPort:
    """
    This class represents a character device QEMU lets you configure.

    Generally, this will represent either a serial or monitor device. Both of
    these have several options: defaults (unreliable), empty device (null), no
    device (none), stdio or multiplexed together, a file for logging, or a
    socket for interactivity. This class allows to configure these easily.

    If a socket is used, then this will also allow you to create a "repl" ready
    to interact with the VM.
    """

    _kind: str
    _filename: t.Optional[str]
    _is_socket: bool
    _socket: t.Optional[UnixSocketRepl]
    _args: t.List[str]
    _qemu: "QemuRunner"

    def __init__(self, kind: str, qemu: "QemuRunner"):
        self._kind = kind
        self._qemu = qemu
        self.null()

    def _basic(self, args: t.List[str]) -> None:
        # helper for simple outputs
        self._filename = None
        self._args = args
        self._socket = None
        self._is_socket = False

    def omit(self) -> None:
        """
        Don't include command line arguments for this port.

        Generally not a good idea, but it is necessary to configure a
        multiplexed serial and Qemu monitor on stdio.
        """
        self._basic([])

    def none(self) -> None:
        """Instruct qemu to exclude this device"""
        self._basic([self._kind, "none"])

    def null(self) -> None:
        """Instruct qemu to include this device with no backend"""
        self._basic([self._kind, "null"])

    def stdio(self) -> None:
        """Instruct qemu to bind to stdio"""
        self._basic([self._kind, "stdio"])

    def shared(self) -> None:
        """
        For serial, create a multiplexed monitor+serial.

        The monitor device should be configured using omit().
        """
        assert self._kind == "-serial"
        self._basic([self._kind, "mon:stdio"])

    def socket(self) -> None:
        """Configure a unix socket"""
        self._filename = f"socket{self._kind}-{self._qemu._id}"
        self._args = [self._kind, f"unix:{self._filename},server=on,wait=off"]
        self._socket = None
        self._is_socket = True

    def log(self, filename: t.Optional[str] = None) -> None:
        """Configure a file output for logging (no input)"""
        if filename:
            self._filename = filename
        else:
            self._filename = f"log{self._kind}-{self._qemu._id}.log"
        self._args = [self._kind, f"file:{self._filename}"]
        self._socket = None
        self._is_socket = False

    def get_repl(self) -> UnixSocketRepl:
        """For sockets, return a Repl to interact with"""
        assert self._is_socket
        assert self._filename is not None
        end = time.time() + 10
        path = self._qemu._cwd / self._filename
        while time.time() < end:
            if path.exists():
                break
            time.sleep(0.1)
        if not self._socket:
            if self._kind == "-monitor":
                self._socket = UnixSocketRepl(str(path), rb"\n\(qemu\) ")
            else:
                # can't know about the serial prompt, so set a fake one that
                # will read until a line with ": " or "$ " or "# ""
                self._socket = UnixSocketRepl(str(path), rb"\n.*[$:#] $")
        return self._socket


class QemuRunner:
    """
    This is a nice wrapper around QEMU for both Python and interactive use.

    The hope is to make it simple to configure QEMU in code, and then interact
    with the resulting VM's control socket, serial port, SSH, or VNC. To use
    the class, construct an instance. You must then perform the following
    required configuration:

    1. Disk configuration - use .hd() or .drive(). At least one disk argument
       is required.

    You may optionally do the following configurations:

    1. Networking - default is none, but you can setup user networking
       with SSH enabled:
       .net_user(ssh=True|False)
    2. VNC - default is off. Use .vnc_off() or .vnc_on() to change it.
    3. Serial - default is "null", but can select:
       .serial_stdio() - not a good idea for multiple threads
       .serial_log(filename)
       .serial_null()
    4. Monitor - default is none, but can select:
       .monitor_none()
       .monitor_qmp(filename)
    5. CDROM - add an ISO file / cdrom
    6. Kernel - add a kernel + initrd + args

    """

    _cpumem_args: t.List[str]
    _disk_args: t.List[str]

    _net_args: t.List[str]
    ssh_port: t.Optional[int]

    _vnc_args: t.List[str]
    vnc_port: t.Optional[int]

    serial: ConfiguredPort
    monitor: ConfiguredPort

    _misc_args: t.List[str]

    _hd: t.List[str]
    _id: int
    _proc: t.Optional[subprocess.Popen]
    _cwd: Path

    def __init__(
        self,
        cpus: int,
        mem: int,
        cpu: str = "host",
        id: t.Optional[int] = None,
    ):
        self._cpumem_args = ["-smp", str(cpus), "-m", str(mem), "-cpu", cpu]
        self._disk_args = []
        self._misc_args = []
        self._hd = ["hda", "hdb", "hdc", "hdd"]
        self._id = id if id is not None else THREAD_ID.get()
        self.net_none()
        self.vnc_off()
        self.serial = ConfiguredPort("-serial", self)
        self.monitor = ConfiguredPort("-monitor", self)
        self._proc = None
        self._cwd = Path.cwd()

    def hd(self, path: str) -> "QemuRunner":
        """
        Add a basic file-backed hard disk. Choose the first node name
        available.
        """
        if not self._hd:
            raise ValueError("Exhausted hda through hdd")
        hd = self._hd.pop(0)
        self._disk_args.extend([f"-{hd}", path])
        return self

    def drive(self, **kwargs: str) -> "QemuRunner":
        """
        Wraps the qemu -drive argument, provide any args you want.
        """
        if "node_name" in kwargs:
            node_name = kwargs["node_name"]
            if node_name not in self._hd:
                raise ValueError(f"Node {node_name} not available")
            else:
                self._hd.remove(node_name)
        arg = ",".join(f"{k.replace('_', '-')}={v}" for k, v in kwargs.items())
        self._disk_args.extend(["-drive", arg])
        return self

    def net_none(self) -> "QemuRunner":
        self._net_args = []
        self.ssh_port = None
        return self

    def net_user(self, ssh: bool = False, rand: bool = False) -> "QemuRunner":
        self._net_args = ["-net", "nic", "-net"]
        if ssh:
            if rand:
                port = choose_ssh_port()
            else:
                port = 5022 + self._id
            self._net_args.append(f"user,hostfwd=::{port}-:22")
            self.ssh_port = port
        else:
            self._net_args.append("user")
            self.ssh_port = None
        return self

    def vnc(self) -> "QemuRunner":
        self._vnc_args = ["-vnc", f":{self._id}"]
        self.vnc_port = 5900 + self._id
        return self

    def vnc_off(self) -> "QemuRunner":
        self._vnc_args = ["-vnc", "none"]
        self.vnc_port = None
        return self

    def set_serial(self, mode: str) -> "QemuRunner":
        getattr(self.serial, mode)()
        return self

    def set_monitor(self, mode: str) -> "QemuRunner":
        getattr(self.monitor, mode)()
        return self

    def mon_serial(self):
        self.monitor.omit()
        self.serial.shared()
        return self

    def cdrom(self, path: str) -> "QemuRunner":
        self._misc_args.extend(["-cdrom", path])
        return self

    def add_virtio_devs(self) -> "QemuRunner":
        return self.args(
            "-device",
            "virtio-rng-pci",
        )

    def nvme(
        self, file: str, id: str = "nvm", format: str = "raw"
    ) -> "QemuRunner":
        return self.args(
            "-drive",
            f"file={file},if=none,format={format},id={id}",
            "-device",
            f"nvme,serial=deadbeef,drive={id}",
        )

    def kernel(
        self,
        path: str,
        initrd: t.Optional[str] = None,
        cmdline: t.Optional[str] = None,
    ) -> "QemuRunner":
        self._misc_args.extend(["-kernel", path])
        if initrd:
            self._misc_args.extend(["-initrd", initrd])
        if cmdline:
            self._misc_args.extend(["-append", cmdline])
        return self

    def args(self, *args: str) -> "QemuRunner":
        """Specify your own args to qemu, be careful with this!"""
        self._misc_args.extend(args)
        return self

    def cwd(self, path: Path) -> "QemuRunner":
        self._cwd = path
        return self

    def get_cmd(self) -> t.List[str]:
        return (
            ["qemu-system-x86_64", "-enable-kvm"]
            + self._cpumem_args
            + self._disk_args
            + self._net_args
            + self._vnc_args
            + self.serial._args
            + self.monitor._args
            + self._misc_args
        )

    def run(self) -> subprocess.Popen:
        self._proc = subprocess.Popen(self.get_cmd(), cwd=self._cwd)
        return self._proc

    def wait(self):
        self._proc.wait()


def create_overlay_disk(
    disk: Path,
    suffix: str,
    where: t.Optional[Path] = None,
) -> Path:
    if not where:
        where = disk.parent
    overlay = where / f"{disk.name}.{suffix}"
    if overlay.exists():
        overlay.unlink()
    subprocess.run(
        [
            "qemu-img",
            "create",
            "-F",
            "qcow2",
            "-f",
            "qcow2",
            "-b",
            str(disk.absolute()),
            str(overlay.absolute()),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return overlay


def main():
    parser = argparse.ArgumentParser(description="Heavy VM Qemu helper")
    parser.add_argument(
        "disk",
        help="disk image to boot",
    )
    args = parser.parse_args()
    disk = Path(args.disk)
    overlay = create_overlay_disk(disk, "tmp")
    print("Created temporary boot disk. Starting qemu...")
    runner = (
        QemuRunner(2, 4096)
        .hd(str(overlay))
        .add_virtio_devs()
        .net_user(ssh=True)
        .vnc()
        .mon_serial()
    )
    print(repr(runner.get_cmd()))
    runner.run()
    runner.wait()
    if input("delete temporary disk? ").lower() == "y":
        overlay.unlink()


if __name__ == "__main__":
    main()
