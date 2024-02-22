# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
import dataclasses
import json
import sys
import tempfile
import time
import typing as t
from pathlib import Path

from paramiko.client import AutoAddPolicy
from paramiko.client import SSHClient

from testing.heavyvm.images import CONFIGURATIONS
from testing.heavyvm.qemu import create_overlay_disk
from testing.heavyvm.qemu import QemuRunner
from testing.heavyvm.qemu import UnixSocketRepl
from testing.util import BASE_DIR
from testing.util import ci_section_end
from testing.util import ci_section_start


@dataclasses.dataclass
class VmInfo:
    ssh_port: int
    serial_socket: Path
    monitor_socket: Path
    overlay_disk: Path
    nvme_disk: Path

    ol_version: t.Tuple[int, int]
    uek_version: int

    def get_serial_repl(self) -> UnixSocketRepl:
        return UnixSocketRepl(
            str(self.serial_socket),
            UnixSocketRepl.GENERIC_PROMPT,
        )

    def get_qemu_repl(self) -> UnixSocketRepl:
        return UnixSocketRepl(
            str(self.monitor_socket),
            UnixSocketRepl.QEMU_PROMPT,
        )

    def get_ssh(self) -> SSHClient:
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy)
        client.connect(
            "localhost",
            port=self.ssh_port,
            username="root",
            password="password",
        )
        return client

    def to_dict(self) -> t.Dict[str, t.Any]:
        d = dataclasses.asdict(self)
        d["serial_socket"] = str(self.serial_socket.absolute())
        d["monitor_socket"] = str(self.monitor_socket.absolute())
        d["overlay_disk"] = str(self.overlay_disk.absolute())
        d["nvme_disk"] = str(self.nvme_disk.absolute())
        return d

    @property
    def name(self) -> str:
        return (
            f"ol{self.ol_version[0]}u{self.ol_version[1]}uek{self.uek_version}"
        )

    @classmethod
    def from_dict(cls, d: t.Dict[str, t.Any]) -> "VmInfo":
        d["serial_socket"] = Path(d["serial_socket"])
        d["monitor_socket"] = Path(d["serial_socket"])
        d["overlay_disk"] = Path(d["overlay_disk"])
        d["nvme_disk"] = Path(d["nvme_disk"])
        return cls(**d)


class TestRunner:
    image_dir: Path
    vm_info_file: Path
    vm_info_dir: Path
    overlay_dir: Path
    vms: t.Dict[str, VmInfo]

    images: t.List[str]

    _vms_up: bool
    _ssh: t.Dict[str, SSHClient]

    def _section_start(
        self, name: str, text: str, collapsed: bool = False
    ) -> None:
        ci_section_start(name, text, collapsed=collapsed)

    def _section_end(self, name: str) -> None:
        ci_section_end(name)

    def _launch_vms(self) -> None:
        self._section_start("launch_vms", "Launching VMs", collapsed=True)
        info: t.List[VmInfo] = []
        serial_ports: t.List[UnixSocketRepl] = []
        self.vm_info_dir.mkdir(parents=True, exist_ok=True)
        for i, image in enumerate(CONFIGURATIONS):
            if self.images and image.name not in self.images:
                continue
            image_path = self.image_dir / image.image_name
            overlay = create_overlay_disk(
                image_path, "testrunner", where=self.overlay_dir
            )
            blank_nvme = tempfile.NamedTemporaryFile("wb", delete=False)
            blank_data = b"0" * 4096
            for _ in range(10):
                blank_nvme.write(blank_data)
            blank_nvme.close()
            runner = (
                QemuRunner(2, 4096, id=i)
                .hd(str(overlay.absolute()))
                .net_user(ssh=True, rand=True)
                .set_monitor("socket")
                .set_serial("socket")
                .args("-daemonize")
                .add_virtio_devs()
                .nvme(blank_nvme.name)
                .cwd(self.vm_info_dir)
            )
            runner.run()
            runner.wait()  # waits for the intermediate process to die
            info.append(
                VmInfo(
                    ssh_port=runner.ssh_port,  # type: ignore
                    serial_socket=self.vm_info_dir / runner.serial._filename,  # type: ignore # noqa
                    monitor_socket=self.vm_info_dir / runner.monitor._filename,  # type: ignore # noqa
                    overlay_disk=overlay,
                    nvme_disk=Path(blank_nvme.name),
                    ol_version=(image.ol, image.ol_update),
                    uek_version=image.uek,
                )
            )
            serial_ports.append(runner.serial.get_repl())
        print("Waiting for vms to come up...")
        for port in serial_ports:
            port.read_until(rb"localhost login:")
            port.close()
        self.vms = {i.name: i for i in info}
        with self.vm_info_file.open("w") as f:
            json.dump([d.to_dict() for d in info], f)
        self._vms_up = True
        self._section_end("launch_vms")

    def __init__(
        self,
        image_dir: t.Optional[Path] = None,
        vm_info_dir: t.Optional[Path] = None,
        overlay_dir: t.Optional[Path] = None,
        images: t.Optional[t.List[str]] = None,
    ):
        self.vm_info_dir = vm_info_dir or (BASE_DIR / "heavy-vminfo")
        self.vm_info_file = self.vm_info_dir / "vms.json"
        self.image_dir = image_dir or (BASE_DIR / "images")
        self.overlay_dir = overlay_dir or self.image_dir
        self._vms_up = False
        self._ssh = {}
        self.images = images or []
        if self.vm_info_file.exists():
            with self.vm_info_file.open() as f:
                vms = [VmInfo.from_dict(vm) for vm in json.load(f)]
                self.vms = {i.name: i for i in vms}
                self._vms_up = True
        else:
            self._launch_vms()

    def __enter__(self) -> None:
        pass

    def _get_ssh(self, vm: VmInfo) -> SSHClient:
        name = vm.name
        if name not in self._ssh:
            self._ssh[name] = vm.get_ssh()
        return self._ssh[name]

    def terminate_vms(self) -> None:
        if not self._vms_up:
            return
        for vm in self.vms.values():
            repl = vm.get_qemu_repl()
            repl.send_cmd(b"q")
            repl.close()
        time.sleep(1)
        for vm in self.vms.values():
            vm.overlay_disk.unlink()
            vm.nvme_disk.unlink()
        self.vm_info_file.unlink()
        self._vms_up = False

    def cleanup_ssh(self) -> None:
        for ssh_client in self._ssh.values():
            ssh_client.close()
        self._ssh.clear()

    def __exit__(self, *_: t.Any) -> None:
        self.cleanup_ssh()
        self.terminate_vms()

    def _run_cmd(
        self, client: SSHClient, cmd: str, check: bool = True
    ) -> t.Tuple[int, str]:
        channel = client.get_transport().open_session()  # type: ignore
        # redirect stderr to stdout for simplicity
        channel.exec_command(cmd + " 2>&1")
        data = bytearray()
        while True:
            new = channel.recv(4096)
            if len(new) == 0:
                break
            data.extend(new)
        status = channel.recv_exit_status()
        if check and status != 0:
            raise Exception(f"SSH command '{cmd}' failed ({status})")
        return status, data.decode()

    def copy_extract_files(self, archive: Path) -> None:
        for vm in self.vms.values():
            dest = Path("/root/test")
            ssh_client = self._get_ssh(vm)
            sftp = ssh_client.open_sftp()
            sftp.mkdir(str(dest))
            dest_file = dest / archive.name
            sftp.put(str(archive), str(dest_file))
            sftp.close()
            self._run_cmd(
                ssh_client, f"tar -C /root/test -xf /root/test/{archive.name}"
            )

    def run_cmd(self, cmd: str) -> None:
        self._section_start(
            "run_cmd", f"Running command {cmd}", collapsed=True
        )
        for vm in self.vms.values():
            print(
                f"Running command on ol{vm.ol_version[0]} uek{vm.uek_version}"
            )
            ssh_client = self._get_ssh(vm)
            _, result = self._run_cmd(ssh_client, cmd)
            print("Result:\n" + result)
        self._section_end("run_cmd")

    def run_test(self, cmd: str) -> int:
        fail_list = []
        for vm in self.vms.values():
            slug = f"ol{vm.ol_version[0]}uek{vm.uek_version}"
            self._section_start(
                f"test_{slug}", f"Running test on {slug}", collapsed=True
            )
            ssh_client = self._get_ssh(vm)
            code, result = self._run_cmd(ssh_client, cmd, check=False)
            print("Result:\n" + result)
            if code == 0:
                print("Passed!")
            else:
                print("Failed.")
                fail_list.append(vm.name)
            self._section_end(f"test_{slug}")
        if fail_list:
            print(
                "The following tests failed:\n- {}".format(
                    "\n- ".join(fail_list)
                )
            )
        else:
            print("All tests passed, nice!")
        return len(fail_list)


def main():
    parser = argparse.ArgumentParser(description="test runner")
    parser.add_argument(
        "--image-dir",
        type=Path,
        default=None,
        help="Directory to find the VM images",
    )
    parser.add_argument(
        "--vm-info-dir",
        type=Path,
        default=None,
        help="Directory to store serial and monitor connections",
    )
    parser.add_argument(
        "--overlay-dir",
        type=Path,
        default=None,
        help="Directory to store the ephemeral overlay disks",
    )
    parser.add_argument(
        "--tarball",
        type=Path,
        required=True,
        help="Location of git archive",
    )
    parser.add_argument(
        "images",
        nargs="*",
        help="Images to run tests on",
    )
    args = parser.parse_args()
    r = TestRunner(
        vm_info_dir=args.vm_info_dir,
        overlay_dir=args.overlay_dir,
        image_dir=args.image_dir,
        images=args.images,
    )
    with r:
        r.copy_extract_files(args.tarball)
        sys.exit(r.run_test("cd /root/test && python3 -m pytest -rP tests"))


if __name__ == "__main__":
    main()
