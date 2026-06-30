# Copyright (c) 2023, 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import os
import shutil
import subprocess
import sys
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from drgn import FaultError
from drgn.helpers.linux.block import for_each_disk

import tests as test_context
from drgn_tools import corelens
from drgn_tools import scsi
from tests import DrgnToolsTestCase
from tests import skip_live
from tests import skip_unless_live
from tests import skip_unless_vmcore


@skip_live
@skip_unless_vmcore("iscsi-uek6")
class TestScsiVmcore(DrgnToolsTestCase):
    def _hosts(self):
        return list(scsi.for_each_scsi_host(self.prog))

    def test_scsi_helpers_and_reports(self):
        hosts = self._hosts()
        self.assertIn(
            "megaraid_sas", {scsi.host_module_name(host) for host in hosts}
        )

        devices = [
            dev
            for host in hosts
            for dev in scsi.for_each_scsi_host_device(host)
        ]
        names = {scsi.scsi_device_name(dev) for dev in devices}
        self.assertTrue({"sda", "sdb", "sdc"}.issubset(names))

        disks = {
            disk.disk_name.string_().decode(): disk
            for disk in for_each_disk(self.prog)
        }
        self.assertEqual(
            scsi.scsi_disk_driver(self.prog, disks["sdb"]), "megaraid_sas"
        )
        self.assertGreater(
            sum(len(list(scsi.for_each_scsi_target(host))) for host in hosts),
            0,
        )

        with redirect_stdout(StringIO()) as stdout:
            scsi.print_scsi_hosts(self.prog)
            scsi.print_shost_devs(self.prog)
            scsi.print_inflight_scsi_cmnds(self.prog)
            scsi.print_scsi_target(self.prog)

        output = stdout.getvalue()
        self.assertIn("SCSI_HOST", output)
        self.assertIn("Device", output)
        self.assertIn("Target Device", output)
        self.assertIn("READ_10", output)
        self.assertIn("WRITE_10", output)
        self.assertIn("Total inflight commands across all disks :", output)

    def test_corelens_scsiinfo(self):
        vmcore = test_context.VMCORE
        self.assertIsNotNone(vmcore)
        vmcore = Path(vmcore)
        command = [
            sys.executable,
            "-m",
            "drgn_tools.corelens",
            "--dwarf-dir",
            str(vmcore.parent),
            str(vmcore),
            "-M",
            "scsiinfo",
        ]
        for module_args in ([], scsi.ScsiInfo.default_args[0]):
            result = subprocess.run(
                command + module_args,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("SCSI_HOST", result.stdout)
            self.assertIn("megaraid_sas", result.stdout)
            if module_args:
                self.assertIn("Device", result.stdout)
                self.assertIn("Target Device", result.stdout)
                self.assertIn("READ_10", result.stdout)


@skip_unless_live
class TestScsiLiveVm(DrgnToolsTestCase):
    fio_proc = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        scsi_test_dir = os.environ.get("DRGNTOOLS_SCSI_TEST_DIR")
        if not scsi_test_dir:
            raise unittest.SkipTest("SCSI VM test disk is unavailable")
        fio = shutil.which("fio")
        if not fio:
            raise RuntimeError("fio is required for the SCSI VM tests")

        path = Path(scsi_test_dir) / "drgntools-scsi-fio.dat"
        cls.fio_proc = subprocess.Popen(
            [
                fio,
                f"--filename={path}",
                "--direct=1",
                "--rw=randrw",
                "--bs=4k",
                "--ioengine=libaio",
                "--iodepth=128",
                "--size=64m",
                "--runtime=120",
                "--numjobs=4",
                "--time_based",
                "--group_reporting",
                "--name=scsi-iotest",
            ]
        )

    @classmethod
    def tearDownClass(cls):
        if cls.fio_proc is None:
            return
        if cls.fio_proc.poll() is None:
            cls.fio_proc.terminate()
        cls.fio_proc.wait()

    def test_scsiinfo(self):
        hosts = [
            host
            for host in scsi.for_each_scsi_host(self.prog)
            if scsi.host_module_name(host) == "virtio_scsi"
        ]
        self.assertTrue(hosts)

        devices = list(scsi.for_each_scsi_host_device(hosts[0]))
        self.assertEqual(len(devices), 1)
        disk_name = scsi.scsi_device_name(devices[0])
        self.assertTrue(disk_name.startswith("sd"))
        self.assertTrue(list(scsi.for_each_scsi_target(hosts[0])))

        disks = {
            disk.disk_name.string_().decode(): disk
            for disk in for_each_disk(self.prog)
        }
        self.assertEqual(
            scsi.scsi_disk_driver(self.prog, disks[disk_name]), "virtio_scsi"
        )

        commands = []
        for _ in range(50):
            try:
                commands = list(scsi.for_each_scsi_cmnd(self.prog, devices[0]))
            except FaultError:
                pass
            if commands:
                break
            if self.fio_proc.poll() is not None:
                self.fail("fio exited before SCSI commands were observed")
            time.sleep(0.1)
        self.assertTrue(commands)

        with redirect_stdout(StringIO()) as stdout:
            corelens.run(
                self.prog,
                "scsiinfo --hosts --devices --queue --target --verbose",
            )

        output = stdout.getvalue()
        self.assertIn("virtio_scsi", output)
        self.assertIn(disk_name, output)
        self.assertIn("Target Device", output)
        self.assertIn("Total inflight commands across all disks :", output)


class TestScsi(DrgnToolsTestCase):
    def test_scsi_smoke(self):
        scsi.print_scsi_hosts(self.prog, verbose=True)
        scsi.print_shost_devs(self.prog)
        scsi.print_inflight_scsi_cmnds(self.prog)
        scsi.print_scsi_target(self.prog)

    def test_scsiinfo_required_debuginfo(self):
        """Loaded SCSI drivers required by scsiinfo must have DWARF."""
        checked = []
        for driver in scsi.ScsiInfo.debuginfo_kmods:
            try:
                module = self.prog.module(driver)
            except LookupError:
                continue
            checked.append(driver)
            self.assertFalse(module.wants_debug_file())
