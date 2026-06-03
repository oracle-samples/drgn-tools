# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import os
import shutil
import subprocess
import time
import unittest
from pathlib import Path

from drgn import FaultError

import tests as test_context
from drgn_tools import inflightio
from tests import DrgnToolsTestCase


class TestInflightio(DrgnToolsTestCase):
    fio_proc = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if test_context.VMCORE:
            raise unittest.SkipTest("test marked to skip on vmcores")
        if not shutil.which("fio"):
            raise unittest.SkipTest("fio is not available")
        if "DRGNTOOLS_BLOCK_TEST_DIR" in os.environ:
            path = Path(os.environ["DRGNTOOLS_BLOCK_TEST_DIR"])
        else:
            path = Path.cwd()
        path = path / "drgntools-fio.dat"
        cls.fio_proc = subprocess.Popen(
            [
                "fio",
                f"--filename={path}",
                "--direct=1",
                "--rw=randrw",
                "--bs=4k",
                "--ioengine=libaio",
                "--iodepth=128",
                "--size=100m",
                "--runtime=120",
                "--numjobs=4",
                "--time_based",
                "--group_reporting",
                "--name=iotest",
            ]
        )
        # say what you will about sleep-sync, it does the job normally
        time.sleep(5)

    @classmethod
    def tearDownClass(cls):
        if cls.fio_proc is None:
            return
        try:
            if cls.fio_proc.poll() is not None:
                raise AssertionError(
                    "The fio process died before all tests completed!"
                )
        finally:
            if cls.fio_proc.poll() is None:
                cls.fio_proc.terminate()
            cls.fio_proc.wait()

    def test_dump_inflight_io(self):
        # Retry this test a few times since it is flaky on a live system
        for _ in range(3):
            try:
                inflightio.dump_inflight_io(self.prog)
                break
            except FaultError:
                pass
        else:
            self.fail("Inflight I/O failed 3 times")
