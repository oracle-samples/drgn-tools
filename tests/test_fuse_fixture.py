# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import ctypes
import os
import subprocess
import sys
import time
import unittest

from testing.fuse_fixture import FuseFixture
from tests import DrgnToolsTestCase
from tests import skip_unless_live


@skip_unless_live
class TestFuseFixture(DrgnToolsTestCase):
    @classmethod
    def setUpClass(cls):
        unavailable = False
        if os.geteuid() != 0 or not os.path.exists("/dev/fuse"):
            unavailable = True
        try:
            ctypes.CDLL("libfuse3.so.3")
        except OSError:
            unavailable = True
        if unavailable:
            if "DRGNTOOLS_BLOCK_TEST_DIR" in os.environ:
                raise RuntimeError("FUSE 3 is not available in the VM")
            raise unittest.SkipTest("FUSE mounting is not available")
        super().setUpClass()

    def test_contents_and_timed_write(self):
        with FuseFixture(write_delay=0.05) as fixture:
            self.assertIsNotNone(fixture.mountpoint)
            self.assertIsNotNone(fixture.file_path)
            self.assertEqual(os.listdir(str(fixture.mountpoint)), ["file"])
            self.assertEqual(fixture.file_path.read_bytes(), b"test")
            start = time.monotonic()
            self.assertEqual(fixture.file_path.write_bytes(b"write"), 5)
            self.assertGreaterEqual(time.monotonic() - start, 0.04)

    def test_close_aborts_write(self):
        fixture = FuseFixture(write_delay=60.0)
        with fixture:
            self.assertIsNotNone(fixture.file_path)
            mountpoint = fixture.mountpoint
            self.assertIsNotNone(mountpoint)
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; import sys; "
                    "Path(sys.argv[1]).write_bytes(b'x')",
                    str(fixture.file_path),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.1)
            self.assertIsNone(proc.poll())
        self.assertNotEqual(proc.wait(timeout=2), 0)
        self.assertFalse(mountpoint.exists())
