# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import os
import subprocess
import time
from pathlib import Path

import pytest
from drgn import FaultError

from drgn_tools import block


@pytest.fixture(scope="module")
def fio(prog_type):
    if "DRGNTOOLS_BLOCK_TEST_DIR" in os.environ:
        path = Path(os.environ["DRGNTOOLS_BLOCK_TEST_DIR"])
    else:
        path = Path.cwd()
    path = path / "drgntools-fio.dat"
    proc = subprocess.Popen(
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
    try:
        # say what you will about sleep-sync, it does the job normally
        time.sleep(5)
        yield
    finally:
        if proc.poll() is not None:
            pytest.fail("The fio process died before all tests completed!")
        proc.terminate()
        proc.wait()


@pytest.mark.skip_vmcore("*")
def test_dump_inflight_io(prog, fio):
    # Retry this test a few times since it is flaky on a live system
    for _ in range(3):
        try:
            block.dump_inflight_io(prog)
            break
        except FaultError:
            pass
    else:
        pytest.fail("Inflight I/O failed 3 times")
