# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn
import pytest

from drgn_tools import bt


@pytest.mark.skip_vmcore("*-uek4")
def test_bt_smoke(prog, request, debuginfo_type):
    if (
        debuginfo_type == "ctf"
        and prog.platform.arch == drgn.Architecture.AARCH64
    ):
        pytest.xfail("still unsupported for unwinding with aarch64 + CTF")
    if prog.flags & drgn.ProgramFlags.IS_LIVE:
        thread = prog.thread(1)
    else:
        thread = prog.crashed_thread()

    print("===== STACK TRACE [show_vars=False] =====")
    bt.bt(thread, show_vars=False)
    print("===== STACK TRACE [show_vars=True] =====")
    bt.bt(thread, show_vars=True)
