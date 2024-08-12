# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn
from drgn.helpers.linux import cpu_curr

from drgn_tools import bt


def test_bt_smoke(prog):
    if prog.flags & drgn.ProgramFlags.IS_LIVE:
        thread = prog.thread(1)
    else:
        try:
            thread = prog.crashed_thread()
        except Exception:
            # On x86_64 uek4, the sysrq does not actually trigger a panic, it
            # triggers a NULL pointer dereference, which triggers an "oops", and
            # that directly calls into the kexec code without ever calling
            # panic(). Thus, panic_cpu == -1, and prog.crashing_cpu() page
            # faults because it tries to index the wrong per-cpu variables.
            # To handle this, use the x86_64-specific "crashing_cpu" variable.
            # Note that on some drgn versions we get "FaultError", others we get
            # "Exception". So we just catch Exception here.
            pid = cpu_curr(prog, prog["crashing_cpu"]).pid.value_()
            thread = prog.thread(pid)

    print("===== STACK TRACE [show_vars=False] =====")
    bt.bt(thread, show_vars=False)
    print("===== STACK TRACE [show_vars=True] =====")
    bt.bt(thread, show_vars=True)
