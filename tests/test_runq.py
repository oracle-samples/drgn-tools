# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn import ProgramFlags

import drgn_tools.runq as runq


def test_run_queue(prog):
    if ProgramFlags.IS_LIVE & prog.flags:
        return
    runq.run_queue(prog)


def test_run_queue_check(prog):
    if ProgramFlags.IS_LIVE & prog.flags:
        return
    runq.run_queue_check(prog)
