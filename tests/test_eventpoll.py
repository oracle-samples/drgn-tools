# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import eventpoll


def test_eventpoll(prog):
    eventpoll.dump_eventpoll_info(prog, ready_only=False)
