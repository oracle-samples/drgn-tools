# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn.helpers.linux.cpumask import for_each_possible_cpu

from drgn_tools import smp


def test_is_cur_csd_pending(prog):
    for cpu in for_each_possible_cpu(prog):
        print(smp.is_cur_csd_pending(prog, cpu))


def test_is_call_single_queue_empty(prog):
    for cpu in for_each_possible_cpu(prog):
        print(smp.is_call_single_queue_empty(prog, cpu))


def test_dump_smp_ipi_state(prog):
    smp.dump_smp_ipi_state(prog)
