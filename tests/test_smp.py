# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn.helpers.linux.cpumask import for_each_possible_cpu

from drgn_tools import smp
from tests import DrgnToolsTestCase
from tests import skip_live


class TestSmp(DrgnToolsTestCase):
    def test_is_cur_csd_pending(self):
        for cpu in for_each_possible_cpu(self.prog):
            print(smp.is_cur_csd_pending(self.prog, cpu))

    def test_is_call_single_queue_empty(self):
        for cpu in for_each_possible_cpu(self.prog):
            print(smp.is_call_single_queue_empty(self.prog, cpu))

    @skip_live  # flaky on live systems
    def test_dump_smp_ipi_state(self):
        smp.dump_smp_ipi_state(self.prog)
