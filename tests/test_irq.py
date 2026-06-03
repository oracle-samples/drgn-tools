# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import irq
from tests import DrgnToolsTestCase


class TestIrq(DrgnToolsTestCase):
    def test_print_all_irqs(self):
        irq.print_all_irqs(self.prog)

    def test_print_irqs_affinities(self):
        irq.print_irqs_affinities(self.prog)

    def test_show_each_cpu_irq_stats(self):
        irq.show_each_cpu_irq_stats(self.prog)

    def test_show_irq_stats(self):
        irq.show_irq_stats(self.prog)

    def test_show_cpu_irq_stats(self):
        irq.show_cpu_irq_stats(self.prog, 0)
