# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import irq


def test_print_all_irqs(prog):
    irq.print_all_irqs(prog)


def test_print_irqs_affinities(prog):
    irq.print_irqs_affinities(prog)


def test_show_each_cpu_irq_stats(prog):
    irq.show_each_cpu_irq_stats(prog)


def test_show_irq_stats(prog):
    irq.show_irq_stats(prog)


def test_show_cpu_irq_stats(prog):
    irq.show_cpu_irq_stats(prog, 0)
