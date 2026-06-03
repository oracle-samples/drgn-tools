# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import kvm
from tests import DrgnToolsTestCase


class TestKvm(DrgnToolsTestCase):
    def test_kvmutil(self):
        kvm.print_vm_list(self.prog)
        kvm.print_vcpu_list(self.prog)
        kvm.print_memslot_info(self.prog)
        kvm.print_ioeventfd_info(self.prog)
        kvm.print_kvmstat_info(self.prog)
