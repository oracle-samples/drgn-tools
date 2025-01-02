# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import kvm


def test_kvmutil(prog):
    kvm.print_vm_list(prog)
    kvm.print_vcpu_list(prog)
