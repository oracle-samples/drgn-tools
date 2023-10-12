# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import nvme


def test_nvme_show(prog):
    print("===== Dump NVMe namespace info =====")
    nvme.show_ns_info(prog)

    print("===== Dump NVMe controller info =====")
    nvme.show_ctrl_info(prog)

    print("===== Dump NVMe firmware info =====")
    nvme.show_firmware_info(prog)

    print("===== Dump NVMe queue info =====")
    nvme.show_queue_info(prog)

    print("===== Dump NVMe queue map =====")
    nvme.show_queue_map(prog)

    print("===== Dump NVMe MSI mask =====")
    nvme.show_msi_mask(prog)
