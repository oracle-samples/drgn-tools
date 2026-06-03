# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import nvme
from tests import DrgnToolsTestCase


class TestNvme(DrgnToolsTestCase):
    def test_nvme_show(self):
        print("===== Dump NVMe namespace info =====")
        nvme.show_ns_info(self.prog)

        print("===== Dump NVMe controller info =====")
        nvme.show_ctrl_info(self.prog)

        print("===== Dump NVMe firmware info =====")
        nvme.show_firmware_info(self.prog)

        print("===== Dump NVMe queue info =====")
        nvme.show_queue_info(self.prog)

        print("===== Dump NVMe queue map =====")
        nvme.show_queue_map(self.prog)

        print("===== Dump NVMe MSI mask =====")
        nvme.show_msi_mask(self.prog)
