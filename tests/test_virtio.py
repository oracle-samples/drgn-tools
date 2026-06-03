# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import virtio
from tests import DrgnToolsTestCase


class TestVirtio(DrgnToolsTestCase):
    def test_virtio_show(self):
        print("===== DUMP ALL VIRTIO DEVICES ONLY =====")
        # Print all virtio device
        virtio.virtio_show(self.prog)

        print("===== DUMP ALL VIRTIO DEVICES AND VRING =====")
        # Print all virtio device also all vrings
        virtio.virtio_show(self.prog, show_vq=True)

        print("===== DUMP virtio0 AND VRING =====")
        # Print virtio0 device also vrings
        virtio.virtio_show(self.prog, show_vq=True, vd_name="virtio0")
