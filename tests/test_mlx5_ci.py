# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Tests exercised by the drgn-tools unittest-based CI runners."""
import unittest

from drgn_tools.corelens import all_corelens_modules
from drgn_tools.mlx5_support.decode import _decode_wqe


class TestMlx5Corelens(unittest.TestCase):
    def test_module_is_discoverable(self):
        module = all_corelens_modules()["mlx5"]

        self.assertEqual(module.name, "mlx5")
        self.assertEqual(module.run_when, "never")
        self.assertEqual(module.skip_unless_have_kmods, ["mlx5_core"])
        self.assertEqual(module.debuginfo_kmods, ["mlx5_core", "mlx5_ib"])

    def test_decode_send_wqe(self):
        raw = bytearray(64)
        raw[0:4] = ((0x02 << 24) | (0x3456 << 8) | 0x0A).to_bytes(4, "big")
        raw[4:8] = ((0x123456 << 8) | 0x18).to_bytes(4, "big")

        decoded = _decode_wqe(bytes(raw))

        self.assertEqual(decoded["opcode_display"], "SEND(0xa)")
        self.assertEqual(decoded["wqe_index"], 0x3456)
        self.assertEqual(decoded["qpn"], 0x123456)
        self.assertEqual(decoded["ds"], 0x18)


if __name__ == "__main__":
    unittest.main()
