# Copyright (c) 2023, 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

import drgn_tools.lsmod as lsmod
from tests import DrgnToolsTestCase
from tests import skip_unless_have_kmod


class TestLsmod(DrgnToolsTestCase):
    MODULE_NAME = "drgntools_test"

    def _test_module(self):
        return self.prog.module(self.MODULE_NAME).object

    def test_smoke(self):
        lsmod.print_module_summary(self.prog)
        lsmod.print_module_parameters(self.prog)

    @skip_unless_have_kmod
    def test_print_module_summary(self):
        mod = self._test_module()

        with patch.object(lsmod, "for_each_module", return_value=[mod]):
            with patch.object(lsmod, "print_table") as print_table:
                lsmod.print_module_summary(self.prog)

        print_table.assert_called_once()
        table = print_table.call_args[0][0]

        self.assertEqual(
            table[0],
            ["MODULE", "NAME", "SIZE", "REF", "DEPENDENT MODULES"],
        )
        self.assertEqual(len(table), 2)
        self.assertEqual(table[1][0], hex(mod.value_()))
        self.assertEqual(table[1][1], self.MODULE_NAME)
        self.assertGreater(int(table[1][2]), 0)
        self.assertEqual(table[1][3], str(int(mod.refcnt.counter)))
        self.assertEqual(table[1][4], "")

    @skip_unless_have_kmod
    def test_print_module_parameters(self):
        mod = self._test_module()

        with patch.object(lsmod, "for_each_module", return_value=[mod]):
            with patch.object(lsmod, "print_table") as print_table:
                with redirect_stdout(StringIO()) as stdout:
                    lsmod.print_module_parameters(self.prog)

        print_table.assert_called_once()
        table = print_table.call_args[0][0]
        output = stdout.getvalue()

        self.assertIn(f"MODULE NAME:    {self.MODULE_NAME}", output)
        self.assertIn(f"PARAM COUNT: {mod.num_kp.value_()}", output)
        self.assertIn(f"ADDRESS    : {hex(mod.num_kp.address_of_())}", output)

        self.assertEqual(table[0], ["PARAMETER", "ADDRESS", "TYPE", "VALUE"])
        rows = {row[0]: row for row in table[1:]}
        params = lsmod.module_params(mod)
        self.assertEqual(len(rows), mod.num_kp.value_())
        self.assertEqual(rows.keys(), params.keys())

        expected = {
            "lsmod_test_int": ("int", "-42"),
            "lsmod_test_uint": ("uint", "4242"),
            "lsmod_test_long": ("long", "-420000"),
            "lsmod_test_ulong": ("ulong", "420000"),
            "lsmod_test_true": ("bool", "Y"),
            "lsmod_test_false": ("bool", "N"),
            "lsmod_test_charp": (
                "charp",
                '"drgn \\"tools\\" \\\\ lsmod"',
            ),
            "lsmod_test_null_charp": ("charp", "(null)"),
            "lsmod_test_string": ("string", '"fixed string"'),
        }

        for name, (type_name, value) in expected.items():
            row = rows[name]
            self.assertEqual(
                row[1], hex(params[name].kernel_param.address_of_())
            )
            self.assertEqual(row[2], type_name)
            self.assertEqual(row[3], value)

        row = rows["lsmod_test_array"]
        self.assertEqual(
            row[1],
            hex(params["lsmod_test_array"].kernel_param.address_of_()),
        )
        self.assertEqual(row[2], "int[3]")
        self.assertIn("10", row[3])
        self.assertIn("20", row[3])
        self.assertIn("-30", row[3])
        self.assertNotIn("40", row[3])
