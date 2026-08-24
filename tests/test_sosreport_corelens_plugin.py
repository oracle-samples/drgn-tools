# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import importlib.util
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


def load_corelens_sosreport_module():
    file = Path(__file__).parent.parent / "extras/corelens.py"
    if not file.is_file():
        raise unittest.SkipTest("extras/corelens.py does not exist")

    plugins = types.ModuleType("sos.report.plugins")
    plugins.Plugin = type("Plugin", (), {})
    plugins.RedHatPlugin = type("RedHatPlugin", (), {})

    class PluginOpt:
        def __init__(self, *args, **kwargs):
            pass

    plugins.PluginOpt = PluginOpt

    report = types.ModuleType("sos.report")
    report.plugins = plugins
    sos = types.ModuleType("sos")
    sos.report = report

    with mock.patch.dict(
        sys.modules,
        {
            "sos": sos,
            "sos.report": report,
            "sos.report.plugins": plugins,
        },
    ):
        spec = importlib.util.spec_from_file_location(
            "corelens_under_test", str(file)
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


class TestVmcorePath(unittest.TestCase):
    def test_fs_target(self):
        corelens = load_corelens_sosreport_module()

        for conf_path in ("crash", "/crash", "/"):
            with self.subTest(
                f"path {conf_path}"
            ), tempfile.NamedTemporaryFile("wt") as tf, mock.patch.object(
                corelens.subprocess,
                "check_output",
                return_value="/mnt/kdump\n",
            ):
                tf.write(
                    "\n".join(
                        [
                            "# Comment",
                            "",
                            "xfs UUID=foobar",
                            f"path {conf_path}",
                            "",
                        ]
                    )
                )
                tf.flush()
                path, err = corelens.LibCorelens.get_vmcore_dir_path(
                    None, kdump_conf=tf.name
                )

            if conf_path == "/":
                self.assertEqual(path, "/mnt/kdump/")
            else:
                self.assertEqual(path, "/mnt/kdump/crash")
            self.assertIsNone(err)

    def test_rootfs_target(self):
        corelens = load_corelens_sosreport_module()

        with tempfile.NamedTemporaryFile("wt") as tf, mock.patch.object(
            corelens.subprocess,
            "check_output",
            return_value="/mnt/kdump\n",
        ):
            tf.write(
                "\n".join(
                    [
                        "# Comment",
                        "",
                        "# xfs UUID=foobar",
                        "path /crash",
                        "",
                    ]
                )
            )
            tf.flush()
            path, err = corelens.LibCorelens.get_vmcore_dir_path(
                None, kdump_conf=tf.name
            )

        self.assertEqual(path, "/crash")
        self.assertIsNone(err)

    def test_rootfs_target_relative(self):
        corelens = load_corelens_sosreport_module()

        with tempfile.NamedTemporaryFile("wt") as tf, mock.patch.object(
            corelens.subprocess,
            "check_output",
            return_value="/mnt/kdump\n",
        ):
            tf.write(
                "\n".join(
                    [
                        "# Comment",
                        "",
                        "# xfs UUID=foobar",
                        "path crash",
                        "",
                    ]
                )
            )
            tf.flush()
            path, err = corelens.LibCorelens.get_vmcore_dir_path(
                None, kdump_conf=tf.name
            )

        self.assertIsNone(path)
        self.assertEqual(err, "error: absolute path required: crash")

    def test_noconfig(self):
        corelens = load_corelens_sosreport_module()

        with tempfile.NamedTemporaryFile("wt") as tf, mock.patch.object(
            corelens.subprocess,
            "check_output",
            return_value="/mnt/kdump\n",
        ):
            tf.write(
                "\n".join(
                    [
                        "# Comment",
                        "",
                        "# xfs UUID=foobar",
                        "# path /crash",
                        "",
                    ]
                )
            )
            tf.flush()
            path, err = corelens.LibCorelens.get_vmcore_dir_path(
                None, kdump_conf=tf.name
            )

        self.assertEqual(path, "/var/crash")
        self.assertIsNone(err)

    def test_unsupported_fs(self):
        corelens = load_corelens_sosreport_module()

        for fstype in ("nfs", "raw", "ssh"):
            with self.subTest(f"config {fstype}"), tempfile.NamedTemporaryFile(
                "wt"
            ) as tf, mock.patch.object(
                corelens.subprocess,
                "check_output",
                return_value="/mnt/kdump\n",
            ):
                tf.write(
                    "\n".join(
                        [
                            "# Comment",
                            "",
                            f"{fstype} target",
                            "# path /crash",
                            "",
                        ]
                    )
                )
                tf.flush()
                path, err = corelens.LibCorelens.get_vmcore_dir_path(
                    None, kdump_conf=tf.name
                )

            self.assertIsNone(path)
            self.assertEqual(
                err, f"error: vmcore storage not supported: {fstype} target"
            )

    def test_findmnt_fail(self):
        corelens = load_corelens_sosreport_module()

        with tempfile.NamedTemporaryFile("wt") as tf, mock.patch.object(
            corelens.subprocess,
            "check_output",
            side_effect=subprocess.CalledProcessError(1, "findmnt foo"),
        ):
            tf.write(
                "\n".join(
                    [
                        "# Comment",
                        "",
                        " xfs target",
                        "# path /crash",
                        "",
                    ]
                )
            )
            tf.flush()
            path, err = corelens.LibCorelens.get_vmcore_dir_path(
                None, kdump_conf=tf.name
            )

        self.assertIsNone(path)
        self.assertEqual(
            err, "error: could not find storage target: xfs target"
        )
