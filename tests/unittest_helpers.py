# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Small adapters for function-style tests run by unittest."""
import contextlib
import inspect
import io
import unittest
from types import SimpleNamespace
from unittest import mock


class MonkeyPatch:
    def __init__(self):
        self._patchers = []

    def setattr(self, target, name, value):
        patcher = mock.patch.object(target, name, value)
        patcher.start()
        self._patchers.append(patcher)

    def undo(self):
        for patcher in reversed(self._patchers):
            patcher.stop()
        self._patchers.clear()


class Capture:
    def __init__(self):
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

    def readouterr(self):
        captured = SimpleNamespace(
            out=self.stdout.getvalue(), err=self.stderr.getvalue()
        )
        self.stdout.seek(0)
        self.stdout.truncate(0)
        self.stderr.seek(0)
        self.stderr.truncate(0)
        return captured


def parametrize(names, values, ids=None):
    if isinstance(names, str):
        names = tuple(name.strip() for name in names.split(","))
    else:
        names = tuple(names)

    def decorate(function):
        cases = []
        for value in values:
            if len(names) == 1:
                value = (value,)
            cases.append(dict(zip(names, value)))
        function.__unittest_parameters__ = cases
        function.__unittest_parameter_ids__ = tuple(ids) if ids else None
        return function

    return decorate


def raises(exception, match=None):
    case = unittest.TestCase()
    if match is None:
        return case.assertRaises(exception)
    return case.assertRaisesRegex(exception, match)


def load_test_functions(namespace, standard_tests):
    suite = unittest.TestSuite()
    suite.addTests(standard_tests)

    for name, function in sorted(namespace.items()):
        if not name.startswith("test_") or not inspect.isfunction(function):
            continue
        if function.__module__ != namespace["__name__"]:
            continue

        cases = getattr(function, "__unittest_parameters__", [{}])
        case_ids = getattr(function, "__unittest_parameter_ids__", None)
        for index, parameters in enumerate(cases):
            test_name = name
            if case_ids:
                test_name = "{}_{}".format(name, case_ids[index])
            elif len(cases) > 1:
                test_name = "{}_{}".format(name, index)

            def run(function=function, parameters=parameters):
                signature = inspect.signature(function)
                kwargs = dict(parameters)
                monkeypatch = None
                capture = None

                if "monkeypatch" in signature.parameters:
                    monkeypatch = MonkeyPatch()
                    kwargs["monkeypatch"] = monkeypatch
                if "capsys" in signature.parameters:
                    capture = Capture()
                    kwargs["capsys"] = capture
                try:
                    if capture is None:
                        function(**kwargs)
                    else:
                        with contextlib.redirect_stdout(capture.stdout):
                            with contextlib.redirect_stderr(capture.stderr):
                                function(**kwargs)
                finally:
                    if monkeypatch is not None:
                        monkeypatch.undo()

            run.__name__ = test_name
            suite.addTest(unittest.FunctionTestCase(run))

    return suite
