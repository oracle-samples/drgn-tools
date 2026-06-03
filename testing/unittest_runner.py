# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Run the drgn-tools unittest suite."""
import argparse
import sys
import time
import traceback
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict
from typing import List
from typing import Optional

import tests


class JUnitTestResult(unittest.TextTestResult):
    def __init__(self, stream, descriptions, verbosity):
        super().__init__(stream, descriptions, verbosity)
        self.records = []
        self._start_times = {}

    def startTest(self, test):
        self._start_times[test] = time.time()
        super().startTest(test)

    def _elapsed(self, test) -> float:
        return time.time() - self._start_times.pop(test, time.time())

    def _record(
        self, test, outcome: str, err=None, reason: Optional[str] = None
    ):
        message = reason or ""
        details = ""
        err_type = ""
        if err is not None:
            err_type = err[0].__name__
            message = str(err[1])
            # This is an internal implementation detail of unittest but
            # it is very useful to get this.
            details = self._exc_info_to_string(err, test)  # type: ignore
        self.records.append(
            {
                "id": test.id(),
                "outcome": outcome,
                "time": self._elapsed(test),
                "message": message,
                "details": details,
                "type": err_type,
            }
        )

    def addSuccess(self, test):
        super().addSuccess(test)
        self._record(test, "success")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._record(test, "failure", err=err)

    def addError(self, test, err):
        super().addError(test, err)
        self._record(test, "error", err=err)

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._record(test, "skipped", reason=reason)

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self._record(test, "skipped", err=err, reason="expected failure")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._record(test, "success")


class JUnitTextTestRunner(unittest.TextTestRunner):
    resultclass = JUnitTestResult


def _path_to_module(path: Path) -> str:
    if path.is_absolute():
        try:
            path = path.relative_to(Path.cwd())
        except ValueError as err:
            raise ValueError(
                "test file path must be under the current directory"
            ) from err
    if path.suffix == ".py":
        path = path.with_suffix("")
    return ".".join(path.parts)


def _build_suite(paths: List[str]) -> unittest.TestSuite:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    root = Path.cwd()

    if not paths:
        paths = ["tests"]

    for arg in paths:
        path = Path(arg)
        if path.is_dir():
            suite.addTests(
                loader.discover(
                    str(path),
                    pattern="test*.py",
                    top_level_dir=str(root),
                )
            )
        elif path.is_file():
            suite.addTests(loader.loadTestsFromName(_path_to_module(path)))
        else:
            suite.addTests(loader.loadTestsFromName(arg))
    return suite


def _split_test_id(test_id: str):
    parts = test_id.split(".")
    if len(parts) == 1:
        return "", parts[0]
    return ".".join(parts[:-1]), parts[-1]


def _subelement(parent, tag: str, attrib: Dict[str, str]):
    return ET.SubElement(parent, tag, {k: str(v) for k, v in attrib.items()})


def write_junit_xml(
    result: JUnitTestResult,
    path: Path,
    suite_name: str,
    properties: Dict[str, str],
) -> None:
    failures = sum(
        1 for record in result.records if record["outcome"] == "failure"
    )
    errors = sum(
        1 for record in result.records if record["outcome"] == "error"
    )
    skipped = sum(
        1 for record in result.records if record["outcome"] == "skipped"
    )
    elapsed = sum(record["time"] for record in result.records)

    root = ET.Element("testsuites")
    suite = _subelement(
        root,
        "testsuite",
        {
            "name": suite_name,
            "tests": str(len(result.records)),
            "failures": str(failures),
            "errors": str(errors),
            "skipped": str(skipped),
            "time": f"{elapsed:.6f}",
        },
    )
    if properties:
        props = ET.SubElement(suite, "properties")
        for name, value in sorted(properties.items()):
            _subelement(props, "property", {"name": name, "value": value})

    for record in result.records:
        classname, name = _split_test_id(record["id"])
        testcase = _subelement(
            suite,
            "testcase",
            {
                "classname": classname,
                "name": name,
                "time": f"{record['time']:.6f}",
            },
        )
        if record["outcome"] == "failure":
            failure = _subelement(
                testcase,
                "failure",
                {
                    "message": record["message"],
                    "type": record["type"] or "failure",
                },
            )
            failure.text = record["details"]
        elif record["outcome"] == "error":
            error = _subelement(
                testcase,
                "error",
                {
                    "message": record["message"],
                    "type": record["type"] or "error",
                },
            )
            error.text = record["details"]
        elif record["outcome"] == "skipped":
            skipped_elem = _subelement(
                testcase,
                "skipped",
                {"message": record["message"]},
            )
            skipped_elem.text = record["details"]

    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(
        str(path), encoding="utf-8", xml_declaration=True
    )


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run drgn-tools tests")
    parser.add_argument(
        "paths", nargs="*", help="test modules, files, or dirs"
    )
    parser.add_argument("--vmcore", default=None, help="Run tests for VMCORE")
    parser.add_argument(
        "--vmcore-dir",
        type=Path,
        default=None,
        help="Search for vmcores in DIR",
    )
    parser.add_argument(
        "--ctf",
        action="store_true",
        default=False,
        help="Use CTF data instead of DWARF",
    )
    parser.add_argument("--junitxml", type=Path, default=None)
    parser.add_argument(
        "-o", action="append", default=[], dest="compat_options"
    )
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("-q", "--quiet", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    if not __debug__:
        raise SystemExit(
            "error: drgn-tools tests use assert statements; do not run with -O"
        )

    args = _parse_args(sys.argv[1:] if argv is None else argv)
    tests.configure(
        vmcore=args.vmcore,
        vmcore_dir=args.vmcore_dir,
        ctf=args.ctf,
    )
    suite = _build_suite(args.paths)

    buffer = True
    verbosity = 2
    if args.quiet:
        verbosity = 0
    elif args.verbose:
        verbosity = 2
        buffer = False

    runner = JUnitTextTestRunner(verbosity=verbosity, buffer=buffer)
    try:
        result = runner.run(suite)
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)

    if args.junitxml is not None:
        write_junit_xml(
            result,  # type: ignore
            args.junitxml,
            tests.suite_name(),
            tests.suite_properties(),
        )
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
