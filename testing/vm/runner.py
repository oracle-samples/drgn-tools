# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""VM test runner."""
import argparse
import fnmatch
import shutil
import sys
import traceback
from collections import defaultdict
from concurrent.futures import FIRST_COMPLETED
from concurrent.futures import Future
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Set
from typing import Union

from testing.config import APPSTREAM_PYTHONS
from testing.config import Debuginfo
from testing.config import KernelCategory
from testing.config import KernelKind
from testing.config import KernelVer
from testing.config import PythonVer
from testing.config import REPO_ROOT
from testing.config import Rootfs
from testing.config import TARGETS
from testing.config import TestDirectories
from testing.rootfs import ensure_rootfs
from testing.util import ci_section
from testing.vm.artifacts import ensure_kernel
from testing.vm.boot import run_in_vm
from testing.vm.kmod import ensure_kmod
from testing.vm.logging import default_verbose
from testing.vm.logging import VmLogger


def _select_targets(pattern: str = "*") -> List[KernelCategory]:
    return [t for t in TARGETS if fnmatch.fnmatch(t.name, pattern)]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="testing.vm runner")
    parser.add_argument(
        "--kernel",
        "-k",
        default="*",
        help="Match against target slug (example: ol9-uek8-*)",
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=None,
        help="Base directory for cached and generated test artifacts",
    )
    parser.add_argument(
        "--skip-rootfs-build",
        action="store_true",
        help="Do not build rootfs (requires it to already exist)",
    )
    parser.add_argument(
        "--skip-rpm-fetch",
        action="store_true",
        help=(
            "Do not download repodata or RPMs "
            "(requires cached metadata/RPMs)"
        ),
    )
    parser.add_argument(
        "--skip-kmod-build",
        action="store_true",
        help="Do not build kernel module (requires existing .ko output)",
    )
    parser.add_argument(
        "--skip-all",
        "-n",
        action="store_true",
        help=(
            "Activate all --skip-* options "
            "(requires everything already built)"
        ),
    )
    parser.add_argument(
        "--no-ctf",
        dest="ctf",
        action="store_false",
        help="Skip CTF mode",
    )
    parser.add_argument(
        "--no-dwarf",
        dest="dwarf",
        action="store_false",
        help="Skip DWARF mode",
    )
    parser.add_argument(
        "--parallel",
        "-j",
        type=int,
        default=1,
        help="Parallelism to run tests",
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Connect stdout/stdin of the VM to the terminal (conflicts with -j)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=default_verbose(),
        help="Print output from builds & increase kernel log level",
    )
    parser.add_argument(
        "--delete-after-test",
        action="store_true",
        help=(
            "Delete downloaded & extracted RPMs after all tests for the "
            "target are complete. This reduces the disk space used by the "
            "tests, but it is only useful with -j 1 which guarantees that "
            "we run the tests sequentially."
        ),
    )
    parser.add_argument(
        "--python",
        type=PythonVer,
        default=PythonVer.SYSTEM,
        help="Python version for running tests (default: system python)",
    )
    parser.add_argument(
        "--all-python-versions",
        action="store_true",
        help="Run tests against all python versions (overrides --python)",
    )
    parser.add_argument(
        "test_args",
        nargs="*",
        help="Arguments to test through to unittest_runner",
    )

    args = parser.parse_args()
    if not args.dwarf and not args.ctf:
        raise SystemExit(
            "Both --no-dwarf and --no-ctf were set, nothing to run"
        )
    if args.skip_all:
        args.skip_rootfs_build = True
        args.skip_rpm_fetch = True
        args.skip_kmod_build = True
    if args.interactive and args.parallel > 1:
        raise SystemExit(
            f"--interactive cannot be used with -j {args.parallel}"
        )
    return args


class TestParam(NamedTuple):
    mode: Debuginfo
    python: PythonVer
    test_args: List[str]


class TestResult(NamedTuple):
    kernel: KernelCategory
    param: TestParam
    status: str
    exception: Optional[Exception]


class SetupError(NamedTuple):
    input: Union[Rootfs, KernelCategory]
    exception: Exception


TaskRes = Union[Rootfs, KernelVer, TestResult, SetupError]


class VmTest:
    rootfs_to_targets: Dict[Rootfs, List[KernelCategory]]
    target_to_params: Dict[KernelCategory, List[TestParam]]
    layout: TestDirectories
    log: VmLogger
    threads: int
    skip_rootfs_build: bool
    skip_rpm_fetch: bool
    skip_kmod_build: bool
    delete_after_test: bool
    thread_pool: Optional[ThreadPoolExecutor]
    futures: Set["Future[TaskRes]"]
    complete: Set["Future[TaskRes]"]
    pending: List[Any]

    def __init__(
        self,
        rootfs_to_targets: Dict[Rootfs, List[KernelCategory]],
        target_to_params: Dict[KernelCategory, List[TestParam]],
        layout: TestDirectories,
        log: VmLogger,
        threads: int,
        skip_rootfs_build: bool = False,
        skip_rpm_fetch: bool = False,
        skip_kmod_build: bool = False,
        delete_after_test: bool = False,
    ):
        self.rootfs_to_targets = rootfs_to_targets
        self.target_to_params = target_to_params
        self.layout = layout
        self.log = log
        self.threads = threads
        self.skip_rootfs_build = skip_rootfs_build
        self.skip_rpm_fetch = skip_rpm_fetch
        self.skip_kmod_build = skip_kmod_build
        self.delete_after_test = delete_after_test
        if threads == 1:
            self.pending = []
            self.thread_pool = None
        else:
            self.futures = set()
            self.complete = set()
            self.thread_pool = ThreadPoolExecutor(max_workers=threads)

    def ensure_rootfs(self, rootfs: Rootfs) -> TaskRes:
        try:
            with ci_section(
                f"{rootfs.name}_setup", f"Set up rootfs {rootfs.name}"
            ):
                ensure_rootfs(
                    rootfs,
                    self.layout,
                    self.log,
                    skip_build=self.skip_rootfs_build,
                )
            return rootfs
        except Exception as e:
            return SetupError(rootfs, e)

    def ensure_target(self, target: KernelCategory) -> TaskRes:
        try:
            with ci_section(
                f"{target.name}_setup", f"Set up kernel {target.name}"
            ):
                kernel = ensure_kernel(
                    target,
                    self.layout,
                    self.log,
                    skip_fetch=self.skip_rpm_fetch,
                )
                ensure_kmod(
                    kernel,
                    REPO_ROOT,
                    self.layout,
                    self.log,
                    skip_build=self.skip_kmod_build,
                )
            return kernel
        except Exception as e:
            return SetupError(target, e)

    def run_test(self, kernel: KernelVer, param: TestParam) -> TaskRes:
        target = kernel.category
        mode = param.mode
        python = param.python
        with ci_section(
            f"{target.name}_{mode.value}",
            f"Run {mode.value.upper()} tests for {target.name}",
        ):
            ctf = mode == Debuginfo.CTF
            if kernel.category.kind == KernelKind.RHCK and ctf:
                self.log.skip_test(
                    target.name, mode, python, "CTF unsupported"
                )
                return TestResult(target, param, "skip", None)
            self.log.begin_test(target.name, mode, python, target.shared_fs)
            log_path = self.layout.vm_log_path(
                kernel.category, mode, param.python
            )
            log_path.parent.mkdir(exist_ok=True, parents=True)
            command = [
                python.value,
                "-m",
                "testing.unittest_runner",
                *param.test_args,
            ]
            if ctf:
                command.append("--ctf")
            try:
                run_in_vm(
                    kernel,
                    self.layout,
                    REPO_ROOT,
                    command,
                    None if self.log.interactive else log_path,
                    self.log,
                )
            except RuntimeError as e:
                self.log.fail_test(target.name, mode, python)
                return TestResult(target, param, "fail", e)
            else:
                self.log.pass_test(target.name, mode, python)
                return TestResult(target, param, "pass", None)

    def submit(self, task, *args) -> None:
        if self.thread_pool:
            self.futures.add(self.thread_pool.submit(task, *args))
        else:
            self.pending.append((task, args))

    def should_continue(self) -> bool:
        if self.thread_pool:
            return bool(self.complete) or bool(self.futures)
        else:
            return bool(self.pending)

    def next_result(self) -> TaskRes:
        if self.thread_pool:
            if self.complete:
                return self.complete.pop().result()
            else:
                self.complete, self.futures = wait(
                    self.futures, return_when=FIRST_COMPLETED
                )
                return self.complete.pop().result()
        else:
            task, args = self.pending.pop()
            return task(*args)

    def __enter__(self) -> None:
        if self.thread_pool:
            self.thread_pool.__enter__()

    def __exit__(self, *args) -> None:
        if self.thread_pool:
            # If there are any futures, we're exiting in error
            for future in self.futures:
                future.cancel()
            self.thread_pool.__exit__(*args)

    def maybe_delete(self, res: TestResult) -> None:
        if not self.delete_after_test:
            return
        if not hasattr(self, "by_kernel"):
            self.by_kernel: Dict[KernelCategory, int] = defaultdict(int)
        cat = res.kernel
        self.by_kernel[cat] += 1
        if self.by_kernel[cat] < len(self.target_to_params[cat]):
            return
        self.log.message("Deleting RPM cache and extraction directory")
        shutil.rmtree(self.layout.target_path(cat))

    def account_error(
        self, res: SetupError, results: List[TestResult]
    ) -> None:
        if isinstance(res.input, Rootfs):
            targets = self.rootfs_to_targets[res.input]
        elif isinstance(res.input, KernelCategory):
            targets = [res.input]
        else:
            assert False  # unreachable
        # propagate setup errors to the eventual targets
        for target in targets:
            for params in self.target_to_params[target]:
                results.append(
                    TestResult(target, params, "error", res.exception)
                )

    def run(self) -> List[TestResult]:
        results = []
        for rootfs in self.rootfs_to_targets.keys():
            self.submit(self.ensure_rootfs, rootfs)

        while self.should_continue():
            res = self.next_result()
            if isinstance(res, Rootfs):
                for target in self.rootfs_to_targets[res]:
                    self.submit(self.ensure_target, target)
            elif isinstance(res, KernelVer):
                for param in self.target_to_params[res.category]:
                    self.submit(self.run_test, res, param)
            elif isinstance(res, TestResult):
                results.append(res)
                self.maybe_delete(res)
            elif isinstance(res, SetupError):
                self.account_error(res, results)
            else:
                assert False  # unreachable

        return results


def main() -> None:
    args = _parse_args()
    layout = TestDirectories.create(args.base_dir)
    log = VmLogger(args.verbose, args.interactive)
    targets = _select_targets(args.kernel)
    if not targets:
        raise SystemExit(f"No targets matched --kernel {args.kernel!r}")

    modes = []
    if args.dwarf:
        modes.append(Debuginfo.DWARF)
    if args.ctf:
        modes.append(Debuginfo.CTF)

    rootfs_to_targets: Dict[Rootfs, List[KernelCategory]] = {}
    target_to_params = {}
    for target in targets:
        rootfs_to_targets.setdefault(target.rootfs, []).append(target)
        if args.all_python_versions:
            pythons = [PythonVer.SYSTEM] + list(
                APPSTREAM_PYTHONS[target.ol_ver]
            )
            target_to_params[target] = [
                TestParam(mode, pyver, args.test_args)
                for pyver in pythons
                for mode in modes
            ]
        else:
            target_to_params[target] = [
                TestParam(mode, args.python, args.test_args) for mode in modes
            ]

    runner = VmTest(
        rootfs_to_targets,
        target_to_params,
        layout,
        log,
        args.parallel,
        skip_rootfs_build=args.skip_rootfs_build,
        skip_rpm_fetch=args.skip_rpm_fetch,
        skip_kmod_build=args.skip_kmod_build,
        delete_after_test=args.delete_after_test,
    )
    results = runner.run()
    skipped = [r for r in results if r.status == "skip"]
    if skipped:
        print("Skipped:")
        for result in skipped:
            print(
                "- {} ({}, {}): {}".format(
                    result.kernel.name,
                    result.param.mode.value,
                    result.param.python.value,
                    result.status,
                )
            )
    failed = [r for r in results if r.status in ("fail", "error")]
    if failed:
        print("VM test failures:")
        for result in failed:
            print(
                "- {} ({}, {}): {}".format(
                    result.kernel.name,
                    result.param.mode.value,
                    result.param.python.value,
                    result.status,
                )
            )
            if result.exception:
                fmt = "".join(
                    traceback.format_exception_only(
                        type(result.exception), result.exception
                    )
                ).strip()
                print(f"  {fmt}")
        sys.exit(1)


if __name__ == "__main__":
    main()
