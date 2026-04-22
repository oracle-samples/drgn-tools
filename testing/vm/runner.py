# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""New VM test runner orchestration (initial implementation)."""
import argparse
import fnmatch
import shlex
import sys
from pathlib import Path
from typing import List

from testing.util import ci_section
from testing.vm.artifacts import ensure_kernel_artifacts
from testing.vm.config import default_paths
from testing.vm.config import TARGETS
from testing.vm.config import VmPaths
from testing.vm.config import VmTarget
from testing.vm.kmod import ensure_kmod
from testing.vm.rootfs import ensure_rootfs


def _select_targets(pattern: str = "*") -> List[VmTarget]:
    return [t for t in TARGETS if fnmatch.fnmatch(t.name, pattern)]


def _default_command() -> List[str]:
    return [sys.executable, "-m", "pytest", "tests"]


def _stub_test_execution(
    target: VmTarget, command: List[str], kmod_path: Path
) -> None:
    command_str = " ".join(shlex.quote(arg) for arg in command)
    print(
        "TODO: VM boot/test execution not implemented yet "
        f"for {target.name}; would run: {command_str}; "
        f"module: {kmod_path}"
    )


def _parse_args() -> argparse.Namespace:
    defaults = default_paths()

    parser = argparse.ArgumentParser(description="testing.vm runner")
    parser.add_argument(
        "--kernel",
        default="*",
        help="Match against target slug (example: ol9-uek8-*)",
    )
    parser.add_argument(
        "--extract-dir",
        type=Path,
        default=defaults.extract_dir,
        help="Directory for extracted kernel RPMs",
    )
    parser.add_argument(
        "--yum-cache-dir",
        type=Path,
        default=defaults.yum_cache_dir,
        help="Directory for YUM metadata and RPM cache",
    )
    parser.add_argument(
        "--rootfs-dir",
        type=Path,
        default=defaults.rootfs_dir,
        help="Directory containing OL rootfs chroots",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=defaults.work_dir,
        help="Directory for VM work artifacts",
    )
    parser.add_argument(
        "--skip-rootfs-build",
        action="store_true",
        help="Do not build rootfs (requires it to already exist)",
    )
    parser.add_argument(
        "--skip-rpm-fetch",
        action="store_true",
        help="Do not fetch/extract kernel RPMs (requires existing extract dir)",
    )
    parser.add_argument(
        "--skip-kmod-build",
        action="store_true",
        help="Do not build kernel module (requires existing .ko output)",
    )
    parser.add_argument(
        "command",
        nargs="*",
        help="Command to run in-guest once VM execution is implemented",
    )
    return parser.parse_args()


def _paths_from_args(args: argparse.Namespace) -> VmPaths:
    return VmPaths(
        extract_dir=args.extract_dir,
        yum_cache_dir=args.yum_cache_dir,
        rootfs_dir=args.rootfs_dir,
        work_dir=args.work_dir,
    )


def main() -> None:
    args = _parse_args()
    paths = _paths_from_args(args)

    command = args.command if args.command else _default_command()
    targets = _select_targets(args.kernel)
    if not targets:
        raise SystemExit(f"No targets matched --kernel {args.kernel!r}")

    repo_root = Path.cwd().absolute()

    for target in targets:
        with ci_section(
            f"{target.name}_rootfs",
            f"Build rootfs for {target.name}",
        ):
            rootfs = ensure_rootfs(
                target.ol_ver,
                paths.rootfs_dir,
                skip_build=args.skip_rootfs_build,
            )

        with ci_section(
            f"{target.name}_kernel",
            f"Download/extract kernel RPMs for {target.name}",
        ):
            artifacts = ensure_kernel_artifacts(
                target.kernel,
                paths.extract_dir,
                paths.yum_cache_dir,
                skip_fetch=args.skip_rpm_fetch,
            )

        with ci_section(
            f"{target.name}_kmod",
            f"Build test kernel module for {target.name}",
        ):
            kmod_path = ensure_kmod(
                rootfs,
                target,
                artifacts.release,
                repo_root,
                paths.extract_dir,
                paths.kmod_dir,
                skip_build=args.skip_kmod_build,
            )
            print(f"Built module: {kmod_path}")

        with ci_section(
            f"{target.name}_run",
            f"Run tests for {target.name}",
        ):
            _stub_test_execution(target, command, kmod_path)


if __name__ == "__main__":
    main()
