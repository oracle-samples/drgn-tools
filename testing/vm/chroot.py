# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Chroot execution helpers for testing.vm."""
import argparse
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass(frozen=True)
class BindMount:
    source: Path
    destination: str
    readonly: bool = False


def _rootfs_mount_target(rootfs: Path, destination: str) -> Path:
    if not destination.startswith("/"):
        raise ValueError(
            f"Destination must be an absolute path: {destination}"
        )
    return rootfs / destination.lstrip("/")


def run_in_chroot(rootfs: Path, command: str, binds: List[BindMount]) -> None:
    lines = ["set -euo pipefail"]
    mount_targets = []

    for bind in binds:
        target = _rootfs_mount_target(rootfs, bind.destination)
        mount_targets.append(target)
        source = bind.source.absolute()
        lines.append(f"mkdir -p {shlex.quote(str(target))}")
        lines.append(
            "mount --bind "
            f"{shlex.quote(str(source))} {shlex.quote(str(target))}"
        )
        if bind.readonly:
            lines.append(
                "mount -o remount,ro,bind " f"{shlex.quote(str(target))}"
            )

    proc_target = _rootfs_mount_target(rootfs, "/proc")
    lines.append(f"mkdir -p {shlex.quote(str(proc_target))}")
    mount_targets.append(proc_target)
    lines.append(f"mount -t proc proc {shlex.quote(str(proc_target))}")

    lines.append("cleanup() {")
    lines.append("  status=$?")
    for target in reversed(mount_targets):
        lines.append(f"  umount -l {shlex.quote(str(target))} || true")
    lines.append("  exit $status")
    lines.append("}")
    lines.append("trap cleanup EXIT")
    lines.append(
        "chroot "
        f"{shlex.quote(str(rootfs))} /bin/bash -lc {shlex.quote(command)}"
    )

    script = "\n".join(lines)
    subprocess.run(
        [
            "unshare",
            "--mount",
            "--user",
            "--map-root-user",
            "--fork",
            "--pid",
            "/bin/bash",
            "-lc",
            script,
        ],
        check=True,
    )


def _parse_bind(spec: str, readonly: bool) -> BindMount:
    if ":" not in spec:
        raise ValueError(
            f"Invalid bind mount {spec!r}; expected SRC:DST format"
        )
    source_str, destination = spec.split(":", 1)
    if not source_str:
        raise ValueError(f"Bind mount source path is empty: {spec!r}")
    if not destination:
        raise ValueError(f"Bind mount destination path is empty: {spec!r}")
    return BindMount(Path(source_str), destination, readonly=readonly)


def _command_to_shell(command: List[str]) -> str:
    if not command:
        return "/bin/bash"
    if command[0] == "--":
        command = command[1:]
    if not command:
        return "/bin/bash"
    return " ".join(shlex.quote(arg) for arg in command)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run command in OL chroot")
    parser.add_argument(
        "rootfs",
        type=Path,
        help="Rootfs directory to chroot into",
    )
    parser.add_argument(
        "--bind",
        action="append",
        default=[],
        metavar="SRC:DST",
        help="Bind mount host SRC to chroot DST (read-write)",
    )
    parser.add_argument(
        "--ro-bind",
        action="append",
        default=[],
        metavar="SRC:DST",
        help="Bind mount host SRC to chroot DST (read-only)",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to execute in chroot",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if not args.rootfs.is_dir():
        raise SystemExit(f"Rootfs does not exist: {args.rootfs}")

    binds = []
    try:
        for spec in args.bind:
            binds.append(_parse_bind(spec, readonly=False))
        for spec in args.ro_bind:
            binds.append(_parse_bind(spec, readonly=True))
    except ValueError as e:
        raise SystemExit(str(e)) from e

    run_in_chroot(
        args.rootfs.absolute(),
        _command_to_shell(args.command),
        binds=binds,
    )


if __name__ == "__main__":
    main()
