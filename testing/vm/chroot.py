# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Chroot execution helpers for testing.vm."""
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

    mount_targets.append(Path("/proc"))
    lines.append(f"mount -t proc proc {_rootfs_mount_target(rootfs, '/proc')}")

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
