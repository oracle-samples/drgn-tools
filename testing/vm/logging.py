# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Logging helpers for testing.vm."""
import os
from pathlib import Path


def default_verbose() -> bool:
    return any(
        os.environ.get(name) for name in ("CI", "GITHUB_ACTIONS", "GITLAB_CI")
    )


class VmLogger:
    def __init__(self, verbose: bool, interactive: bool) -> None:
        self.verbose = verbose
        self.interactive = interactive

    def begin_target(self, target: str) -> None:
        if self.verbose:
            print(f"Beginning build & test for {target}...")

    def begin_test(self, target: str, mode: str, fs_mode: str) -> None:
        print(f"Running {mode} tests for {target} using {fs_mode}...")

    def skip_test(self, target: str, mode: str, reason: str) -> None:
        print(f"Skipping {mode} tests for {target}: {reason}")

    def fail_test(self, target: str, mode: str) -> None:
        print(f"FAILED: {target} {mode}")

    def pass_test(self, target: str, mode: str) -> None:
        print(f"PASS: {target} {mode}")

    def already_done(self, kind: str, path: Path) -> None:
        if self.verbose:
            print(f"Already done: {kind}: {path}", flush=True)

    def working(self, kind: str, path: Path) -> None:
        # This should be printed even when non-verbose, otherwise users
        # tend to get testy about why it's taking so long.
        print(f"Working : {kind}: {path}...", flush=True)

    def done(self, kind: str, path: Path) -> None:
        print(f"Complete: {kind}: {path}", flush=True)

    def message(self, text: str, verbose_only: bool = False) -> None:
        if self.verbose or not verbose_only:
            print(text, flush=True)
