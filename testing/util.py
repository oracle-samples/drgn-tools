# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

BASE_DIR = (Path(__file__).parent.parent / "testdata").absolute()
"""
Default directory where all testing data object should go. Should
be overridden on the CLI where necessary.
"""


def gitlab_section_start(
    name: str, text: str, collapsed: bool = False
) -> None:
    """
    Begin a section for gitlab CI output.
    """
    if collapsed:
        name += "[collapsed=true]"
    print(f"\x1b[0Ksection_start:{int(time.time())}:{name}\r\x1b[0K{text}")
    sys.stdout.flush()


def gitlab_section_end(name: str) -> None:
    """
    Close the section for gitlab CI output.
    """
    print(f"\x1b[0Ksection_end:{int(time.time())}:{name}\r\x1b[0K")
    sys.stdout.flush()


def github_section_start(
    name: str, text: str, collapsed: bool = False
) -> None:
    print(f"::group::{text}")


def github_section_end(name: str) -> None:
    print("::endgroup::")


if os.environ.get("GITHUB_ACTIONS"):
    ci_section_start = github_section_start
    ci_section_end = github_section_end
elif os.environ.get("GITLAB_CI"):
    ci_section_start = gitlab_section_start
    ci_section_end = gitlab_section_end
else:

    def ci_section_start(
        name: str, text: str, collapsed: bool = False
    ) -> None:
        pass

    def ci_section_end(name: str) -> None:
        pass


@contextmanager
def ci_section(
    name: str, text: str, collapsed: bool = False
) -> Generator[None, None, None]:
    ci_section_start(name, text, collapsed=collapsed)
    try:
        yield
    finally:
        ci_section_end(name)
