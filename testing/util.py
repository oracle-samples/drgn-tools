# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
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


@contextmanager
def gitlab_section(
    name: str,
    text: str,
    collapsed: bool = False,
) -> Generator[None, None, None]:
    """
    Return a context manager that starts a section on entry, and ends it on
    exit.
    """
    gitlab_section_start(name, text, collapsed=collapsed)
    try:
        yield
    finally:
        gitlab_section_end(name)
