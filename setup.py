# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import os.path
import re
import shutil
import subprocess

from setuptools import setup

long_description = "drgn helper script repository"

RELEASE_VERSION = "0.5.1"


def get_version():
    try:
        with open("drgn_tools/_version.py", "r") as f:
            version_py = f.read()
    except FileNotFoundError:
        version_py = None

    public_version = RELEASE_VERSION
    local_version = "+unknown"

    # If this is a git repository, use a git-describe(1)-esque local version.
    # Otherwise, get the local version saved in the sdist.
    if os.path.exists(".git") and shutil.which("git"):
        try:
            dirty = bool(
                subprocess.check_output(
                    ["git", "status", "-uno", "--porcelain"],
                    # Use the environment variable instead of --no-optional-locks
                    # to support Git < 2.14.
                    env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
                )
            )
        except subprocess.CalledProcessError:
            dirty = False

        try:
            count = int(
                subprocess.check_output(
                    ["git", "rev-list", "--count", f"v{public_version}.."],
                    stderr=subprocess.DEVNULL,
                    universal_newlines=True,
                )
            )
        except subprocess.CalledProcessError:
            print(f"warning: v{public_version} tag not found")
        else:
            if count == 0:
                local_version = "+dirty" if dirty else ""
            else:
                commit = subprocess.check_output(
                    ["git", "rev-parse", "--short", "HEAD"],
                    universal_newlines=True,
                ).strip()
                local_version = f"+{count}.g{commit}"
                if dirty:
                    local_version += ".dirty"
    elif version_py is not None:
        match = re.search(
            rf'^__version__ = "{re.escape(public_version)}([^"]*)"$',
            version_py,
            re.M,
        )
        if match:
            local_version = match.group(1)
        else:
            print("warning: drgn_tools/_version.py is invalid")
    else:
        print("warning: drgn_tools/_version.py not found")

    version = public_version + local_version

    new_version_py = f'__version__ = "{version}"\n'
    if new_version_py != version_py:
        with open("drgn_tools/_version.py", "w") as f:
            f.write(new_version_py)

    return version


setup(
    name="drgn-tools",
    version=get_version(),
    description="drgn helper script repository",
    long_description=long_description,
    install_requires=[
        "drgn>=0.0.24",
    ],
    url="https://github.com/oracle-samples/drgn-tools",
    author="Oracle Linux Sustaining Engineering Team",
    author_email="stephen.s.brennan@oracle.com",
    license="UPL",
    packages=["drgn_tools"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Universal Permissive License (UPL)",
    ],
    keywords="kernel UEK debug",
    entry_points={
        "console_scripts": [
            "DRGN=drgn_tools.cli:main",
            "corelens=drgn_tools.corelens:main",
        ],
    },
)
