# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Create a zipapp distribution of drgn-tools which can provided to customers.
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
import zipapp
from pathlib import Path


def main():
    entry_points = {
        "corelens": "drgn_tools.corelens:main",
        "cli": "drgn_tools.cli:main",
    }
    parser = argparse.ArgumentParser(
        description="create drgn-tools distributions"
    )
    parser.add_argument(
        "--interpreter",
        default="/usr/bin/python3",
        help="Set the interpreter (if different from target system python)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Set the output file",
    )
    parser.add_argument(
        "--entry-point",
        default="corelens",
        help=f"Select an entry point ({','.join(entry_points.keys())} "
        "or a function name)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="just do it without any prompts or info",
    )
    args = parser.parse_args()

    print(
        """\
Please note: the contents of the drgn_tools/ directory will be used to create
this distribution AS-IS! If you have any contents in that directory which should
not be distributed to a customer, please Ctrl-C now and clean them up. You may
want to use:

    git clean -ndx drgn_tools/

To see if you have any untracked files. You can use:

    git clean -fdx drgn_tools/

To delete everything listed by the prior command. Finally, you can use:

    git status drgn_tools/

To verify which files have uncommitted changes. It's totally fine to include
extra files & uncommitted changes, but it's important to be sure you only
include what you intended.

Please hit enter to acknowledge and continue, or Ctrl-C to abort.\
"""
    )
    input()
    base_dir = Path(__file__).parent
    if args.entry_point in entry_points:
        output_file = args.output or f"{args.entry_point}.pyz"
        entry_point = entry_points[args.entry_point]
    else:
        output_file = args.output or "drgn_tools.pyz"
        entry_point = args.entry_point

    # Be sure that we re-generate the "_version.py" file for accuracy
    subprocess.run(
        [sys.executable, base_dir / "setup.py", "--version"],
        check=True,
        stdout=subprocess.DEVNULL,
        cwd=base_dir,
    )

    # Only the contents of "drgn_tools" should be included. All other files that
    # are part of the project should be excluded.
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        shutil.copytree(base_dir / "drgn_tools", tmp / "drgn_tools")
        zipapp.create_archive(
            td, output_file, interpreter=args.interpreter, main=entry_point
        )

    print(
        f"""\
Created a distribution: {output_file}

It can be directly copied to a target system, and it can be directly executed.
The target system MUST have a /usr/bin/python3 and have drgn installed. The
target system DOES NOT need to have drgn-tools installed -- but if it does, that
is fine. Nothing on the target system will be modified.

You can use "unzip -l {output_file}" to check the contents of the zip file to
ensure only what you intended to include is present.\
"""
    )


if __name__ == "__main__":
    main()
