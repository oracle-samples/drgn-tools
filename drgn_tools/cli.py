# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
The drgn_tools CLI entry point.

This is not intended to be anything "wild & crazy". It is just the normal drgn
REPL, but with helpers to automatically find the vmlinux and modules.
"""
import argparse
import importlib
import os
import sys
from typing import Any
from typing import Dict

from drgn import Program

from drgn_tools.corelens import make_runner
from drgn_tools.debuginfo import fetch_debuginfo
from drgn_tools.debuginfo import find_debuginfo
from drgn_tools.module import get_module_load_summary
from drgn_tools.module import load_module_debuginfo

try:
    from drgn_tools._version import __version__
except ImportError:
    __version__ = "UNKNOWN"  # uncommon, but guard against it

from drgn.cli import run_interactive
from drgn.cli import version_header


CLI_HELPERS = {
    "drgn_tools.bt": ["bt"],
    "drgn_tools.printk": ["dmesg"],
    "drgn_tools.module": [
        "KernelModule",
        "for_each_module",
        "find_module",
        "load_module_debuginfo",
    ],
    "drgn_tools.util": ["redirect_stdout"],
}


def main() -> None:
    parser = argparse.ArgumentParser(description="drgn wrapper")
    parser.add_argument("vmcore", help="vmcore to open")
    parser.add_argument(
        "--extract-modules",
        "-x",
        action="store_true",
        help=(
            "extract the debuginfo for all loaded moudles (requires "
            "a vmlinux repository)"
        ),
    )
    args = parser.parse_args()

    prog = Program()
    try:
        prog.set_core_dump(args.vmcore)
    except PermissionError:
        if args.vmcore == "/proc/kcore":
            try:
                from drgn.internal.sudohelper import open_via_sudo

                prog.set_core_dump(open_via_sudo(args.vmcore, os.O_RDONLY))
            except ImportError:
                sys.exit("error: no permission to open /proc/kcore")

    release = prog["UTS_RELEASE"].string_().decode("ascii")
    print(f"Detected version: {release}")

    vmlinux = find_debuginfo(prog, "vmlinux")
    if not vmlinux:
        print("vmlinux not found, trying to fetch")
        fetched = fetch_debuginfo(release, ["vmlinux"])
        if not fetched:
            print("error: could not find vmlinux")
            sys.exit(1)
        vmlinux = fetched["vmlinux"]
    if not vmlinux:
        print("error: vmlinux not found, and no failed to fetch it")
        sys.exit(1)

    print(f"Using {str(vmlinux)}")
    prog.load_debug_info([vmlinux])
    more = "\n"

    load_module_debuginfo(prog, extract=args.extract_modules, quiet=True)

    def banner_func(banner: str) -> str:
        header = version_header()
        imports = "\n"
        for mod_name, names in CLI_HELPERS.items():
            imports += f">>> from {mod_name} import {', '.join(names)}\n"
        return (
            header
            + "\n"
            + banner
            + imports
            + (f"{more}" f"Welcome to Oracle drgn-tools v{__version__}!\n")
            + str(get_module_load_summary(prog))
            + "\n"
        )

    def globals_func(globals_: Dict[str, Any]) -> Dict[str, Any]:
        for mod_name, names in CLI_HELPERS.items():
            mod = importlib.import_module(mod_name)
            for name in names:
                globals_[name] = getattr(mod, name)
        globals_["cl"] = make_runner(prog)
        return globals_

    run_interactive(
        prog,
        banner_func=banner_func,
        globals_func=globals_func,
    )


if __name__ == "__main__":
    main()
