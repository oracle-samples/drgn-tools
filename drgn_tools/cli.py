# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
The drgn_tools CLI entry point.

This is not intended to be anything "wild & crazy". It is just the normal drgn
REPL, but with helpers to automatically find the vmlinux and modules.
"""
import argparse
import importlib
import logging
import os
import sys
from typing import Any
from typing import Dict

import drgn
from drgn import Program

from drgn_tools.corelens import make_runner
from drgn_tools.debuginfo import drgn_prog_set as register_debug_info_finders
from drgn_tools.debuginfo import update_debug_info_policy
from drgn_tools.module import get_module_load_summary

try:
    from drgn_tools._version import __version__
except ImportError:
    __version__ = "UNKNOWN"  # uncommon, but guard against it

from drgn.cli import run_interactive
from drgn.cli import version_header


try:
    from drgn.helpers.linux.ctf import load_ctf  # noqa

    HAVE_CTF = True
except (ImportError, ModuleNotFoundError):
    HAVE_CTF = False


CLI_HELPERS = {
    "drgn_tools.bt": ["bt"],
    "drgn_tools.printk": ["dmesg"],
    "drgn_tools.module": [
        "KernelModule",
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
            "extract the debuginfo for all loaded modules (requires "
            "a vmlinux repository, implies --dwarf)"
        ),
    )
    parser.add_argument(
        "--ctf",
        "-C",
        action="store_true",
        help="force the use of CTF",
    )
    parser.add_argument(
        "--ctf-file",
        help="specify a CTF file to use (implies --ctf)",
    )
    parser.add_argument(
        "--dwarf",
        "-D",
        action="store_true",
        help="force the use of DWARF debuginfo",
    )
    args = parser.parse_args()

    # Set the implied arguments
    if args.ctf_file:
        args.ctf = True
    if args.extract_modules:
        args.dwarf = True

    if args.ctf and args.dwarf:
        sys.exit("error: --dwarf and --ctf conflict, use only one")

    logging.basicConfig()
    drgnlog = logging.getLogger("drgn")
    drgnlog.setLevel(logging.INFO)

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

    # Normally, drgn-tools is installed in such a way that
    # "drgn_tools.debuginfo" is registered as a drgn plugin, so that the debug
    # info finders are automatically registered. However, when run from a git
    # checkout, or if drgn-tools was not installed properly, the hook may not
    # run. Manually check that the finders are registered before continuing.
    if "drgn_tools.debuginfo.options" not in prog.cache:
        register_debug_info_finders(prog)

    # Instruct the debuginfo finders based on the CLI arguments
    update_debug_info_policy(
        prog,
        dwarf_only=args.dwarf,
        ctf_only=args.ctf,
        ctf_file=args.ctf_file,
    )

    try:
        old_level = drgnlog.getEffectiveLevel()
        drgnlog.setLevel(logging.ERROR)
        prog.load_default_debug_info()
    except drgn.MissingDebugInfoError:
        if prog.main_module().wants_debug_file():
            sys.exit("error: unable to find vmlinux debuginfo")
    finally:
        drgnlog.setLevel(old_level)
    db_kind = "CTF" if prog.cache.get("using_ctf") else "DWARF"

    def banner_func(banner: str) -> str:
        header = version_header()
        ctf_blurb = ", with CTF)" if HAVE_CTF else ", without CTF)"
        header = header[:-1] + ctf_blurb
        imports = "\n"
        for mod_name, names in CLI_HELPERS.items():
            imports += f">>> from {mod_name} import {', '.join(names)}\n"
        db_info = f"Using {db_kind}"
        if db_kind == "DWARF":
            db_info += "\n" + str(get_module_load_summary(prog))
        return (
            header
            + "\n"
            + banner
            + imports
            + f"\nWelcome to Oracle drgn-tools v{__version__}!\n"
            + db_info
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
