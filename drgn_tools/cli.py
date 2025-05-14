# Copyright (c) 2024, Oracle and/or its affiliates.
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
from pathlib import Path
from typing import Any
from typing import Dict
from typing import Optional
from typing import Tuple

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
        "load_module_debuginfo",
    ],
    "drgn_tools.util": ["redirect_stdout"],
}


def _get_ctf_path(release: str, args: argparse.Namespace) -> Optional[str]:
    if args.ctf_file and os.path.isfile(args.ctf_file):
        return args.ctf_file
    default = f"/lib/modules/{release}/kernel/vmlinux.ctfa"
    if os.path.isfile(default):
        return default
    by_vmcore = Path(args.vmcore).parent / "vmlinux.ctfa"
    if by_vmcore.is_file():
        return str(by_vmcore)
    return None


def _set_debuginfo(
    prog: Program, release: str, args: argparse.Namespace
) -> Tuple[str, str]:
    problems = [f"Kernel version: {release}"]

    # First try to find DWARF on the system (unless we're forcing CTF). If
    # found, continue to loading modules: we're committed to DWARF. If not, try
    # CTF before fetching DWARF debuginfo.
    if not args.ctf:
        vmlinux = find_debuginfo(prog, "vmlinux")
        if vmlinux:
            prog.load_debug_info([vmlinux])
            load_module_debuginfo(
                prog, extract=args.extract_modules, quiet=True
            )
            return "DWARF", str(vmlinux)
        else:
            problems.append("DWARF debuginfo not found for vmlinux")

    # Try CTF so long as we're not forcing DWARF.
    if not args.dwarf:
        ctf_path = _get_ctf_path(release, args)
        if ctf_path and HAVE_CTF:
            load_ctf(prog, ctf_path)
            prog.cache["using_ctf"] = True
            return "CTF", ctf_path
        elif ctf_path:
            problems.append(
                "CTF found, but drgn is not built with CTF support"
            )
        elif not HAVE_CTF:
            problems.append(
                "CTF debuginfo is not found, and drgn has no CTF support"
            )
        else:
            problems.append("CTF debuginfo was not found")

    # Now try to fetch DWARF via a fetcher.
    if not args.ctf:
        print("Fetching debuginfo...")
        fetched = fetch_debuginfo(release, ["vmlinux"])
        if fetched and "vmlinux" in fetched:
            vmlinux = fetched["vmlinux"]
            prog.load_debug_info([vmlinux])
            load_module_debuginfo(
                prog, extract=args.extract_modules, quiet=True
            )
            return "DWARF", str(vmlinux)
        else:
            problems.append("DWARF debuginfo could not be fetched")

    # Nothing worked, sorry!
    problem_str = "\n".join(problems)
    sys.exit(f"error: failed to find debuginfo:\n{problem_str}")


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
    db_kind, db_file = _set_debuginfo(prog, release, args)

    def banner_func(banner: str) -> str:
        header = version_header()
        ctf_blurb = ", with CTF)" if HAVE_CTF else ", without CTF)"
        header = header[:-1] + ctf_blurb
        imports = "\n"
        for mod_name, names in CLI_HELPERS.items():
            imports += f">>> from {mod_name} import {', '.join(names)}\n"
        db_info = f"Using {db_kind}: {db_file}"
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
