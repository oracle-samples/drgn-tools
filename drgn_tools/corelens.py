# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Run analysis helper code and output to stdout or a directory
"""
import abc
import argparse
import collections
import contextlib
import importlib
import inspect
import logging
import os
import pkgutil
import re
import shlex
import sys
import time
import traceback
from fnmatch import fnmatch
from logging.handlers import MemoryHandler
from pathlib import Path
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import drgn
from drgn import Program
from drgn import ProgramFlags
from drgn.cli import version_header as drgn_version_header

from drgn_tools.debuginfo import drgn_prog_set as register_debug_info_finders
from drgn_tools.debuginfo import get_debuginfo_config
from drgn_tools.logging import FilterMissingDebugSymbolsMessages
from drgn_tools.module import get_module_load_summary
from drgn_tools.util import redirect_stdout


log = logging.getLogger("corelens")


class _CorelensArgparseEscapeException(Exception):
    pass


class CorelensModule(abc.ABC):
    """
    The base class for all corelens modules.

    In order to make a helper executable by corelens, you need to create your
    own sub-class of this one. At a minimum, you must define the field
    :attr:`name` and provide a :meth:`run()` method. Here is a minimal example
    of a hello world module:

    .. code-block:: python

        class HelloWorld(CorelensModule):
            name = "hello"
            def run(self, prog, args):
                print("Hello, world!")

    However, further fields can be set in order to document debuginfo and kernel
    module expectations, and to handle command line arguments.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        **Required:** set a field with the name of this module
        """
        raise NotImplementedError()

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        """
        **Required:** a function which executes the module

        This function will be called to execute the module. Use the normal
        print() function, which writes to ``sys.stdout``, to print information.
        When output is directed to a file, ``sys.stdout`` will be updated, so
        output redirection is transparent to the function.

        :param prog: Kernel being debugged
        :param args: Parsed command line arguments (see :meth:`add_args`)
        """
        raise NotImplementedError("You must implement run()")

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        """
        Set command line arguments for the module

        Use the :py:mod:`argparse` library to add any arguments your program
        accepts. The arguments may be provided on the command line, or come from
        the :attr:`default_args` field.

        :params parser: argument parser to configure
        """
        pass

    @property
    def skip_unless_have_kmods(self) -> Optional[List[str]]:
        """
        If specified, skip this when the kmods are not present in the kernel

        This field, when specified, is a list of strings naming kernel modules (referred
        to as kmod in these docs to avoid confusing with "corelens module").
        This kmod(s) is expected to signify the presence of the subsystem that this
        module is dealing with. If the kmod(s) is not loaded in the kernel, then
        this module is skipped by corelens. If the kmod(s) is loaded, but no
        debuginfo is present, the module is skipped and an error is raised.
        """
        return None

    @property
    def debuginfo_kmods(self) -> List[str]:
        """
        A list of kmod names (or fnmatch patterns) we need debuginfo for

        This field, when specified, is a list of strings. Each string could be a
        kmod name, or a :mod:`fnmatch` pattern which matches several kmods.

        Unlike :attr:`skip_unless_have_kmods`, we don't require that the kmods
        here are loaded. Instead, we just require that *if* the modules are
        loaded, they must have debuginfo present.

        This can be useful for a subsystem that has several modules which may
        use it, e.g. the virtio subsystem. Each virtio device has its own kmod
        implementing it (such as ``virtio_blk``). There should be no specific
        requirement that a particular virtio device has its module loaded, but
        just that all the virtio modules have debuginfo ready.
        """
        return []

    @property
    def need_dwarf(self) -> bool:
        """
        When True, this corelens module requires DWARF debuginfo
        """
        return False

    @property
    def default_args(self) -> List[List[str]]:
        """
        When specified, this list contains arguments to be passed by default to
        the module, when corelens is run in report mode (-a).

        Since corelens supports executing the same module multiple times, it may
        be desirable to run the same module multiple times in different
        configurations. Thus, each element of this list is a sub-list containing
        command line arguments. For example, suppose module "mod" should be run
        as below during a report:

            corelens /proc/kcore -M mod --arg one -M mod --arg two

        Then you could specify these arguments as:

            default_args = [["--arg", "one"], ["--arg", "two"]]

        In the more common case, where a module should be run just once with
        specified arguments, you would use:

            default_args = [["--specified", "arguments"]]

        As a special case, when this is omitted, it is set to the empty list
        ``[]``, which is a short-hand for ``[[]]``, meaning to run module once
        with no additional arguments.
        """
        return []

    @property
    def verbose_args(self) -> List[List[str]]:
        """
        When specified, this sets the default command line argument for verbose
        reports. If left unspecified, this returns the same as default_args.
        See default_args for more details.
        """
        return self.default_args

    @property
    def live_ok(self) -> bool:
        """
        Set this to False if the module doesn't support live kernels
        """
        return True

    @property
    def run_when(self) -> str:
        """
        Specify when this corelens module should be run in reports

        always: whenever -a or -A are specified
        verbose: whenever -A is specified
        never: never run by -a or -A. Can still be run via -M
        """
        return "always"

    def _notes(self) -> List[str]:
        # Return notes for the user about this module.
        notes = []
        if self.need_dwarf:
            notes.append("Requires DWARF debuginfo.")
        if not self.live_ok:
            notes.append("Live kernel not supported.")
        if self.skip_unless_have_kmods:
            notes.append(
                "Skipped unless '{}' kernel module(s) are loaded.".format(
                    ", ".join(self.skip_unless_have_kmods)
                )
            )
        if self.run_when == "verbose":
            notes.append("Detailed module (runs with -A)")
        elif self.run_when == "never":
            notes.append("Manually run module (only run with -M)")
        return notes

    def _parse_args(
        self,
        args: List[str],
        exit_on_error: bool = True,
    ) -> argparse.Namespace:
        """
        Parses a list of arguments and returns the resulting namespace.

        :param exit_on_error: If False, we trap all attempts to exit (e.g.
                              printing help or invalid arguments).
        """
        description = self.__doc__
        if description:
            description = inspect.cleandoc(description)
        epilog = "\n\n".join(self._notes())
        parser = argparse.ArgumentParser(
            prog=self.name,
            description=description,
            epilog=epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        if not exit_on_error:

            def exit(*args, **kwargs):
                raise _CorelensArgparseEscapeException()

            parser.exit = exit  # type: ignore

        self.add_args(parser)
        return parser.parse_args(args)

    def _default_args(self, verbose: bool = False) -> List[argparse.Namespace]:
        args_sets = self.verbose_args if verbose else self.default_args
        if not args_sets:
            return [self._parse_args([], exit_on_error=False)]
        else:
            return [
                self._parse_args(args, exit_on_error=False)
                for args in args_sets
            ]


def all_corelens_modules() -> Dict[str, CorelensModule]:
    # NOTE: we will only discover subclasses via __subclasses__() if they have
    # already been imported. Maybe in the future, we'll have some third-party
    # modules, but for now, we just import everything in drgn_tools so we can
    # be confident we have them all.
    paths = [str(Path(__file__).parent)]
    for mod in pkgutil.iter_modules(path=paths, prefix="drgn_tools."):
        importlib.import_module(mod.name)

    subclasses = collections.deque(CorelensModule.__subclasses__())
    result = []
    while subclasses:
        subcls = subclasses.popleft()
        this_node_subclasses = subcls.__subclasses__()
        if this_node_subclasses:
            # Assume that any class with children is not executable. Add
            # its children to the queue (BFS) but do not instantiate it.
            subclasses.extend(this_node_subclasses)
        else:
            result.append(subcls())  # type: ignore
    return {m.name: m for m in result}


def default_corelens_modules(
    verbose: bool = False,
) -> List[Tuple[CorelensModule, argparse.Namespace]]:
    """
    Return the default corelens modules to run for reports

    :param verbose: select the more verbose report preset (-A)
    """
    all_modules = all_corelens_modules()
    if verbose:
        mods = [mod for mod in all_modules.values() if mod.run_when != "never"]
    else:
        mods = [
            mod for mod in all_modules.values() if mod.run_when == "always"
        ]
    result = []
    for mod in mods:
        for args in mod._default_args(verbose):
            result.append((mod, args))
    return result


def _load_candidate_modules(
    module_args: List[List[str]],
    run_all: bool,
    run_all_verbose: bool,
) -> List[Tuple[CorelensModule, argparse.Namespace]]:
    """
    Load the modules which the user has requested to run.

    These are just candidates, because we'll need to filter them based on what
    kernel modules are loaded, and which debuginfo is available. Loading this
    is done prior to opening the vmcore so we can fail fast if the user is
    asking for corelens modules that don't exist.

    :param args: The arguments to main()
    :returns: A list of (corelens) modules to run and their arguments
    """
    if run_all or run_all_verbose:
        return default_corelens_modules(verbose=run_all_verbose)

    all_modules = all_corelens_modules()
    if not module_args:
        sys_mod = all_modules["sys"]
        return [(sys_mod, sys_mod._parse_args([]))]
    candidate_modules_to_run = []
    for arglist in module_args:
        mod_name = arglist[0]
        mod_args = arglist[1:]
        try:
            mod = all_modules[mod_name]
            candidate_modules_to_run.append((mod, mod._parse_args(mod_args)))
        except KeyError:
            sys.exit(f"error: module '{mod_name}' not found")
    return candidate_modules_to_run


def _load_prog_and_debuginfo(args: argparse.Namespace) -> Program:
    if args.ctf and args.dwarf:
        sys.exit("error: --dwarf and --ctf conflict")

    # Corelens doesn't fully respect the configurations in drgn_tools.ini.
    # Downloads are disabled, but extraction from a local vmlinux-repo is
    # allowed. CTF is enabled by default.
    # CLI flags allow using CTF only, DWARF only, as well as enabling downloads.
    opts = get_debuginfo_config()
    opts.enable_ctf = True
    opts.disable_dwarf = False

    if args.ctf:
        opts.disable_dwarf = True
    elif args.dwarf:
        opts.enable_ctf = False
    opts.enable_extract = True
    opts.enable_download = args.enable_download
    opts.dwarf_dir = args.dwarf_dir
    opts.ctf_file = args.ctf_file

    prog = Program()
    prog.cache["drgn_tools.debuginfo.options"] = opts
    try:
        prog.set_core_dump(args.vmcore)
    except PermissionError:
        if args.vmcore == "/proc/kcore":
            try:
                from drgn.internal.sudohelper import open_via_sudo

                prog.set_core_dump(open_via_sudo(args.vmcore, os.O_RDONLY))
            except ImportError:
                sys.exit("error: no permission to open vmcore")

    if "drgn_tools.debuginfo" not in prog.cache:
        register_debug_info_finders(prog)
    try:
        prog.load_default_debug_info()
    except drgn.MissingDebugInfoError:
        if prog.main_module().wants_debug_file():
            sys.exit("error: could not find vmlinux debuginfo")
        # otherwise, let's see whether we have enough module debuginfo

    return prog


def _check_module_debuginfo(
    candidate_modules: List[Tuple[CorelensModule, argparse.Namespace]],
    prog: Program,
    warn_not_present: bool = True,
) -> Tuple[
    List[Tuple[CorelensModule, argparse.Namespace]], List[str], List[str]
]:
    summary = get_module_load_summary(prog)
    all_kmod_names = set(km.name for km in summary.all_mods())
    loaded_kmods = set(km.name for km in summary.loaded_mods)
    missing_kmods = set(km.name for km in summary.missing_mods)

    modules_to_run = []
    errors = []
    warnings = []
    for mod, args in candidate_modules:
        # Corelens modules that depend on a particular subsystem module being
        # present, should should be skipped if it is not present.
        if mod.skip_unless_have_kmods is not None and (
            not all(m in all_kmod_names for m in mod.skip_unless_have_kmods)
        ):
            if warn_not_present:
                warnings.append(
                    "{} skipped because '{}' was (were) not (all) loaded in the kernel".format(
                        mod.name, ", ".join(mod.skip_unless_have_kmods)
                    )
                )
            continue

        # Corelens modules which don't support live kernels are skipped
        # immediately
        if (prog.flags & ProgramFlags.IS_LIVE) and not mod.live_ok:
            warnings.append(
                f"{mod.name} skipped because it does not support live kernels"
            )
            continue

        # Corelens modules requiring DWARF can't be run when using CTF
        if mod.need_dwarf and prog.cache.get("using_ctf"):
            warnings.append(
                f"{mod.name} skipped because it requires DWARF debuginfo, but "
                "CTF is loaded instead"
            )
            continue

        # All modules that require debuginfo should have it loaded
        if mod.skip_unless_have_kmods is not None and (
            not all(m in loaded_kmods for m in mod.skip_unless_have_kmods)
        ):
            errors.append(
                "{} skipped because '{}' did not have (all) debuginfo loaded".format(
                    mod.name, ", ".join(mod.skip_unless_have_kmods)
                )
            )
            continue
        skip = False
        for missing_dbinfo in missing_kmods:
            for pattern in mod.debuginfo_kmods:
                if pattern.startswith("re:"):
                    if re.fullmatch(pattern[3:], missing_dbinfo):
                        errors.append(
                            f"{mod.name} skipped because '{missing_dbinfo}'"
                            " did not have debuginfo loaded"
                        )
                        skip = True
                elif fnmatch(missing_dbinfo, pattern):
                    errors.append(
                        f"{mod.name} skipped because '{missing_dbinfo}'"
                        " did not have debuginfo loaded"
                    )
                    skip = True
        if skip:
            continue

        modules_to_run.append((mod, args))
    return modules_to_run, errors, warnings


def _run_module(
    mod: CorelensModule,
    prog: Program,
    args: argparse.Namespace,
    errors: List[str],
    print_header: bool = False,
) -> float:
    """
    Execute a module return even on error. Update errors list with any failure.
    Return runtime in seconds.
    """
    start_time = time.time()
    try:
        if print_header:
            print(f"\n====== MODULE {mod.name} ======")
        mod.run(prog, args)
    except (KeyboardInterrupt, BrokenPipeError):
        raise
    except Exception:
        formatted = traceback.format_exc()
        errors.append(
            f"Encountered exception in {mod.name}:\n" f"{formatted}\n"
        )
    return time.time() - start_time


def _report_errors(errors: List[str], warnings: List[str]) -> None:
    for error in errors:
        log.error("error: " + error)
    for warning in warnings:
        log.warning("warning: " + warning)


def _split_args(arg_list: List[str], delim: str = "-M") -> List[List[str]]:
    """
    Split an argument list into sublists by delimiter
    """
    split_args = []
    arg_list = sys.argv[1:]
    while True:
        try:
            index = arg_list.index(delim)
        except ValueError:
            split_args.append(arg_list)
            break
        split_args.append(arg_list[:index])
        arg_list = arg_list[index + 1 :]
    return split_args


def _print_module_listing() -> None:
    maxlen = max(len(name) for name in all_corelens_modules())
    for name, module in all_corelens_modules().items():
        doc = getattr(module, "__doc__")
        if doc:
            lines = doc.split("\n")
            first_line = (lines[0] or lines[1]).strip()
            print(f"{name.ljust(maxlen)} {first_line}")
        else:
            print(name)
        for note in module._notes():
            print(" " * (maxlen), note)


def _version_string() -> str:
    try:
        from drgn.helpers.linux.ctf import load_ctf  # noqa

        ctf_str = "with CTF"
    except ModuleNotFoundError:
        ctf_str = "without CTF"

    try:
        from drgn_tools._version import __version__
    except ModuleNotFoundError:
        __version__ = "VERSION UNKNOWN"

    return f"drgn-tools {__version__}, {drgn_version_header()}, {ctf_str}"


def _do_main() -> None:
    corelens_begin_time = time.time()
    parser = argparse.ArgumentParser(
        description="Kernel core dump analysis tool",
        prog="corelens",
        usage=(
            "corelens [-o OUT] vmcore [-M MODULE [options] [-M MODULE ...]]\n"
            "       corelens [-o OUT] vmcore [-a | -A]\n"
            "       corelens -h           (for help)\n"
            "       corelens -L           (to list modules)\n"
            "       corelens -M MODULE -h (for module-specific help)"
        ),
        epilog="""
        After specifying the options and a vmcore, you may optionally specify
        modules and their arguments. You must introduce each module name and its
        arguments from the next with "-M". If you do not specify any modules,
        then corelens will print basic information about the vmcore.
        """,
    )
    parser.add_argument(
        "vmcore",
        help="vmcore to run against (use /proc/kcore for live)",
        nargs="?",
    )
    parser.add_argument(
        "--list",
        "-L",
        action="store_true",
        help="list corelens module names",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="store_true",
        help="print the version of corelens",
    )
    parser.add_argument(
        "--dwarf",
        "-D",
        action="store_true",
        help="only use DWARF debuginfo (disable CTF)",
    )
    parser.add_argument(
        "--dwarf-dir",
        "-d",
        help="directory to add to the debuginfo search path (should contain"
        " vmlinux and .ko.debug DWARF debuginfo files)",
    )
    parser.add_argument(
        "--ctf",
        "-C",
        action="store_true",
        help="only use CTF debuginfo (disable DWARF)",
    )
    parser.add_argument(
        "--ctf-file",
        "-c",
        help="specify a CTF file to use (implies --ctf)",
    )
    parser.add_argument(
        "--enable-download",
        "-g",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument(
        "-a",
        action="store_true",
        dest="run_all",
        help="run all of the standard corelens modules",
    )
    grp.add_argument(
        "-A",
        action="store_true",
        dest="run_all_verbose",
        help="run ALL of the modules, both standard and detailed",
    )
    parser.add_argument(
        "--output-directory",
        "-o",
        metavar="OUT",
        help="store output in a directory (each module has its own output file)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="output diagnostic information as debuginfo is loaded",
    )
    split_args = _split_args(sys.argv[1:])
    args = parser.parse_args(split_args[0])

    # Set the implied arguments
    if args.ctf_file:
        args.ctf = True
    if args.dwarf_dir:
        args.dwarf = True
    if args.ctf and args.dwarf:
        sys.exit("error: --dwarf and --ctf conflict, use only one")

    if args.list:
        _print_module_listing()
        sys.exit(0)
    elif args.version:
        print(_version_string())
        sys.exit(0)

    # Load corelens modules before initializing prog, so that the argument
    # parsers get a chance to run. This way, it's legal to do things like:
    # corelens -M dentrycache -h, which prints the dentrycache help without
    # needing to specify a vmcore.
    if args.run_all and split_args[1:]:
        sys.exit("error: either specify -A or a list of modules, not both")
    candidate_modules_to_run = _load_candidate_modules(
        split_args[1:], args.run_all, args.run_all_verbose
    )

    if not args.vmcore:
        parser.print_usage()
        sys.exit("error: specify a vmcore or /proc/kcore, or a help option")
    if args.vmcore == "/proc/kcore":
        print("warning: Running corelens against a live system.")
        print("         Data may be inconsistent, or corelens may crash.")

    # We have a few kinds of CLI output:
    # - Information regarding corelens & runtime (debuginfo version, how long
    #   each module runs, etc).
    # - Output produced by corelens modules.
    # - Warnings and errors. These are always printed directly.
    #
    # Here's how we handle each in the three major situations we see:
    #
    # (1) Running in "report mode" (i.e. anything using the -o option)
    #     - Corelens metedata & runtime info is printed in real time. It is also
    #       printed to a file named "corelens" inside the report.
    #     - Corelens module output goes to a file inside the report.
    # (2) Running multiple modules, but still printing to stdout
    #     (eg: corelens /proc/kcore -M sys -M dentrycache
    #      OR: corelens /proc/kcore -a)
    #     - Corelens metadata & runtime info is collected and printed at the end
    #     - Corelens module output is printed to stdout, separated by headers
    # (3) Running a single module (eg: corelens /proc/kcore -M sys)
    #     - Corelens metadata & runtime info is suppressed
    #     - Corelens module output is printed to stdout
    out_dir: Optional[Path] = None
    print_header = False
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    drgnlog = logging.getLogger("drgn")
    drgnlog.addFilter(FilterMissingDebugSymbolsMessages())
    drgnlog.setLevel(logging.DEBUG if args.verbose else logging.WARNING)
    if args.output_directory:
        out_dir = Path(args.output_directory)
        try:
            out_dir.mkdir(exist_ok=True)
        except OSError as e:
            sys.exit(f"error creating output directory: {e}")

        root_logger.addHandler(logging.StreamHandler())
        root_logger.addHandler(
            logging.FileHandler(out_dir / "corelens", mode="w")
        )
    elif len(candidate_modules_to_run) > 2:
        print_header = True
        root_logger.addHandler(
            MemoryHandler(
                capacity=float("inf"),  # type: ignore
                target=logging.StreamHandler(),
            )
        )
        log.info("%s", "\n====== corelens ======")
    start_time = time.time()
    prog = _load_prog_and_debuginfo(args)
    modules_to_run, errors, warnings = _check_module_debuginfo(
        candidate_modules_to_run,
        prog,
        # "warning: A skipped because A was not loaded in the kernel"
        # messages are useful when the user explicitly requested module A to
        # run, but it's not applicable. However, when we run the report mode (-a
        # or -A), the user never requisted these specific modules: they just
        # expect that relevant modules will run. Suppress the warning for those
        # modes.
        warn_not_present=not (args.run_all or args.run_all_verbose),
    )
    load_time = time.time() - start_time

    log.info("%s", _version_string())
    kind = "CTF" if prog.cache.get("using_ctf") else "DWARF"
    log.info("Loaded %s debuginfo in in %.03fs", kind, load_time)
    log.debug(
        "Enabled debuginfo finders: %r", prog.enabled_debug_info_finders()
    )

    for mod, mod_args in modules_to_run:
        log.info("Running module %s...", mod.name)
        with contextlib.ExitStack() as es:
            if out_dir:
                out_file = out_dir / mod.name
                es.enter_context(redirect_stdout(str(out_file), append=True))
            runtime = _run_module(mod, prog, mod_args, errors, print_header)
        log.info("  completed in %.3fs", runtime)

    corelens_total_time = time.time() - corelens_begin_time
    log.info("corelens total runtime: %.3fs", corelens_total_time)
    _report_errors(errors, warnings)
    if errors:
        sys.exit(1)


def main() -> None:
    # Wrap _do_main() with standard Ctrl-C and pipe handling. We do this here,
    # rather than in the "if __name__ == '__main__'" area below, because this is
    # the entry point called by the command line stub that actually gets
    # installed to /usr/bin. If we included it below, then the /usr/bin/corelens
    # script wouldn't get these error handlers.
    try:
        _do_main()
    except KeyboardInterrupt:
        sys.exit("interrupted")
    except BrokenPipeError:
        pass


def run(prog: Program, cl_cmd: str) -> None:
    """
    Run a single corelens command

    The string ``cl_cmd`` is split using common shell lexing rules, and the
    first token is used as the name of the corelens module. The remaining tokens
    are used as arguments to that corelens module. The module is executed
    against ``prog``.

    :param cl_cmd: command string to execute
    """
    cmd = shlex.split(cl_cmd)
    module_name, args = cmd[0], cmd[1:]
    module = all_corelens_modules()[module_name]
    try:
        ns = module._parse_args(args, exit_on_error=False)
    except _CorelensArgparseEscapeException:
        return
    to_run, errors, warnings = _check_module_debuginfo([(module, ns)], prog)
    _report_errors(errors, warnings)
    if to_run:
        module.run(prog, ns)


def make_runner(prog: Program) -> Callable[[str], None]:
    """
    Return a helper, "cl", which executes corelens commands against a program

    The :func:`run()` function requires passing the ``prog`` as its first
    argument, which is a bit clunky when trying to run a command. So, this
    function can return a helper that is bound to the specific program, so that
    you can simply run ``cl("command")`` without including the ``prog``
    argument. This is intended for interactive environments.
    """

    def cl(cl_cmd: str) -> None:
        return run(prog, cl_cmd)

    return cl


if __name__ == "__main__":
    # When the module is run directly, as in "python -m drgn_tools.corelens",
    # Python actually creates this module with the name "__main__", rather than
    # drgn_tools.corelens. Later on, when other code imports
    # drgn_tools.corelens, this module is actually re-read and a new module with
    # the correct name is created. That means that there are actually two copies
    # of the class CorelensModule: the one defined in __main__, and the one
    # defined in drgn_tools.corelens. Nothing inherits from the one in __main__,
    # so if we run __main__.main(), we don't detect any corelens modules. We
    # need to run drgn_tools.corelens.main() in order to actually get a
    # functional program.
    import drgn_tools.corelens

    drgn_tools.corelens.main()
