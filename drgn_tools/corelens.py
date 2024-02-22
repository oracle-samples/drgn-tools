# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Run analysis helper code and output to stdout or a directory
"""
import abc
import argparse
import collections
import importlib
import inspect
import os
import pkgutil
import re
import shlex
import sys
import time
import traceback
from fnmatch import fnmatch
from pathlib import Path
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from drgn import Program
from drgn import ProgramFlags

from drgn_tools.debuginfo import find_debuginfo
from drgn_tools.module import get_module_load_summary
from drgn_tools.module import KernelModule
from drgn_tools.module import load_module_debuginfo
from drgn_tools.util import redirect_stdout


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
    def skip_unless_have_kmod(self) -> Optional[str]:
        """
        If specified, skip this when the kmod is not present in the kernel

        This field, when specified, is a string naming a kernel module (referred
        to as kmod in these docs to avoid confusing with "corelens module").
        This kmod is expected to signify the presence of the subsystem that this
        module is dealing with. If the kmod is not loaded in the kernel, then
        this module is skipped by corelens. If the kmod is loaded, but no
        debuginfo is present, the module is skipped and an error is raised.
        """
        return None

    @property
    def debuginfo_kmods(self) -> List[str]:
        """
        A list of kmod names (or fnmatch patterns) we need debuginfo for

        This field, when specified, is a list of strings. Each string could be a
        kmod name, or a :mod:`fnmatch` pattern which matches several kmods.

        Unlike :attr:`skip_unless_have_kmod`, we don't require that the kmods
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
        parser = argparse.ArgumentParser(
            prog=self.name,
            description=description,
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


def _load_prog_and_debuginfo(args: argparse.Namespace) -> Tuple[Program, bool]:
    """
    Load up the program and debuginfo. Don't attempt extraction.

    :returns: A 2-tuple. The first element is the loaded program, the second
    element is true when CTF is in use.
    """
    prog = Program()
    try:
        prog.set_core_dump(args.vmcore)
    except PermissionError:
        if args.vmcore == "/proc/kcore":
            try:
                from drgn.internal.sudohelper import open_via_sudo

                prog.set_core_dump(open_via_sudo(args.vmcore, os.O_RDONLY))
            except ImportError:
                sys.exit("error: no permission to open vmcore")
    if args.ctf and args.debuginfo:
        sys.exit("error: --debuginfo and --ctf conflict")

    # Search for DWARF debuginfo first, unless CTF is explicitly requested.
    vmlinux = None
    fmts_tried = []
    if not args.ctf:
        fmts_tried.append("DWARF")
        vmlinux = find_debuginfo(prog, "vmlinux", dinfo_path=args.debuginfo)

    if vmlinux:
        # Found DWARF debuginfo, continue to use that.
        prog.load_debug_info([vmlinux])
        load_module_debuginfo(prog, extract=False, quiet=True)
        return prog, False

    # Try to use CTF debuginfo
    try:
        from drgn.helpers.linux.ctf import load_ctf

        fmts_tried.append("CTF")
        release = prog["UTS_RELEASE"].string_().decode()
        path = args.ctf or f"/lib/modules/{release}/kernel/vmlinux.ctfa"
        if os.path.isfile(path):
            load_ctf(prog, path)
            return prog, True
    except ModuleNotFoundError:
        pass

    # On failure, report what we tried so the user knows
    tried = ", ".join(fmts_tried)
    sys.exit(f"error: could not find debuginfo (tried {tried})")


def _check_module_debuginfo(
    candidate_modules: List[Tuple[CorelensModule, argparse.Namespace]],
    prog: Program,
    ctf: bool = False,
) -> Tuple[
    List[Tuple[CorelensModule, argparse.Namespace]], List[str], List[str]
]:
    # When running with CTF debuginfo, there's no need to check which modules
    # have debuginfo: CTF contains info for every module. Thus, skip the module
    # load summary, which may not be cheap.
    if not ctf:
        summary = get_module_load_summary(prog)

    # Now we check whether module requirements are satisfied. Some kmods may not
    # be present in the kernel at all, whereas others are present, but with no
    # debuginfo. If the required kmod is not present, then skip the module. If
    # the kmod is present but with no debuginfo, log an error but continue to
    # run the remainder.
    all_kmod_names = set(km.name for km in KernelModule.all(prog))
    if not ctf:
        loaded_kmods = set(km.name for km in summary.loaded_mods)
        missing_kmods = set(km.name for km in summary.missing_mods)

    modules_to_run = []
    errors = []
    warnings = []
    for mod, args in candidate_modules:
        # Corelens modules which don't support live kernels are skipped
        # immediately
        if (prog.flags & ProgramFlags.IS_LIVE) and not mod.live_ok:
            warnings.append(
                f"{mod.name} skipped because it does not support live kernels"
            )
            continue

        # Corelens modules requiring DWARF can't be run when using CTF
        if mod.need_dwarf and ctf:
            warnings.append(
                f"{mod.name} skipped because it requires DWARF debuginfo, but "
                "CTF is loaded instead"
            )
            continue

        # Corelens modules that depend on a particular subsystem module being
        # present, should should be skipped if it is not present.
        if mod.skip_unless_have_kmod is not None and (
            mod.skip_unless_have_kmod not in all_kmod_names
        ):
            warnings.append(
                f"{mod.name} skipped because '{mod.skip_unless_have_kmod}'"
                " was not loaded in the kernel"
            )
            continue

        # At this point, all that's remaining to do is check whether the
        # necessary DWARF debuginfo files are loaded for this Corelens module.
        # If we're using CTF, we can skip this and move on.
        if ctf:
            modules_to_run.append((mod, args))
            continue

        if mod.skip_unless_have_kmod is not None and (
            mod.skip_unless_have_kmod not in loaded_kmods
        ):
            errors.append(
                f"{mod.name} skipped because '{mod.skip_unless_have_kmod}'"
                " did not have debuginfo loaded"
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
    except Exception:
        formatted = traceback.format_exc()
        errors.append(
            f"Encountered exception in {mod.name}:\n" f"{formatted}\n"
        )
    return time.time() - start_time


def _report_errors(
    errors: List[str], warnings: List[str], out_dir: Optional[Path]
) -> None:
    err_file = None if not out_dir else (out_dir / "corelens").open("w")
    for error in errors:
        print("error: " + error, file=sys.stderr)
        if err_file:
            print("error: " + error, file=err_file)
    for warning in warnings:
        print("warning: " + warning, file=sys.stderr)
        if err_file:
            print("warning: " + warning, file=err_file)


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


def main() -> None:
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
        "--debuginfo",
        "-d",
        help="directory to add to the debuginfo search path (should contain"
        " vmlinux and .ko.debug DWARF debuginfo files)",
    )
    parser.add_argument(
        "--ctf",
        help="CTF archive to load (overrides debuginfo and module search)",
    )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument(
        "-a",
        action="store_true",
        dest="run_all",
        help="run almost all of the corelens modules",
    )
    grp.add_argument(
        "-A",
        action="store_true",
        dest="run_all_verbose",
        help="run ALL of the corelens, including those which aren't run by -a",
    )
    parser.add_argument(
        "--output-directory",
        "-o",
        metavar="OUT",
        help="store output in a directory (each module has its own output file)",
    )
    split_args = _split_args(sys.argv[1:])
    args = parser.parse_args(split_args[0])
    if args.list:
        _print_module_listing()
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

    start_time = time.time()
    prog, ctf = _load_prog_and_debuginfo(args)
    modules_to_run, errors, warnings = _check_module_debuginfo(
        candidate_modules_to_run, prog, ctf=ctf
    )
    load_time = time.time() - start_time
    if args.output_directory:
        print(f"Loaded debuginfo in in {load_time:.03f}s")

    out_dir: Optional[Path] = None
    if args.output_directory:
        out_dir = Path(args.output_directory)
        out_dir.mkdir(exist_ok=True)

    print_header = not out_dir and len(modules_to_run) > 1
    for mod, mod_args in modules_to_run:
        if out_dir:
            out_file = out_dir / mod.name
            print(f"Running module {mod.name}... ", end="", flush=True)
            with redirect_stdout(str(out_file), append=True):
                runtime = _run_module(
                    mod, prog, mod_args, errors, print_header
                )
            print(f"completed in {runtime:.3f}s")
        else:
            _run_module(mod, prog, mod_args, errors, print_header)

    _report_errors(errors, warnings, out_dir)
    corelens_total_time = time.time() - corelens_begin_time
    if out_dir:
        print(f"corelens total runtime: {corelens_total_time:.3f}s")
    if errors:
        sys.exit(1)


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
    _report_errors(errors, warnings, None)
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
    # Please, do not ask too many questions about this line. Please. It is a
    # terrible, terrible corner of Python.
    import drgn_tools.corelens

    drgn_tools.corelens.main()
