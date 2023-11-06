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
import re
import shlex
import sys
import traceback
from fnmatch import fnmatch
from pathlib import Path
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from drgn import Program

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
    def default_args(self) -> List[str]:
        """
        When specified, this sets the default command line arguments
        """
        return []

    def _parse_args(
        self,
        args: Optional[List[str]] = None,
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
        if args is None:
            args = self.default_args
        return parser.parse_args(args)


def all_corelens_modules() -> Dict[str, CorelensModule]:
    # NOTE: we will only discover subclasses via __subclasses__() if they have
    # already been imported. It's possible in the future that we'll want a
    # mechanism to support third-party modules, but for now, we can be satisfied
    # with simply maintaining a list of Python modules which contain
    # CorelensModule subclasses.
    python_mods = [
        "drgn_tools.printk",
        "drgn_tools.nvme",
        "drgn_tools.virtio",
        "drgn_tools.ext4_dirlock",
        "drgn_tools.workqueue",
        "drgn_tools.smp",
        "drgn_tools.block",
        "drgn_tools.md",
        "drgn_tools.rds",
        "drgn_tools.cmdline",
        "drgn_tools.cpuinfo",
    ]
    for python_module in python_mods:
        importlib.import_module(python_module)

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


def _load_candidate_modules(
    module_args: List[List[str]],
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
    all_modules = all_corelens_modules()
    if not module_args:
        return [(mod, mod._parse_args()) for mod in all_modules.values()]
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
    """
    Load up the program and debuginfo. Don't attempt extraction.
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

    if args.ctf:
        try:
            from drgn.helpers.linux.ctf import load_ctf

            load_ctf(prog, args.ctf)
            return prog
        except ImportError:
            sys.exit("error: drgn is not built with CTF support")

    vmlinux = find_debuginfo(prog, "vmlinux", dinfo_path=args.debuginfo)

    if not vmlinux:
        sys.exit("error: vmlinux not found")

    prog.load_debug_info([vmlinux])
    load_module_debuginfo(prog, extract=False, quiet=True)
    return prog


def _check_module_debuginfo(
    candidate_modules: List[Tuple[CorelensModule, argparse.Namespace]],
    prog: Program,
    ctf: bool = False,
) -> Tuple[
    List[Tuple[CorelensModule, argparse.Namespace]], List[str], List[str]
]:
    summary = get_module_load_summary(prog)

    # Now we check whether module requirements are satisfied. Some kmods may not
    # be present in the kernel at all, whereas others are present, but with no
    # debuginfo. If the required kmod is not present, then skip the module. If
    # the kmod is present but with no debuginfo, log an error but continue to
    # run the remainder.
    all_kmod_names = set(km.name for km in KernelModule.all(prog))
    loaded_kmods = set(km.name for km in summary.loaded_mods)
    missing_kmods = set(km.name for km in summary.missing_mods)

    modules_to_run = []
    errors = []
    warnings = []
    for mod, args in candidate_modules:
        if mod.need_dwarf and ctf:
            warnings.append(
                f"{mod.name} skipped because it requires DWARF debuginfo, but "
                "CTF is loaded instead"
            )
            continue
        if mod.skip_unless_have_kmod is not None:
            # Skip, it is not present in the kernel
            if mod.skip_unless_have_kmod not in all_kmod_names:
                warnings.append(
                    f"{mod.name} skipped because '{mod.skip_unless_have_kmod}'"
                    " was not loaded in the kernel"
                )
                continue
            # Error, it is present but not loaded
            if mod.skip_unless_have_kmod not in loaded_kmods:
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
                elif fnmatch(missing_dbinfo, pattern):
                    errors.append(
                        f"{mod.name} skipped because '{missing_dbinfo}'"
                        " did not have debuginfo loaded"
                    )
        if skip:
            continue

        modules_to_run.append((mod, args))
    return modules_to_run, errors, warnings


def _run_module(
    mod: CorelensModule,
    prog: Program,
    args: argparse.Namespace,
    errors: List[str],
    to_stdout: bool = False,
) -> None:
    """
    Execute a module return even on error. Update errors list with any failure
    """
    try:
        if to_stdout:
            print(f"====== MODULE {mod.name} ======")
        mod.run(prog, args)
    except Exception:
        formatted = traceback.format_exc()
        errors.append(
            f"Encountered exception in {mod.name}:\n" f"{formatted}\n"
        )


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
    parser = argparse.ArgumentParser(
        description="Run analysis helper code",
        prog="corelens",
        usage="corelens [options] vmcore [-M MODULE [options] [-M MODULE ...]]",
        epilog="""
        After specifying the options and a vmcore, you may optionally specify
        modules and their arguments. You must introduce each module name and its
        arguments from the next with "-M". If you do not specify any modules,
        then corelens will run all applicable modules with their default
        arguments.
        """,
    )
    parser.add_argument(
        "vmcore",
        help="vmcore to run against (use /proc/kcore for live)",
        nargs="?",
        default="/proc/kcore",
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
    parser.add_argument(
        "--output-directory",
        "-o",
        help="store output in a directory (each module has its own output file)",
    )
    split_args = _split_args(sys.argv[1:])
    args = parser.parse_args(split_args[0])
    if args.list:
        _print_module_listing()
        sys.exit(0)

    candidate_modules_to_run = _load_candidate_modules(split_args[1:])
    prog = _load_prog_and_debuginfo(args)
    modules_to_run, errors, warnings = _check_module_debuginfo(
        candidate_modules_to_run, prog
    )

    out_dir: Optional[Path] = None
    if args.output_directory:
        out_dir = Path(args.output_directory)
        out_dir.mkdir(exist_ok=True)

    for mod, mod_args in modules_to_run:
        if out_dir:
            out_file = out_dir / mod.name
            with redirect_stdout(str(out_file)):
                _run_module(mod, prog, mod_args, errors)
        else:
            _run_module(mod, prog, mod_args, errors, to_stdout=True)

    _report_errors(errors, warnings, out_dir)
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
