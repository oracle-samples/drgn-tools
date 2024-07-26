# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
import collections
import typing as t

import drgn
from drgn import Architecture
from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn import ProgramFlags
from drgn import TypeKind
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.sched import cpu_curr
from drgn.helpers.linux.sched import task_state_to_char

from drgn_tools.corelens import CorelensModule
from drgn_tools.mm import AddrKind
from drgn_tools.module import KernelModule
from drgn_tools.task import task_cpu

__all__ = (
    "bt",
    "bt_frames",
    "bt_has",
    "bt_has_any",
    "expand_frames",
    "expand_traces",
    "find_pt_regs",
    "frame_name",
    "is_pt_regs",
    "print_frames",
    "print_task_header",
)


def func_name(prog: drgn.Program, frame: drgn.StackFrame) -> t.Optional[str]:
    if frame.name:
        return frame.name
    try:
        return frame.symbol().name
    except LookupError:
        return None


def frame_name(prog: drgn.Program, frame: drgn.StackFrame) -> str:
    """Return a suitable name for a stack frame"""
    # Looking up the module for an address is currently a bit inefficient, since
    # we iterate over every module. However, categorizing the address is quick!
    # Check whether the address is kernel text, and if so, don't do the module
    # lookup.
    mod = None
    try:
        kind = AddrKind.categorize(prog, frame.pc)
    except LookupError:
        return "???"  # LookupError: program counter is not known
    if kind not in (AddrKind.TEXT, AddrKind.INITTEXT):
        mod = KernelModule.lookup_address(prog, frame.pc)

    # For frames where drgn has a name, we should stick with that name: it may
    # include inline functions that are more specific than the symbol we would
    # lookup. However, even in that case, we still want to add on the module
    # name.
    if frame.name and mod:
        return f"{frame.name} [{mod.name}]"
    elif frame.name:
        return frame.name

    # Ok, drgn doesn't know the name of this frame: maybe it is a module which
    # is missing debuginfo? We can start by falling back to the symbol table.
    try:
        name = frame.symbol().name
    except LookupError:
        # And the drgn symbol table doesn't know either. We can still try to
        # lookup the symbol name for a module using whatever its kallsyms and
        # exported symbols are.
        if mod:
            name = mod.get_symbol(frame.pc)
            if not name:
                name = "UNKNOWN"
        else:
            name = f"{frame.pc:016x}"

    # Annotate with module name here as well.
    if mod:
        name = f"{name} [{mod.name}]"
    return name


def is_pt_regs(type_: drgn.Type) -> bool:
    """
    Determine whether a type refers to struct pt_regs, (pointer or direct)
    """
    if type_.kind == TypeKind.POINTER:
        type_ = type_.type
    if type_.kind != TypeKind.STRUCT:
        return False
    return type_.type_name() == "struct pt_regs"


def find_pt_regs(trace: drgn.StackTrace) -> t.Optional[drgn.Object]:
    """
    Given a stack trace, return the last pt_regs variable found, if any.
    """
    last_pt_regs = None
    for frame in trace:
        for local in frame.locals():
            try:
                val = frame[local]
            except KeyError:
                continue
            except Exception as e:
                # In this case, drgn misbehaves on a type of DWARF opcode
                # which it couldn't handle anyway. The proper way to handle
                # it is to treat it as an absent variable. Normally, we
                # still print absent variables (since it helps to have their
                # type info). In this case we'll just bite the bullet and
                # skip printing the variable altogether.
                # https://github.com/osandov/drgn/issues/233
                # https://github.com/osandov/drgn/issues/374
                if "unknown DW" in str(e):
                    # unknown DWARF expression opcode
                    # unknown DW_AT_const_value form
                    # This detection should be good enough :)
                    continue
                else:
                    raise
            if is_pt_regs(val.type_) and not val.absent_:
                try:
                    # The variable could be an uninitialized pointer or
                    # something unexpected. The goal of finding the pt_regs is
                    # finding something we can backtrace. If we can't access sp,
                    # then that will ultimately fail. Check whether we get a
                    # FaultError here, and if so, don't return that pt_regs var.
                    val.sp.value_()
                    last_pt_regs = val
                except drgn.FaultError:
                    pass
    return last_pt_regs


def expand_traces(trace: drgn.StackTrace) -> t.List[drgn.StackTrace]:
    """
    Given a stack trace, return all stack segments we can find.

    A stack segment would be something like an interrupt stack or NMI. It is
    possible to have multiple kernel stacks: for instance, a system call, which
    is interrupted, and then a NMI. Sometimes drgn doesn't get all of these in
    one stack trace, and we need to search for additional stack segments by
    finding a pt_regs variable on the stack. This function returns as many as
    possible.
    """
    prog = trace.prog
    traces = [trace]
    pt_regs = find_pt_regs(trace)
    # We should continue appending traces so long as (a) we can find a pt_regs,
    # and (b) the stack pointer for that pt_regs is different than the stack
    # pointer for the current stack.
    #
    # NOTE: aarch64 does not guarantee having SP if we're unwinding with frame
    # pointers. However, trace[0] always has SP, because we generally have a
    # full register set to start the trace. Thus, this should be safe to test.
    while pt_regs is not None and pt_regs.sp.value_() != trace[0].sp:
        # Interrupted user address.
        if (
            AddrKind.categorize(trace.prog, pt_regs.sp.value_())
            == AddrKind.USER
        ):
            break
        trace = prog.stack_trace(pt_regs)
        traces.append(trace)
        pt_regs = find_pt_regs(trace)
    return traces


def expand_frames(trace: drgn.StackTrace) -> t.List[drgn.StackFrame]:
    """
    Return the frames of an expanded stack trace, flattened to a single list.

    This is almost the same as :func:`expand_traces()`, except that it returns
    the frames in a single list, which is easier to access if you have run
    :func:`bt()` and you are looking to simply access the correct frame index.

    :param trace: A stack trace to expand
    :returns: A list of stack frames
    """
    frames = []
    for trace in expand_traces(trace):
        frames.extend(list(trace))
    return frames


def _bt_user_friendly_arg(
    task_or_prog: t.Union[drgn.Object, drgn.Thread, drgn.Program],
    cpu: t.Optional[int] = None,
    pid: t.Optional[int] = None,
) -> drgn.Object:
    """
    This private function implements the argument handling for bt().

    It turns out to be surprisingly complex: we can handle a wide variety of
    user-friendly ways of specifying something to trace: a drgn.Thread, cpu or
    pid, or just an object representing a stack trace or task_struct.
    """
    prog = None
    if isinstance(task_or_prog, drgn.Thread):
        task = task_or_prog.object
    elif isinstance(task_or_prog, drgn.Program):
        prog = task_or_prog
        if cpu is not None and pid is not None:
            raise ValueError("Provide either cpu or pid, but not both")
        elif cpu is not None:
            task = cpu_curr(prog, cpu)
        elif pid is not None:
            task = prog.thread(pid).object
        else:
            raise ValueError(
                "When the first argument is Program, you must provide "
                "either a cpu or a pid argument."
            )
    elif isinstance(task_or_prog, drgn.Object):
        task = task_or_prog
    else:
        raise ValueError(
            "First argument must be either Program, Thread, or Object "
            "representing a struct task_struct * or pt_regs."
        )
    # Now print a nice warning in case cpu or pid was provided but not used.
    if prog is None and (cpu is not None or pid is not None):
        print(
            "Warning: you provided cpu or pid arguments, but they were "
            "ignored since you provided a Thread or Object as your first "
            "argument."
        )
    return task


def bt_frames(
    task_or_prog: t.Union[drgn.Object, drgn.Thread, drgn.Program],
    cpu: t.Optional[int] = None,
    pid: t.Optional[int] = None,
) -> t.List[drgn.StackFrame]:
    """
    Return the stack frames that :func:`bt()` would print

    This takes mostly the same args as :func:`bt()`, but it doesn't print
    anything. It just returns the frames.
    """
    task = _bt_user_friendly_arg(task_or_prog, cpu=cpu, pid=pid)
    stack_trace = task.prog_.stack_trace(task)
    return expand_frames(stack_trace)


def print_task_header(task: drgn.Object, indent: int = 0) -> None:
    """
    Given a task struct, print the header line of the stack trace.
    """
    cpu = task_cpu(task)
    taskp = task.value_()
    pid = task.pid.value_()
    comm = escape_ascii_string(task.comm.string_())
    st = task_state_to_char(task)
    cpu_note = ""
    if cpu_curr(task.prog_, cpu) == task:
        cpu_note = "!"
    pfx = " " * indent
    print(
        f"{pfx}PID: {pid:<7d}  TASK: {taskp:x} [{st}] CPU: {cpu}{cpu_note}"
        f'  COMMAND: "{comm}"'
    )


def print_frames(
    prog: drgn.Program,
    trace: t.Union[drgn.StackTrace, t.List[drgn.StackFrame]],
    show_vars: bool = False,
    show_absent: bool = False,
    start_idx: int = 0,
    indent: int = 0,
) -> None:
    """
    Print stack frames using the drgn-tools (crash-like) format

    :param prog: Program - necessary because a list of frames has no reference
      to the program they are from.
    :param trace: The stack trace or list of frames to print
    :param show_vars: True if you want to show variables
    :param show_absent: True if you further want to show absent variables
    :param start_idx: Where to start counting the frame indices from
    :param indent: How many spaces to indent the output
    """
    # On aarch64 without DWARF, it seems we're not guaranteed to have the stack
    # pointer, or the frame pointer. Fallback to FP, then NULL, here so we don't
    # crash during unwinds.
    if prog.platform.arch == Architecture.AARCH64:

        def get_sp(frame: drgn.StackFrame) -> int:
            try:
                return frame.sp
            except LookupError:
                try:
                    return frame.register("fp")
                except LookupError:
                    return 0

    else:

        def get_sp(frame: drgn.StackFrame) -> int:
            return frame.sp

    pfx = " " * indent
    for i, frame in enumerate(trace):
        sp = get_sp(frame)
        intr = "!" if frame.interrupted else " "
        try:
            pc = hex(frame.pc)
        except LookupError:
            pc = "???"
        name = frame_name(prog, frame)
        idx = start_idx + i
        out_line = f"{pfx}{intr}#{idx:2d} [{sp:x}] {name} at {pc}"
        try:
            file_, line, col = frame.source()
            out_line += f" {file_}:{line}:{col}"
        except LookupError:
            pass
        print(out_line)

        if not show_vars:
            continue

        # Format the registers, but only when we've reached a stack frame
        # with a different stack pointer than the previous. That is: only
        # when we reach the frame for a non-inline function. Also, only
        # output registers when we have show_vars=True.
        if i == len(trace) - 1 or sp != get_sp(trace[i + 1]):
            registers = frame.registers()
            regnames = list(registers.keys())
            # This formats the registers in three columns.
            for j in range(0, len(regnames), 3):
                print(
                    pfx
                    + " " * 5
                    + "  ".join(
                        f"{reg.upper():>3s}: {registers[reg]:016x}"
                        for reg in regnames[j : j + 3]
                    )
                )

        # This requires drgn 0.0.22+.
        for local in frame.locals():
            try:
                val = frame[local]
            except KeyError:
                continue
            except Exception as e:
                # In this case, drgn misbehaves on a type of DWARF opcode
                # which it couldn't handle anyway. The proper way to handle
                # it is to treat it as an absent variable. Normally, we
                # still print absent variables (since it helps to have their
                # type info). In this case we'll just bite the bullet and
                # skip printing the variable altogether.
                # TODO: when v0.0.23 is released, assuming it contains
                # the fix for the below bug, drop this exception handler.
                # https://github.com/osandov/drgn/issues/233
                if "unknown DWARF expression opcode" in str(e):
                    continue
                else:
                    raise
            if val.absent_ and not show_absent:
                continue

            try:
                val_str = val.format_(dereference=False).replace(
                    "\n", "\n     "
                )
            except FaultError:
                val_str = "(FaultError occurred while formatting!)"
            print(pfx + " " * 5 + f"{local} = {val_str}")


def print_traces(
    traces: t.List[drgn.StackTrace],
    show_vars: bool = False,
    show_absent: bool = False,
    indent: int = 0,
) -> None:
    """
    Given a list of stack traces, print them in the crash-like format

    This will separate each stack trace with a message indicating that
    we are continuing to a new trace.

    :param traces: List of stack traces (see :func:`expand_traces()`)
    :param show_vars: Whether to print variables and registers
    :param show_absent: Whether to print absent variables
    """
    idx = 0
    prog = traces[0].prog
    for trace_idx, trace in enumerate(traces):
        print_frames(
            prog, trace, show_vars=show_vars, start_idx=idx, indent=indent
        )
        idx += len(trace)

        # Ok, this is the end of the loop over each frame within the trace.
        if trace_idx < len(traces) - 1:
            # But there is still another segment
            print(" " * indent + " -- continuing to previous stack -- ")


def bt(
    task_or_prog: t.Union[drgn.Object, drgn.Thread, drgn.Program],
    cpu: t.Optional[int] = None,
    pid: t.Optional[int] = None,
    show_vars: bool = False,
    show_absent: bool = False,
    retframes: bool = False,
    indent: int = 0,
) -> t.Optional[t.List[drgn.StackFrame]]:
    """
    Format a crash-like stack trace.

    This formats a stack trace reminiscent of (but not strictly identical to)
    the crash "bt" command. The function can be called in several ways, to
    maximize flexibility. The first argument may be a task struct or pt_regs
    object, or it may be a :class:`drgn.Thread` representing a task. Finally,
    it can be a :class:`drgn.Program`, in which case you need to provide a CPU
    or PID number as an argument. Here are some examples:

    >>> task = get_some_task_struct(prog)
    >>> bt(task)
    ...
    >>> bt(prog.thread(1))
    ...
    >>> bt(prog, cpu=0)
    ...

    Not all of crash's bt features are yet implemented, but there is one
    feature which already surpasses crash's implementation: printing variable
    values. When enabled, at each stack frame there will be a listing of each
    local variable or function arg, and its value. The value may be "absent" if
    it was optimized out or if the compiler/debuginfo is not able to provide
    enough information to retrieve it.

    This helper also mitigates some issues seen with drgn's built-in stack
    trace functionality: sometimes, the stack trace is truncated (typically at
    a page fault or IRQ boundary). This helper will detect this and "expand" the
    stack trace by searching for the last ``struct pt_regs`` variable in it. The
    helper will print all relevant stack traces. See :func:`expand_traces()`,
    :func:`expand_frames()`, and :func:`bt_frames()` for ways to use this logic
    without needing to print the stack trace.

    :param task_or_prog: Either a task struct pointer, a :class:`drgn.Thread`
      object, or a :class:`drgn.Program`.
    :param cpu: The CPU number to backtrace (only used when ``task_or_prog`` is
      a :class:`drgn.Program`). Mutually exclusive with ``pid``.
    :param pid: The PID to backtrace (only used when ``task_or_prog`` is a
      :class:`drgn.Program`). Mutually exclusive with ``cpu``.
    :param show_vars: Whether to enable formatting variables for each frame.
    :param show_absent: When show_vars=True, this can further expand the output
      to include absent variables. Normally there's no reason to see this, since
      absent variables have no information.
    :param retframes: When true, returns a list of stack frames.
    :param indent: Number of spaces to indent all output lines
    :returns: A list of the stack frames which were printed. This can be useful
      for accessing the variables out of the frames interactively. If you're
      writing a script that needs to access frames, you may want to consider the
      other functions in this module, which do not print the frames.
    """
    task = _bt_user_friendly_arg(task_or_prog, cpu=cpu, pid=pid)
    # We call this "task", but it's legal to provide a struct pt_regs. This
    # function should work fine, but not print the header, in that case.
    if task.type_.type_name() in (
        "struct task_struct",
        "struct task_struct *",
    ):
        state = task_state_to_char(task)
        print_task_header(task, indent=indent)
        if state in ("Z", "X"):
            print(f"Task is in state: {state} - cannot unwind")
            return []

    traces = expand_traces(task.prog_.stack_trace(task))
    print_traces(
        traces, show_vars=show_vars, show_absent=show_absent, indent=indent
    )
    frames = None
    if retframes:
        frames = []
        for trace in traces:
            frames.extend(list(trace))
    return frames


def _index_functions(prog: drgn.Program) -> t.Dict[str, t.Set[int]]:
    # Running a backtrace on every task is a very expensive operation, and it's
    # likely that we will want to find multiple functions. For example, corelens
    # already has several uses of bt_has(). For vmcores, the stacks will never
    # change, so we can create an index to speed up subsequent accesses. We do
    # want to be careful about memory usage: rather than storing stack frames or
    # task pointers (which are complex drgn Data structures), we just keep track
    # of the PIDs for each function. Later, _indexed_bt_has() can find the task
    # and stack frames again.
    func_to_pids = collections.defaultdict(set)
    for task in for_each_task(prog):
        pid = task.pid.value_()
        try:
            frames = bt_frames(task)
            for frame in frames:
                name = func_name(prog, frame)
                if not name:
                    continue
                func_to_pids[name].add(pid)
        except FaultError:
            # FaultError: catch unusual unwinding issues
            pass
    return func_to_pids


def _indexed_bt_has_any(
    prog: drgn.Program,
    funcs: t.List[str],
) -> t.List[t.Tuple[drgn.Object, drgn.StackFrame]]:
    index = prog.cache.get("drgn_tools.bt._index_functions")
    if index is None:
        index = _index_functions(prog)
        prog.cache["drgn_tools.bt._index_functions"] = index

    result = []
    pids = set()
    for funcname in funcs:
        pids.update(index[funcname])
    for pid in pids:
        task = find_task(prog, pid)
        for frame in bt_frames(task):
            name = func_name(prog, frame)
            if name in funcs:
                result.append((task, frame))
    return result


def bt_has_any(
    prog: drgn.Program,
    funcs: t.List[str],
    task: t.Optional[drgn.Object] = None,
) -> t.List[t.Tuple[drgn.Object, drgn.StackFrame]]:
    """
    Search for tasks whose stack contains the given functions

    For each task on the system, examine their stack trace and search for a
    list of functions. For each task containing such a function on the stack,
    return a tuple containing a pointer to the task, and the stack frame
    containing the function call.

    This can be an expensive operation, since there may be many running tasks,
    and unwinding all of them may take some time. As a result, when running
    against a core dump, this function will cache information in order to
    improve runtime.

    :param prog: drgn program
    :param funcname: function name
    :returns: a list of (``struct task_struct *``, drgn.StackFrame)
    """
    # Use a cached function index for vmcores
    if not (prog.flags & ProgramFlags.IS_LIVE):
        return _indexed_bt_has_any(prog, funcs)

    frame_list = []
    tasks = [task] if task is not None else for_each_task(prog)

    for task in tasks:
        try:
            frames = bt_frames(task)
            for frame in frames:
                if func_name(prog, frame) in funcs:
                    frame_list.append((task, frame))
        except (FaultError, ValueError):
            # FaultError: catch unusual unwinding issues
            # ValueError: catch "cannot unwind stack of running task"
            pass

    return frame_list


def bt_has(
    prog: drgn.Program,
    funcname: str,
    task: t.Optional[drgn.Object] = None,
) -> t.List[t.Tuple[drgn.Object, drgn.StackFrame]]:
    """
    Search for tasks whose stack contains a single function

    This function is identical to bt_has_any(), but takes only one
    function argument.
    """
    return bt_has_any(prog, [funcname], task)


def print_online_bt(
    prog: Program, skip_idle: bool = True, **kwargs: t.Any
) -> None:
    """
    Prints the stack trace of all on-CPU tasks

    :kwargs: passed to bt() to control backtrace format
    """
    for cpu in for_each_online_cpu(prog):
        task = cpu_curr(prog, cpu)
        if skip_idle and task.comm.string_().decode() == f"swapper/{cpu}":
            # Just because it's the swapper task, does not mean it is idling.
            # Check the symbol at the top of the stack to ensure it's the
            # architecture idle function, or if the swapper task got halted.
            trace = prog.stack_trace(task)
            try:
                sym = trace[0].symbol().name
                if sym in ("intel_idle", "arch_cpu_idle", "native_safe_halt"):
                    continue
            except (IndexError, LookupError):
                pass
        bt(prog, cpu=cpu, **kwargs)
        print()


def print_all_bt(
    prog: Program, states: t.Optional[t.Container[str]] = None, **kwargs: t.Any
) -> None:
    """
    Prints the stack trace of all tasks

    :param states: when provided (and non-empty), filter the output to only
      contain tasks in the given states (like the single-character codes
      reported by ps(1)).
    :param kwargs: passed to bt() to control backtrace format
    """
    for task in for_each_task(prog):
        st = task_state_to_char(task)

        if states and st not in states:
            continue

        try:
            bt(task, **kwargs)
        except (ValueError, FaultError) as e:
            # Catch ValueError for unwinding running tasks on live
            # systems. Print the task & comm but don't unwind.
            print_task_header(task)
            print(f"Unwind error: {str(e)}")
        print()


class Bt(CorelensModule):
    """
    Print a stack trace for a task, CPU, or set of tasks
    """

    name = "bt"

    # For normal reports, output on-CPU tasks, then D-state tasks
    default_args = [["-a"], ["-s", "D"]]

    # For verbose reports, output on-CPU tasks, followed by all tasks
    verbose_args = [["-a"], ["-A"]]

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        fmt = parser.add_argument_group(
            description="Options controlling the format of the backtrace",
        )
        fmt.add_argument(
            "--variables",
            "-v",
            action="store_true",
            help="show variable values, where possible",
        )
        op = parser.add_mutually_exclusive_group()
        op.add_argument(
            "pid_or_task",
            type=str,
            nargs="?",
            help="A PID, or address of a task_struct to unwind",
        )
        op.add_argument(
            "-c",
            "--cpu",
            type=int,
            help="Print a backtrace for CPU",
        )
        op.add_argument(
            "-a",
            "--all-on-cpu",
            action="store_true",
            help=(
                "Print all tasks currently executing on CPU. Not supported "
                "for live systems: ignored in that case."
            ),
        )
        op.add_argument(
            "--state",
            "-s",
            action="append",
            help=("Print all tasks on the system which are in STATE."),
        )
        op.add_argument(
            "--all-tasks",
            "-A",
            action="store_true",
            help="Print all tasks on the system",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        kwargs = {
            "show_vars": args.variables,
        }
        if args.cpu is not None:
            if prog.flags & ProgramFlags.IS_LIVE:
                print("On-CPU tasks are not supported for /proc/kcore")
            else:
                bt(prog, cpu=args.cpu, **kwargs)
        elif args.pid_or_task is not None:
            try:
                task = prog.thread(int(args.pid_or_task, 10)).object
            except ValueError:
                task_ptr = int(args.pid_or_task, 16)
                task = Object(prog, "struct task_struct *", value=task_ptr)
            bt(task, **kwargs)
        elif args.all_on_cpu:
            if prog.flags & ProgramFlags.IS_LIVE:
                print("On-CPU tasks not supported for /proc/kcore")
            else:
                print("On-CPU tasks:")
                print_online_bt(prog, **kwargs)
        elif args.state:
            print(f"Tasks in states {', '.join(args.state)}: ")
            print_all_bt(prog, states=args.state)
        elif args.all_tasks:
            print("All tasks:")
            print_all_bt(prog)
        else:
            print("error: select a task or group of tasks to backtrace")
