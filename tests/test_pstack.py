# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
import gzip
import sys
from subprocess import PIPE
from subprocess import Popen

import pytest
from drgn import Architecture
from drgn.helpers.linux import task_state_to_char
from drgn.helpers.linux.pid import find_task

from drgn_tools import pstack
from drgn_tools.task import task_cpu


pytestmark = [
    # Only test UEK5+
    pytest.mark.kver_min("4.14"),
]


@pytest.fixture
def sleeping_proc():
    proc = Popen(
        [sys.executable, "-c", "input('ready')"],
        stdout=PIPE,
        stdin=PIPE,
    )
    # Wait until it has printed the prompt, indicating it's likely sleeping
    # waiting for input, and so the stack should be stable.
    data = bytearray()
    while b"ready" not in data:
        data.extend(proc.stdout.read(1))
    try:
        yield proc
    finally:
        proc.terminate()
        proc.wait()


@pytest.mark.skip_vmcore("*")  # live only
def test_task_saved_pt_regs(prog, sleeping_proc):
    regs = pstack.task_saved_pt_regs(find_task(prog, sleeping_proc.pid))

    # We can verify that the stack pointer points into a stack region of the
    # task, and that the instruction pointer points into a mapped object file.
    if prog.platform.arch == Architecture.X86_64:
        pc = int(regs.ip)
        sp = int(regs.sp)
    else:
        pc = int(regs.pc)
        sp = int(regs.sp)

    pc_found = sp_found = False
    for line in open(f"/proc/{sleeping_proc.pid}/maps", "r"):
        fields = line.split()
        start = int(fields[0].split("-")[0], 16)
        end = int(fields[0].split("-")[1], 16)
        permission = fields[1]
        file = fields[-1]

        if start <= pc < end:
            pc_found = True
            # It must be an ELF file:
            assert open(file, "rb").read(4) == b"\x7fELF"
            # It must be an executable mapping:
            assert "x" in permission
        if start <= sp < end:
            sp_found = True
            # It must be in a stack region
            assert file == "[stack]"

    assert pc_found and sp_found


def do_test_task_running_pt_regs(prog, task):
    # Really, all task_running_pt_regs() does is take the registers dict from
    # the top stack frame, and convert it into a "struct pt_regs" according to
    # the particular architecture. So we can test its functionality on a kernel
    # stack, rather than a user stack. Verify that the original stack trace
    # matches the stack trace we get from the generated pt_regs.
    orig_trace = prog.stack_trace(task)
    pt_regs = pstack.task_running_pt_regs(orig_trace)
    new_trace = prog.stack_trace(pt_regs)
    assert len(orig_trace) == len(new_trace)
    for orig, new in zip(orig_trace, new_trace):
        assert orig.pc == new.pc


@pytest.mark.skip_vmcore("*")  # live only
def test_task_running_pt_regs_live(prog, sleeping_proc):
    task = find_task(prog, sleeping_proc.pid)
    do_test_task_running_pt_regs(prog, task)


@pytest.mark.skip_live
def test_task_running_pt_regs_vmcore(prog, sleeping_proc):
    task = find_task(prog, 1)
    do_test_task_running_pt_regs(prog, task)


def build_args(
    output,
    max_stack_bytes=1024 * 1024,
    comm=None,
    state=None,
    all=False,
    online=False,
    pid=None,
):
    if comm is not None:
        comm = []
    if state is not None:
        state = []
    if pid is not None:
        state = []

    return argparse.Namespace(
        output=output,
        max_stack_bytes=max_stack_bytes,
        comm=comm,
        state=state,
        all=all,
        online=online,
        pid=pid,
    )


@pytest.mark.skip_vmcore("*")  # live only
def test_dump(prog, tmp_path, sleeping_proc):
    pid = sleeping_proc.pid
    pstack.dump(prog, build_args(tmp_path / "dump", pid=[pid]))
    with gzip.open(tmp_path / "dump", "rb") as f:
        magic = f.read(8)
        assert magic == b"pstack\x00\x01"

        metadata = pstack.read_json_object(f)
        assert metadata == {"page_size": int(prog["PAGE_SIZE"])}

        task_meta = pstack.read_json_object(f)
        assert task_meta["pid"] == sleeping_proc.pid
        assert task_meta["comm"] == open(f"/proc/{pid}/comm").read().strip()
        assert not task_meta["kernel"]
        assert len(task_meta["threads"]) == 1

        # Get executables from /proc/{pid}/maps and compare with the metadata
        executables = []
        start_addr = 0
        for line in open(f"/proc/{pid}/maps"):
            fields = line.split(maxsplit=5)
            if len(fields) != 6:
                continue
            filename = fields[-1].rstrip()
            if filename[0] == "[":
                continue
            if int(fields[2], 16) == 0:
                start_addr = int(fields[0].split("-")[0], 16)
            if "x" in fields[1] and start_addr != 0:
                executables.append((filename, start_addr))
                start_addr = 0
        assert len(executables) == len(task_meta["mm"])
        for filename, start_addr in executables:
            assert task_meta["mm"][filename][0] == start_addr

        # Now ensure the thread metadata is correct:
        thread = task_meta["threads"][0]
        assert thread["tid"] == pid
        assert thread["comm"] == task_meta["comm"]
        assert thread["kstack"] == str(prog.stack_trace(pid))
        assert thread["cpu"] == task_cpu(find_task(prog, pid))
        assert not thread["on_cpu"]
        assert thread["state"] == "S"

        # Now ensure we have some stack data. Not too much verification of
        # correctness here, just want to ensure it is done correctly.
        end = b"\xff" * 8
        pgsize = int(prog["PAGE_SIZE"])
        while True:
            header = f.read(8)
            assert len(header) == 8
            if header == end:
                break
            assert len(f.read(pgsize)) == pgsize

        # EOF
        assert f.read() == b""


@pytest.mark.skip_vmcore("*")  # live only
def test_read_dump(prog, tmp_path, sleeping_proc, capsys):
    pid = sleeping_proc.pid
    pstack.dump(prog, build_args(tmp_path / "dump", pid=[pid]))
    capsys.readouterr()

    pstack.dump_print(tmp_path / "dump")
    stdout_from_dump = capsys.readouterr().out
    pstack.pstack_print_process(find_task(prog, pid))
    print()
    stdout_from_pstack = capsys.readouterr().out
    assert stdout_from_dump == stdout_from_pstack


def test_get_tasks_pid(prog):
    args = build_args("IGNORE", pid=[1])
    result = pstack.get_tasks(prog, args)
    assert len(result) == 1
    assert result[0].pid.value_() == 1


@pytest.mark.skip_live  # this will flake on live systems
def test_get_tasks_state_and_pid(prog):
    args = build_args("IGNORE", pid=[1], state=["R"])
    result = pstack.get_tasks(prog, args)
    found_init = False
    for task in result:
        assert task_state_to_char(task) == "R" or task.pid.value_() == 1
        found_init = found_init or task.pid.value_() == 1
    assert found_init
