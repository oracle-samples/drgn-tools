# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
from typing import List
from typing import Tuple

from drgn import Object
from drgn import Program

from drgn_tools.corelens import CorelensModule

PAGE_SIZE = 4096


def init_ring_buffer_pages(prog: Program, cpu_buffer: Object) -> List[Object]:
    """
    Construct a linear page list from a cpu_buffer

    :param cpu_buffer: ``struct ring_buffer_per_cpu ``
    :return: List of ``struct buffer_page`` objects.
    """
    global PAGE_SIZE
    PAGE_SIZE = prog["PAGE_SIZE"].value_()

    pages_list = []
    head_page_addr = cpu_buffer.head_page.value_()
    if head_page_addr == 0:
        return []
    pages_list.append(head_page_addr)
    real_head_page_addr = cpu_buffer.head_page.value_()
    curr_addr = head_page_addr
    count = 0
    while True:
        if count >= cpu_buffer.nr_pages:
            break
        buffer_page_obj = Object(prog, "struct buffer_page", address=curr_addr)
        next_ptr = buffer_page_obj.list.next.value_()
        if next_ptr == 0:
            break
        # Check for flag bits
        if next_ptr & 0x3:
            unflagged = next_ptr & ~0x3
            real_head_page_addr = unflagged
            next_ptr = unflagged
        if next_ptr == head_page_addr:
            break
        pages_list.append(next_ptr)
        curr_addr = next_ptr
        count += 1

    # Find head_index
    head_index = 0
    for idx, page_addr in enumerate(pages_list):
        if page_addr == real_head_page_addr:
            head_index = idx
            break

    linear_pages = []
    reader_page_addr = cpu_buffer.reader_page.value_()
    commit_page_addr = cpu_buffer.commit_page.value_()

    if reader_page_addr:
        linear_pages.append(reader_page_addr)

    if reader_page_addr != commit_page_addr:
        n = len(pages_list)
        i = head_index
        while True:
            page_addr = pages_list[i]
            if page_addr != reader_page_addr:
                linear_pages.append(page_addr)
            if page_addr == commit_page_addr:
                break
            i = (i + 1) % n
            if i == head_index:
                break

    return linear_pages


def collect_cpu_data_blocks(
    prog: Program, linear_pages_all_cpus: List[List[Object]]
) -> Tuple[List[bytes], List[int]]:
    """
    Reads buffer_pages and converts them to bytes.

    :param linear_pages_all_cpus:  Lists of ``struct buffer_page``
    :return: A tuple of data_blocks list in bytes and their sizes
    """
    cpu_data_blocks = []
    cpu_data_sizes = []
    for cpu_linear_pages in linear_pages_all_cpus:
        data_bytes = bytearray()
        for page_addr in cpu_linear_pages:
            try:
                bp = Object(prog, "struct buffer_page", address=page_addr)
                raw_page_addr = bp.page.value_()
                if raw_page_addr == 0:
                    continue
                page_bytes = prog.read(raw_page_addr, PAGE_SIZE)
                data_bytes += page_bytes
            except Exception as e:
                print(
                    f"Exception collecting data for CPU page {hex(page_addr)}: {e}"
                )
                continue
        cpu_data_blocks.append(bytes(data_bytes))
        cpu_data_sizes.append(len(data_bytes))

    return cpu_data_blocks, cpu_data_sizes


def dump_trace_dat(
    prog: Program,
    linear_pages_all_cpus: List[List[Object]],
    output_path: str = "./trace.dat",
):
    """
    Formats and dumps ftrace buffer as trace.dat parsable by trace-cmd

    :param linear_pages_all_cpus:  Lists of ``struct buffer_page``
    :return: A tuple of data_blocks list in bytes and their sizes
    """
    is_little_endian = True
    num_cpus = len(linear_pages_all_cpus)
    data_offset = 16
    data_size = PAGE_SIZE - data_offset
    header_page_text = (
        "\tfield: u64 timestamp;\toffset:0;\tsize:8;\tsigned:0;\n"
        f"\tfield: local_t commit;\toffset:8;\tsize:8;\tsigned:1;\n"
        f"\tfield: int overwrite;\toffset:8;\tsize:1;\tsigned:1;\n"
        f"\tfield: char data;\toffset:{data_offset};\tsize:{data_size};\tsigned:0;\n"
    )
    header_event_text = (
        "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n"
        "\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n"
        "\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n"
        "\tfield:int common_pid;\t\toffset:4;\tsize:4;\tsigned:1;\n"
        "\tfield:int common_padding;\t\toffset:8;\tsize:4;\tsigned:1;\n"
    )
    header_page_bytes = header_page_text.encode("ascii")
    header_event_bytes = header_event_text.encode("ascii")

    cpu_data_blocks, cpu_data_sizes = collect_cpu_data_blocks(
        prog, linear_pages_all_cpus
    )

    with open(output_path, "wb") as f:
        # magic header
        magic = b"Dtracing6\0\0\0"
        magic_tag = 0x17 if is_little_endian else 0x18
        f.write(magic_tag.to_bytes(1, "little"))
        f.write(0x08.to_bytes(1, "little"))
        f.write(magic)
        f.write(PAGE_SIZE.to_bytes(4, "little" if is_little_endian else "big"))

        # Write header_page section
        f.write(b"header_page\0")
        f.write(
            len(header_page_bytes).to_bytes(
                8, "little" if is_little_endian else "big"
            )
        )
        f.write(header_page_bytes)

        # Write header_event section
        f.write(b"header_event\0")
        f.write(
            len(header_event_bytes).to_bytes(
                8, "little" if is_little_endian else "big"
            )
        )
        f.write(header_event_bytes)

        f.write(
            (0).to_bytes(4, "little" if is_little_endian else "big")
        )  # event format
        f.write(
            (0).to_bytes(4, "little" if is_little_endian else "big")
        )  # event systems
        f.write(
            (0).to_bytes(4, "little" if is_little_endian else "big")
        )  # kallsyms
        f.write(
            (0).to_bytes(4, "little" if is_little_endian else "big")
        )  # ftrace_printk
        f.write(
            (0).to_bytes(8, "little" if is_little_endian else "big")
        )  # cmdlines

        f.write(num_cpus.to_bytes(4, "little" if is_little_endian else "big"))
        mode_str = b"flyrecord\0".ljust(10, b"\0")[:10]
        f.write(mode_str)

        table_offset = f.tell()
        f.write(b"\x00" * (num_cpus * 16))

        # Align
        align = (-f.tell()) % PAGE_SIZE
        if align:
            f.write(b"\x00" * align)
        data_start_offset = f.tell()

        # Write data and record size
        cpu_offsets, cpu_data_sizes = [], []
        current_offset = data_start_offset
        for data in cpu_data_blocks:
            cpu_offsets.append(current_offset)
            if data:
                f.write(data)
                cpu_data_sizes.append(len(data))
                current_offset += len(data)
            else:
                cpu_data_sizes.append(0)

        # Seek back and write table
        f.seek(table_offset)
        for off, sz in zip(cpu_offsets, cpu_data_sizes):
            f.write(off.to_bytes(8, "little"))
            f.write(sz.to_bytes(8, "little"))

    print(
        f"trace.dat dumped with {num_cpus} CPUs and {sum(cpu_data_sizes)} total bytes of data."
    )


def dump_ftrace(prog: Program) -> None:
    """Dumps ftrace buffer."""
    try:
        trace_array = prog["global_trace"]
    except KeyError:
        print("Error: global_trace symbol not found.")
        return
    try:
        trace_buf = trace_array.array_buffer.buffer
    except AttributeError:
        print("Error: Only UEK7 and above is supported.")
        return
    if trace_buf.value_() == 0:
        print("No ftrace trace buffer found")
        return

    cpu_count = int(trace_buf.cpus)
    linear_pages_all_cpus = []
    for cpu in range(cpu_count):
        cpu_buf = trace_buf.buffers[cpu]
        linear_pages = init_ring_buffer_pages(prog, cpu_buf)
        linear_pages_all_cpus.append(linear_pages)
    dump_trace_dat(prog, linear_pages_all_cpus)


class Ftrace(CorelensModule):
    """
    Dumps ftrace buffer
    """

    name = "ftrace"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        dump_ftrace(prog)
