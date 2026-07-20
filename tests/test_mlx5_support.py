# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Tests for mlx5 compatibility and ring layout helpers."""
import argparse

from drgn_tools import mlx5
from drgn_tools.mlx5_support import compat
from drgn_tools.mlx5_support import dumps
from tests.unittest_helpers import load_test_functions
from tests.unittest_helpers import parametrize


class Struct:
    """Test object with the member access used by the support helpers."""

    def __init__(self, address=None, **members):
        self.address_ = address
        self.members = members

    def member_(self, name):
        try:
            return self.members[name]
        except KeyError:
            raise LookupError(name)


class MemoryProgram:
    def __init__(self, blocks):
        self.blocks = blocks

    def read(self, address, length):
        return self.blocks[address][:length]


def test_member_paths_use_the_first_readable_value_and_report_its_source():
    obj = Struct(
        unusable="not-an-integer",
        nested=Struct(value=17),
        zero=0,
    )

    assert compat._safe_member_path(obj, ["nested", "value"]) == 17
    assert compat._safe_member_path(obj, ["missing", "value"]) is None
    assert (
        compat._first_member_path(
            obj, (["missing"], ["zero"], ["nested", "value"])
        )
        == 0
    )
    assert compat._first_member_path_with_source(
        obj,
        (
            ("missing", ["missing"]),
            ("nested value", ["nested", "value"]),
            ("later zero", ["zero"]),
        ),
    ) == (17, "nested value")
    assert (
        compat._first_int_path(
            obj, (["unusable"], ["nested", "value"], ["zero"])
        )
        == 17
    )
    assert compat._first_int_path_with_source(
        obj,
        (
            ("bad", ["unusable"]),
            ("nested integer", ["nested", "value"]),
            ("later zero", ["zero"]),
        ),
    ) == (17, "nested integer")


@parametrize(
    ("wq", "entry_bytes", "expected"),
    (
        (Struct(sz_m1=7, fbc=Struct(log_sz=5), wqe_cnt=40), 64, 8),
        (Struct(fbc=Struct(log_sz=5)), 64, 32),
        (Struct(wqe_cnt=40), 64, 40),
        (Struct(size=4096), 64, 64),
        (Struct(frag_buf=Struct(size=2048)), 64, 32),
        (Struct(), 64, None),
    ),
    ids=(
        "sz-m1",
        "log-size",
        "entry-count",
        "byte-size",
        "frag-byte-size",
        "unknown",
    ),
)
def test_ring_size_uses_kernel_layout_fallbacks_in_order(
    wq, entry_bytes, expected
):
    assert dumps._ring_size(wq, entry_bytes) == expected


@parametrize(
    ("wq", "expected"),
    (
        (Struct(log_stride=7, fbc=Struct(log_stride=6), stride=32), 128),
        (Struct(fbc=Struct(log_stride=6)), 64),
        (Struct(log_stride=40, stride_bytes=96), 96),
        (Struct(), None),
    ),
    ids=("direct-log", "nested-log", "explicit-stride", "unknown"),
)
def test_ring_stride_uses_log_stride_before_explicit_byte_stride(wq, expected):
    assert dumps._ring_stride_bytes(wq) == expected


def test_ring_entry_address_handles_direct_and_single_fragment_layouts():
    direct = Struct(log_stride=6, buf=0x1000, fbc=Struct(buf=0x9000))
    cqe_128 = Struct(fbc=Struct(log_stride=7), frag_buf=Struct(buf=0x2000))
    single_fragment = Struct(
        fbc=Struct(frags=[Struct(buf=0x3000)], log_stride=6)
    )

    assert dumps._ring_entry_address(direct, 3) == 0x10C0
    assert dumps._ring_entry_address(cqe_128, 2, cqe_mode=True) == 0x2140
    assert dumps._ring_entry_address(single_fragment, 3) == 0x30C0


def test_ring_entry_address_selects_the_right_fragment_and_offset():
    wq = Struct(
        fbc=Struct(
            frags=[Struct(buf=0x1000), Struct(buf=0x5000)],
            log_stride=6,
            log_frag_strides=2,
            frag_sz_m1=3,
            strides_offset=1,
        )
    )

    # index 4 plus the stride offset selects fragment 1, entry 1.
    assert dumps._ring_entry_address(wq, 4) == 0x5040


def test_plain_fragment_address_crosses_pages_wraps_and_honors_npages():
    frag_buf = Struct(
        frags=[
            Struct(buf=0x1000),
            Struct(buf=0x5000),
            Struct(buf=0x9000),
        ],
        size=8192,
        page_shift=12,
        npages=2,
    )

    assert dumps._plain_frag_buf_entry_address(frag_buf, 65) == 0x5040
    assert dumps._plain_frag_buf_entry_address(frag_buf, 128) == 0x1000

    oversized = Struct(
        frags=frag_buf.members["frags"],
        size=12288,
        page_shift=12,
        npages=2,
    )
    assert dumps._plain_frag_buf_entry_address(oversized, 130) is None
    assert dumps._ring_entry_address(Struct(frag_buf=frag_buf), 65) == 0x5040


def test_dump_ring_reads_a_consumer_centered_window_through_shared_layout_helpers():
    blocks = {
        0x1000 + index * 64: bytes([index]) + bytes(63) for index in range(4)
    }
    collector = mlx5.Mlx5Collector(
        MemoryProgram(blocks),
        argparse.Namespace(
            _full_report=False, summary=False, full=False, walk_limit=None
        ),
    )
    wq = Struct(sz_m1=3, log_stride=6, buf=0x1000)

    entries = collector._dump_ring(
        wq,
        max_entries=3,
        default_len=64,
        decode=lambda raw: {"decoded_index": raw[0]},
        known_consumer_index=2,
        owner_mode="eqe",
        around_consumer=True,
    )

    assert [entry["index"] for entry in entries] == [1, 2, 3]
    assert [entry["decoded_index"] for entry in entries] == [1, 2, 3]
    assert [entry["address"] for entry in entries] == [
        "0x1040",
        "0x1080",
        "0x10c0",
    ]
    assert [entry.get("consumer_marker") for entry in entries] == [
        None,
        "cons_index",
        None,
    ]


def load_tests(loader, standard_tests, pattern):
    return load_test_functions(globals(), standard_tests)
