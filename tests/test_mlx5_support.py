# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Tests for mlx5 ring layout helpers."""
from drgn import FaultError

from drgn_tools import mlx5
from drgn_tools.mlx5_support import dumps
from tests.unittest_helpers import load_test_functions


class Struct:
    """Test object with the member access used by the support helpers."""

    def __init__(self, address=None, type_name="struct test", **members):
        self.address_ = address
        self.type_ = self
        self._type_name = type_name
        self.__dict__.update(members)

    def __int__(self):
        return self.address_

    def __str__(self):
        return self._type_name

    def type_name(self):
        return self._type_name

    def member_(self, name):
        try:
            return getattr(self, name)
        except AttributeError:
            raise LookupError(name)

    def __getitem__(self, index):
        return self.entries[index]

    def read_(self):
        return self


class MemoryProgram:
    def __init__(self, blocks, page_size=256):
        self.blocks = blocks
        self.page_size = page_size
        self.reads = []

    def __getitem__(self, name):
        if name != "PAGE_SIZE":
            raise KeyError(name)
        return self.page_size

    def read(self, address, length):
        self.reads.append((address, length))
        for base, data in self.blocks.items():
            offset = address - base
            if 0 <= offset and offset + length <= len(data):
                return data[offset : offset + length]
        raise FaultError("test memory fault", address)


def _fbc(frags, **members):
    return Struct(
        frags=frags,
        sz_m1=members.pop("sz_m1", 7),
        log_sz=members.pop("log_sz", 3),
        log_stride=members.pop("log_stride", 6),
        log_frag_strides=members.pop("log_frag_strides", 2),
        frag_sz_m1=members.pop("frag_sz_m1", 3),
        strides_offset=members.pop("strides_offset", 0),
        **members,
    )


def _collector(prog):
    collector = object.__new__(mlx5.Mlx5Collector)
    collector.prog = prog
    return collector


def _wq(*fragment_bases, **fbc_fields):
    frags = Struct(
        address=0x9000,
        entries=[Struct(buf=base) for base in fragment_bases],
    )
    return Struct(fbc=_fbc(frags, **fbc_fields))


def test_wq_layout_summary_uses_only_canonical_fbc_fields():
    frags = Struct(address=0x2000, entries=[Struct(buf=0x3000)])
    fbc = _fbc(frags, address=0x1100)
    wq = Struct(address=0x1000, type_name="struct mlx5_cqwq", fbc=fbc)

    assert dumps._wq_layout_summary(wq) == {
        "wq": "0x1000",
        "wq_type": "struct mlx5_cqwq",
        "fbc": "0x1100",
        "frags": "0x2000",
        "frag0_buf": "0x3000",
        "sz_m1": 7,
        "log_sz": 3,
        "log_stride": 6,
        "stride_bytes": 64,
        "log_frag_strides": 2,
        "frag_sz_m1": 3,
        "strides_offset": 0,
    }


def test_dump_ring_caches_each_fragment_for_a_centered_window():
    blocks = {
        0x1000: b"".join(bytes([index]) + bytes(63) for index in range(4)),
        0x5000: b"".join(bytes([index]) + bytes(63) for index in range(4, 8)),
    }
    collector = _collector(MemoryProgram(blocks))
    wq = _wq(0x1000, 0x5000)

    entries = collector._dump_ring(
        wq,
        max_entries=6,
        ring_size=8,
        consumer_index=4,
        decode=lambda raw: {"decoded_index": raw[0]},
        descriptor_kind="eqe",
    )

    fields = ("index", "decoded_index", "address", "consumer_marker")
    assert [
        tuple(entry.get(field) for field in fields) for entry in entries
    ] == [
        (1, 1, "0x1040", None),
        (2, 2, "0x1080", None),
        (3, 3, "0x10c0", None),
        (4, 4, "0x5000", "cons_index"),
        (5, 5, "0x5040", None),
        (6, 6, "0x5080", None),
    ]
    assert collector.prog.reads == [(0x1000, 256), (0x5000, 256)]


def test_dump_ring_caches_fragments_during_variable_wqe_walk():
    blocks = {
        0x1000: bytes(256),
        0x5000: bytes(256),
    }
    collector = _collector(MemoryProgram(blocks))
    wq = _wq(0x1000, 0x5000)

    entries = collector._dump_ring(
        wq,
        max_entries=4,
        decode=lambda _raw: {"ds": 8},
        ring_size=8,
        consumer_index=0,
        variable_wqe_stride=True,
    )

    assert [entry["index"] for entry in entries] == [0, 2, 4, 6]
    assert collector.prog.reads == [(0x1000, 256), (0x5000, 256)]


def test_dump_ring_reads_only_the_offset_cq_fragment_span():
    fragment = bytearray(256)
    fragment[64] = 1
    fragment[192] = 2
    collector = _collector(
        MemoryProgram({0x8080: bytes(fragment)}, page_size=4096)
    )
    wq = _wq(
        0x8000,
        sz_m1=1,
        log_sz=1,
        log_stride=7,
        log_frag_strides=5,
        frag_sz_m1=31,
        strides_offset=1,
    )

    entries = collector._dump_ring(
        wq,
        max_entries=2,
        decode=lambda raw: {"value": raw[0]},
        ring_size=2,
        consumer_index=1,
        descriptor_kind="cqe",
    )

    assert [entry["value"] for entry in entries] == [1, 2]
    assert [entry["address"] for entry in entries] == ["0x80c0", "0x8140"]
    assert collector.prog.reads == [(0x8080, 256)]


def test_dump_ring_checks_normal_fbc_size_before_reading():
    collector = _collector(MemoryProgram({}))
    wq = _wq(0x1000)

    entries = collector._dump_ring(
        wq,
        max_entries=1,
        decode=lambda _raw: {},
        ring_size=16,
        consumer_index=0,
    )

    assert entries == [{"index": None, "status": "layout-unavailable"}]
    assert collector.prog.reads == []


def test_dump_ring_uses_ib_cq_allocation_size_and_contains_read_faults():
    frags = Struct(address=0x9000, entries=[Struct(buf=0x1000)])
    # The UEK6/7/8 RDMA CQ allocator initializes FBC log_sz from cqe_size,
    # while nent and frag_buf.size describe the allocated ring.
    cq_buf = Struct(
        type_name="struct mlx5_ib_cq_buf",
        fbc=_fbc(frags, sz_m1=63, log_sz=6),
        nent=2,
        cqe_size=64,
        frag_buf=Struct(size=128),
    )
    collector = _collector(MemoryProgram({}))

    entries = collector._dump_ring(
        cq_buf,
        max_entries=1,
        decode=lambda _raw: {},
        ring_size=2,
        consumer_index=1,
        descriptor_kind="cqe",
    )

    assert entries == [
        {
            "index": 1,
            "_absolute_index": 1,
            "status": "read-unavailable",
            "consumer_marker": "cons_index",
        }
    ]
    assert collector.prog.reads == [(0x1000, 128)]


def load_tests(loader, standard_tests, pattern):
    return load_test_functions(globals(), standard_tests)
