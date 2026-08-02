# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Tests for mlx5 descriptor handling."""
import unittest

from drgn import FaultError

from drgn_tools import mlx5
from drgn_tools.mlx5_support.dumps import _annotate_owner_status


class _EnumType:
    def __init__(self, enumerators):
        self.enumerators = enumerators


class _Constant:
    def __init__(self, value, type_):
        self.value = value
        self.type_ = type_

    def __int__(self):
        return self.value


class _Program:
    def __init__(self):
        self.cache = {}
        self.constants = {}
        groups = (
            (
                ("MLX5_CQE_REQ", 0),
                ("MLX5_CQE_RESP_SEND", 2),
                ("MLX5_CQE_REQ_ERR", 13),
            ),
            (("MLX5_CQE_SYNDROME_LOCAL_LENGTH_ERR", 1),),
            (("MLX5_OPCODE_NOP", 0), ("MLX5_OPCODE_SEND", 10)),
            (
                ("MLX5_EVENT_TYPE_COMP", 0),
                ("MLX5_EVENT_TYPE_CQ_ERROR", 4),
            ),
            (("MLX5_CQ_ERROR_SYNDROME_CQ_OVERRUN", 1),),
        )
        for enumerators in groups:
            type_ = _EnumType(enumerators)
            for name, value in enumerators:
                self.constants[name] = _Constant(value, type_)

    def constant(self, name):
        return self.constants[name]


class _Struct:
    def __init__(self, address=0, type_name="struct test", **members):
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


class _EmbeddedWq(_Struct):
    def __bool__(self):
        raise TypeError("cannot convert an embedded struct to bool")


class _MemoryProgram:
    def __init__(self, blocks):
        self.blocks = blocks

    def __getitem__(self, name):
        if name != "PAGE_SIZE":
            raise KeyError(name)
        return 128

    def read(self, address, length):
        for base, data in self.blocks.items():
            offset = address - base
            if 0 <= offset and offset + length <= len(data):
                return data[offset : offset + length]
        raise FaultError("test memory fault", address)


class TestMlx5(unittest.TestCase):
    def test_hardware_descriptor_decoding(self):
        prog = _Program()
        cqe = bytearray(64)
        cqe[2:4] = (77).to_bytes(2, "big")
        cqe[44:48] = (1514).to_bytes(4, "big")
        cqe[56:60] = (0x0A0ABCDE).to_bytes(4, "big")
        cqe[60:62] = (123).to_bytes(2, "big")
        cqe[63] = 0x21
        decoded = mlx5._decode_cqe(prog, bytes(cqe))
        self.assertEqual(decoded["opcode_display"], "RESP_SEND(0x2)")
        self.assertEqual(decoded["qpn"], 0xABCDE)
        self.assertEqual(decoded["wqe_counter"], 123)
        self.assertEqual(decoded["byte_count_display"], 1514)

        eqe = bytearray(64)
        eqe[1] = 0
        eqe[56:60] = (0x1234).to_bytes(4, "big")
        eqe[63] = 1
        self.assertEqual(mlx5._decode_eqe(prog, bytes(eqe))["cqn"], 0x1234)

        send = bytearray(64)
        send[0:4] = ((0x3456 << 8) | 0x0A).to_bytes(4, "big")
        send[4:8] = ((0x123456 << 8) | 0x18).to_bytes(4, "big")
        self.assertEqual(
            mlx5._decode_wqe(prog, bytes(send)),
            {
                "opcode_display": "SEND(0xa)",
                "wqe_index": 0x3456,
                "qpn": 0x123456,
                "ds": 0x18,
            },
        )

    def test_cqe_owner_and_pollability(self):
        cases = (
            (0, 0x2, 0, 0, "ready", None),
            (0, 0xF, 0, 0, "not-ready", "invalid-sentinel"),
            (1, 0x2, 0, 0, "not-ready", "owner-mismatch"),
            (0, 0x2, 9, 10, "not-ready", "consumed"),
        )
        for owner, opcode, absolute, consumer, status, reason in cases:
            with self.subTest(status=status, reason=reason):
                decoded = {
                    "owner_bit": owner,
                    "opcode_value": opcode,
                    "status": "ok",
                }
                _annotate_owner_status(decoded, absolute, 64, "cqe", consumer)
                self.assertEqual(decoded["status"], status)
                self.assertEqual(decoded.get("not_ready_reason"), reason)

    def test_fragmented_rdma_cq_and_read_fault(self):
        fragments = _Struct(entries=[_Struct(buf=0x1000), _Struct(buf=0x5000)])
        fbc = _Struct(
            frags=fragments,
            sz_m1=63,
            log_sz=6,
            log_stride=6,
            log_frag_strides=1,
            frag_sz_m1=1,
            strides_offset=0,
        )
        cq_buf = _Struct(
            type_name="struct mlx5_ib_cq_buf",
            fbc=fbc,
            nent=4,
            cqe_size=64,
            frag_buf=_Struct(size=256),
        )
        blocks = {
            0x1000: bytes(64) + bytes([1]) + bytes(63),
            0x5000: bytes([2]) + bytes(63) + bytes([3]) + bytes(63),
        }
        collector = object.__new__(mlx5.Mlx5Collector)
        collector.prog = _MemoryProgram(blocks)
        entries = collector._dump_ring(
            cq_buf,
            max_entries=4,
            decode=lambda raw: {"value": raw[0]},
            ring_size=4,
            consumer_index=2,
            descriptor_kind="cqe",
        )
        self.assertEqual([entry["value"] for entry in entries], [0, 1, 2, 3])
        self.assertEqual(
            [entry["address"] for entry in entries],
            ["0x1000", "0x1040", "0x5000", "0x5040"],
        )

        collector.prog = _MemoryProgram({0x1000: blocks[0x1000]})
        entries = collector._dump_ring(
            cq_buf,
            max_entries=4,
            decode=lambda raw: {"value": raw[0]},
            ring_size=4,
            consumer_index=2,
            descriptor_kind="cqe",
        )
        self.assertEqual(
            [entry["status"] for entry in entries[2:]],
            ["read-unavailable", "read-unavailable"],
        )

    def test_embedded_wq_maps_cqe_to_wr_id(self):
        collector = object.__new__(mlx5.Mlx5Collector)
        collector.prog = _Program()
        wq = _EmbeddedWq(wqe_cnt=8, wrid=list(range(100, 108)))
        qp = mlx5._QpEntry({"qpn": 7, "hw_qpn": 7, "creator_type": "user"}, wq)
        entries = [
            {
                "status": "ready",
                "opcode_value": 0,
                "qpn": 7,
                "wqe_counter": 10,
            }
        ]

        self.assertEqual(
            collector._annotate_ib_cqe_wr_ids(
                {"address_struct": "struct mlx5_ib_cq"}, entries, [qp]
            ),
            1,
        )
        self.assertEqual(entries[0]["wr_id"], 102)
        self.assertEqual(entries[0]["wr_id_index"], 2)

    def test_firmware_falls_back_when_mmio_is_unreadable(self):
        class UnreadableIseg:
            @property
            def fw_rev(self):
                raise FaultError("missing MMIO page", 0x1000)

        collector = object.__new__(mlx5.Mlx5Collector)
        mdev = _Struct(address=1, iseg=UnreadableIseg())
        device = _Struct(
            mdev=mdev,
            ibdev=_Struct(
                ib_dev=_Struct(
                    attrs=_Struct(fw_ver=(22 << 32) | (34 << 16) | 1014)
                )
            ),
        )

        self.assertEqual(collector._collect_fw_version(device), "22.34.1014")
        device.ibdev = None
        self.assertEqual(collector._collect_fw_version(device), "unavailable")


if __name__ == "__main__":
    unittest.main()
