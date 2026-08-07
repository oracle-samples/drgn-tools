# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Tests for mlx5 descriptor handling."""
import unittest

from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn import TypeEnumerator
from drgn import TypeMember

from drgn_tools import mlx5


def _test_program():
    prog = Program()
    u8 = prog.int_type("u8", 1, False, "little")
    be16 = prog.int_type("__be16", 2, False, "little")
    be32 = prog.int_type("__be32", 4, False, "little")
    types = {
        "mlx5_cqe64": prog.struct_type(
            "mlx5_cqe64",
            64,
            [
                TypeMember(be16, "wqe_id", 16),
                TypeMember(be32, "byte_cnt", 352),
                TypeMember(be32, "sop_drop_qpn", 448),
                TypeMember(be16, "wqe_counter", 480),
                TypeMember(u8, "op_own", 504),
            ],
        ),
        "mlx5_err_cqe": prog.struct_type(
            "mlx5_err_cqe",
            64,
            [
                TypeMember(u8, "vendor_err_synd", 432),
                TypeMember(u8, "syndrome", 440),
                TypeMember(be32, "s_wqe_opcode_qpn", 448),
                TypeMember(be16, "wqe_counter", 480),
                TypeMember(u8, "op_own", 504),
            ],
        ),
    }
    prog.register_type_finder(
        "test",
        lambda prog, kinds, name, filename: types.get(name),
        enable_index=0,
    )

    constants = {}
    int_type = prog.int_type("int", 4, True, "little")
    groups = (
        (
            ("MLX5_CQE_REQ", 0),
            ("MLX5_CQE_RESP_SEND", 2),
            ("MLX5_CQE_REQ_ERR", 13),
        ),
        (("MLX5_CQE_SYNDROME_LOCAL_LENGTH_ERR", 1),),
        (("MLX5_OPCODE_NOP", 0), ("MLX5_OPCODE_SEND", 10)),
        (("MLX5_EVENT_TYPE_COMP", 0),),
    )
    for enumerators in groups:
        type_ = prog.enum_type(
            None,
            int_type,
            [TypeEnumerator(name, value) for name, value in enumerators],
        )
        for name, value in enumerators:
            constants[name] = Object(prog, type_, value)
    prog.register_object_finder(
        "test",
        lambda prog, name, flags, filename: constants.get(name),
        enable_index=0,
    )
    return prog


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
        prog = _test_program()
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

        cqe[44:48] = (0x0001003C).to_bytes(4, "big")
        decoded = mlx5._decode_cqe(prog, bytes(cqe), striding_rq=True)
        self.assertEqual(decoded["byte_count_display"], 60)

        cqe[63] = 0x0D
        self.assertEqual(
            mlx5._decode_cqe(prog, bytes(cqe)),
            {"owner_bit": 1, "opcode_display": "COMPRESSED"},
        )

        eqe = bytearray(64)
        eqe[1] = 0
        eqe[56:60] = (0x1234).to_bytes(4, "big")
        eqe[63] = 1
        self.assertEqual(mlx5._decode_eqe(prog, bytes(eqe))["cqn"], 0x1234)

        eqe[56:60] = (0xAB001234).to_bytes(4, "big")
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

        receive = bytearray(16)
        receive[0:4] = (0x800005F2).to_bytes(4, "big")
        self.assertEqual(
            mlx5._decode_rq_wqe(bytes(receive))["byte_count"], 1522
        )


if __name__ == "__main__":
    unittest.main()
