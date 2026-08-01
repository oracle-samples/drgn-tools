# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Tests for the mlx5 Corelens module."""
import argparse
from operator import itemgetter
from unittest.mock import patch

from drgn import FaultError

from drgn_tools import mlx5
from drgn_tools.mlx5_support import selection
from drgn_tools.mlx5_support.collect_device import DeviceRecord
from drgn_tools.mlx5_support.render import _render_qps
from tests.unittest_helpers import load_test_functions
from tests.unittest_helpers import parametrize
from tests.unittest_helpers import raises


class _FakeEnumType:
    def __init__(self, enumerators):
        self.enumerators = enumerators


class _FakeConstant:
    def __init__(self, value, type_):
        self.value = value
        self.type_ = type_

    def __int__(self):
        return self.value


class _FakeObject(argparse.Namespace):
    def __int__(self):
        return self.address_


class _FakeAggregateObject(_FakeObject):
    def __bool__(self):
        raise TypeError("cannot convert aggregate object to bool")


class _FakeProgram:
    def __init__(self):
        self.cache = {}
        self._constants = {}
        self._types = {}
        for enumerators in (
            (
                ("MLX5_CQE_OWNER_MASK", 1),
                ("MLX5_CQE_REQ", 0),
                ("MLX5_CQE_RESP_WR_IMM", 1),
                ("MLX5_CQE_RESP_SEND", 2),
                ("MLX5_CQE_RESP_SEND_IMM", 3),
                ("MLX5_CQE_RESP_SEND_INV", 4),
                ("MLX5_CQE_SIG_ERR", 12),
                ("MLX5_CQE_REQ_ERR", 13),
                ("MLX5_CQE_RESP_ERR", 14),
            ),
            (("MLX5_CQE_SYNDROME_LOCAL_LENGTH_ERR", 1),),
            (
                ("MLX5_OPCODE_NOP", 0),
                ("MLX5_OPCODE_RDMA_READ", 16),
                ("MLX5_OPCODE_SEND", 10),
                ("MLX5_OPCODE_TEST_NEW", 127),
            ),
            (
                ("MLX5_EVENT_TYPE_COMP", 0),
                ("MLX5_EVENT_TYPE_CQ_ERROR", 4),
            ),
            (("MLX5_CQ_ERROR_SYNDROME_CQ_OVERRUN", 1),),
            (
                ("IB_QPT_RC", 2),
                ("IB_QPT_RAW_PACKET", 8),
            ),
            (("IB_QPS_RESET", 0),),
        ):
            type_ = _FakeEnumType(enumerators)
            for name, value in enumerators:
                self._constants[name] = _FakeConstant(value, type_)
            if enumerators[0][0].startswith("IB_QPT_"):
                self._types["enum ib_qp_type"] = type_
            elif enumerators[0][0].startswith("IB_QPS_"):
                self._types["enum ib_qp_state"] = type_

    def constant(self, name):
        return self._constants[name]

    def type(self, name):
        return self._types[name]


_FAKE_PROG = _FakeProgram()


def _args(**overrides):
    values = dict.fromkeys(
        "dev netdev ip cqn eqn qpn sqn rqn maxqueues maxcq maxeq maxqp".split()
    )
    values.update(
        {
            name: False
            for name in """
        summary full queues cqs ib_cqs eth_cqs eqs qps dump_cqe dump_eqe
        dump_wqe json
        """.split()
        },
        _full_report=False,
        qp_creators=[],
        maxcqe=mlx5.MAX_DEFAULT_DESCRIPTOR_ENTRIES,
        maxeqe=mlx5.MAX_DEFAULT_DESCRIPTOR_ENTRIES,
        maxwqe=mlx5.MAX_DEFAULT_DESCRIPTOR_ENTRIES,
    )
    values.update(overrides)
    return argparse.Namespace(**values)


def _parser():
    parser = argparse.ArgumentParser()
    mlx5.Mlx5().add_args(parser)
    return parser


def _mapping_collector(monkeypatch):
    monkeypatch.setattr(
        mlx5, "has_member", lambda obj, name: hasattr(obj, name)
    )
    device = DeviceRecord(1)
    collector = mlx5.Mlx5Collector(_FAKE_PROG, _args())
    collector._collect_wq_summary = (
        lambda wq: wq if isinstance(wq, dict) else {}
    )
    return collector, device


def _fake_qp(address=0x1000, hw_qpn=7, **overrides):
    values = {
        "address_": address,
        "ibqp": _FakeObject(
            send_cq=None,
            recv_cq=None,
            qp_num=1,
            res=_FakeObject(user=0, task=None, kern_name=None),
        ),
        "qpn": hw_qpn,
        "trans_qp": _FakeObject(base=_FakeObject(mqp=_FakeObject(qpn=hw_qpn))),
        "type": 2,
        "state": 0,
        "flags": 0,
        "has_rq": 1,
        "is_rss": 0,
        "max_inline_data": 0,
        "db": _FakeObject(address_=address + 0x100),
        "buf": _FakeObject(address_=address + 0x200),
        "sq": {},
        "rq": {},
    }
    values.update(overrides)
    return _FakeObject(**values)


def _fake_ibdev(address, qp_list_address):
    return _FakeObject(
        address_=address,
        qp_list=_FakeObject(
            address_of_=lambda: _FakeObject(address_=qp_list_address)
        ),
    )


def test_summary_qp_count_sums_canonical_ib_device_lists(monkeypatch):
    collector = mlx5.Mlx5Collector(_FAKE_PROG, _args(summary=True))
    device = DeviceRecord(1)
    collector._iter_mlx5_ib_devices = lambda _mdev: iter(
        (_fake_ibdev(0x1000, 0x1100), _fake_ibdev(0x2000, 0x2200))
    )
    monkeypatch.setattr(
        mlx5,
        "list_count_nodes",
        lambda head: {0x1100: 3, 0x2200: 4}[int(head)],
    )

    assert collector._count_summary_qps(device) == 7


def test_summary_qp_count_deduplicates_ib_device_addresses(monkeypatch):
    collector = mlx5.Mlx5Collector(_FAKE_PROG, _args(summary=True))
    device = DeviceRecord(1)
    collector._iter_mlx5_ib_devices = lambda _mdev: iter(
        (_fake_ibdev(0x1000, 0x1100), _fake_ibdev(0x1000, 0x1100))
    )
    counted_heads = []

    def count_nodes(head):
        counted_heads.append(int(head))
        return 3

    monkeypatch.setattr(mlx5, "list_count_nodes", count_nodes)

    assert collector._count_summary_qps(device) == 3
    assert counted_heads == [0x1100]


def test_plain_summary_skips_placeholder_device_counts():
    collector = mlx5.Mlx5Collector(_FAKE_PROG, _args(summary=True))
    device = DeviceRecord(1)
    collector._collect_core_summary = lambda _mdev, _device: {}
    collector._collect_health = lambda _mdev: {}
    collector._collect_capabilities = lambda _mdev: {}

    def unexpected_device_counts(_device):
        raise AssertionError("summary should not calculate placeholder counts")

    collector._device_counts = unexpected_device_counts
    collector._collect_device_details(device)

    assert device.counts == {}


def test_qp_registry_keeps_distinct_objects_with_the_same_logical_qpn(
    monkeypatch,
):
    collector, device = _mapping_collector(monkeypatch)
    port_one = _fake_qp(0x1000, 198)
    port_two = _fake_qp(0x2000, 454)

    collector._record_qp(port_one, device, "mlx5_ib_qp_list")
    collector._record_qp(port_two, device, "mlx5_ib_qp_list")

    assert len(collector._qps) == 2
    assert {entry.record["qpn"] for entry in collector._qps.values()} == {1}
    assert {entry.record["hw_qpn"] for entry in collector._qps.values()} == {
        198,
        454,
    }


def test_qp_registry_merges_sources_aliases_and_preserves_first_work_queue(
    monkeypatch,
):
    collector, device = _mapping_collector(monkeypatch)
    first_sq = {"head": 4, "tail": 2}
    first = collector._record_qp(_fake_qp(sq=first_sq), device, "qp_list")
    merged = collector._record_qp(_fake_qp(), device, "qp_table", table_qpn=9)

    entry = collector._qps[mlx5._QpKey("0x1", "address", 0x1000)]
    assert first is merged is entry.record
    assert entry.record["owners"] == ["qp_list", "qp_table"]
    assert entry.record["qpn_aliases"] == [1, 7, 9]
    assert entry.dump_wq is entry.sq_wq is first_sq


def test_raw_packet_qp_progress_uses_nested_work_queues(monkeypatch):
    collector, device = _mapping_collector(monkeypatch)
    qp = _fake_qp(
        type=8,
        sq={"head": 1, "tail": 2},
        rq={"head": 3, "tail": 4},
        raw_packet_qp=_FakeObject(
            sq=_FakeObject(sq={"head": 11, "tail": 12}),
            rq=_FakeObject(rq={"head": 13, "tail": 14}),
        ),
    )

    record = collector._record_qp(qp, device, "qp_list")

    assert (
        record["sq_pc"],
        record["sq_cc"],
        record["rq_pc"],
        record["rq_cc"],
    ) == (11, 12, 13, 14)
    assert (
        record["sq_pc_source"],
        record["sq_cc_source"],
        record["rq_pc_source"],
        record["rq_cc_source"],
    ) == (
        "qp.raw_packet_qp.sq.sq.head",
        "qp.raw_packet_qp.sq.sq.tail",
        "qp.raw_packet_qp.rq.rq.head",
        "qp.raw_packet_qp.rq.rq.tail",
    )


def test_cq_registry_merges_metadata_and_preserves_first_work_queue(
    monkeypatch,
):
    collector, device = _mapping_collector(monkeypatch)
    key = ("0x1", 7)
    record = {"owner": "rq0", "owners": ["rq0"], "vector": None}
    collector._cqs[key] = mlx5._RingEntry(record, None)
    collector._mlx5e_cq_from_core_cq = lambda *_args: None
    collector._mlx5_ib_cq_from_core_cq = lambda *_args: None
    collector._mlx5_aso_cq_from_core_cq = lambda core, _device: core.aso
    first_wq = object()

    merged = collector._record_core_cq(
        _FakeObject(
            address_=0x1000,
            cqn=7,
            arm_sn=0,
            cons_index=0,
            vector=4,
            irqn=0,
            cqe_sz=64,
            aso=_FakeObject(address_=0x2000, wq=first_wq),
        ),
        device,
        "eq0",
    )
    collector._record_core_cq(
        _FakeObject(
            address_=0x1000,
            cqn=7,
            arm_sn=0,
            cons_index=0,
            vector=9,
            irqn=0,
            cqe_sz=64,
            aso=_FakeObject(address_=0x2000, wq=object()),
        ),
        device,
        "eq1",
    )

    entry = collector._cqs[key]
    assert merged is entry.record is record
    assert entry.wq is first_wq
    assert record["owners"] == ["rq0", "eq0", "eq1"]
    assert record["vector"] == 4


def test_cli_report_modes_selectors_and_limits():
    parser = _parser()
    args = parser.parse_args(
        [
            "--full",
            "--ib-cqs",
            "--eth-cqs",
            "--qp-creator",
            "kernel",
            "--qp-creator",
            "user",
            "--cqn",
            "0x20",
            "--max-cq",
            "4",
            "--max-cqe",
            "8",
        ]
    )

    assert args.full and args.ib_cqs and args.eth_cqs
    assert args.qp_creators == ["kernel", "user"]
    assert (args.cqn, args.maxcq, args.maxcqe) == (0x20, 4, 8)


@parametrize(
    ("arguments", "expected_error"),
    (
        (["--summary", "--full"], SystemExit),
        (["--qp-creator", "unknown"], SystemExit),
        (["--maxcq", "0"], ValueError),
    ),
)
def test_invalid_cli_values_are_rejected(arguments, expected_error):
    parser = _parser()
    with raises(expected_error):
        mlx5._validate_args(parser.parse_args(arguments))


def test_selection_defaults_are_idempotent():
    args = _args(cqn=7)

    selection._resolve_report_sections(args)
    first_application = vars(args).copy()
    selection._resolve_report_sections(args)

    assert vars(args) == first_application
    assert (args._full_report, args.cqs, args.eqs, args.qps) == (
        False,
        True,
        False,
        False,
    )


def test_default_report_mode_and_explicit_overrides(monkeypatch):
    monkeypatch.setattr(selection, "DEFAULT_REPORT_MODE", "summary")
    default_args = _args()
    selection._resolve_report_sections(default_args)
    assert default_args.summary and not default_args._full_report

    selected_args = _args(cqs=True)
    selection._resolve_report_sections(selected_args)
    assert not selected_args.summary and selected_args.cqs


@parametrize(
    ("queue", "expected"),
    (
        ({"kind": "sq", "number": "7"}, True),
        ({"kind": "icosq", "number": 7}, True),
        ({"kind": "rq", "number": 9}, True),
        ({"kind": "rq", "number": 7}, False),
        ({"kind": "sq", "number": 8}, False),
    ),
)
def test_explicit_wqe_queue_selector_matches_kind_and_number(queue, expected):
    args = _args(dump_wqe=True, sqn=7, rqn=9)
    assert selection._queue_matches_wqe_selector(queue, args) is expected


def test_automatic_wqe_queue_selection_is_scoped_to_device():
    args = _args(dump_wqe=True)
    selected = {("mlx5_0", "sqn", 7)}
    queue = {"kind": "sq", "number": 7}

    assert selection._queue_matches_wqe_selector(
        queue, args, selected, "mlx5_0"
    )
    assert not selection._queue_matches_wqe_selector(
        queue, args, selected, "mlx5_1"
    )


def test_cq_filters_match_only_requested_structure_families():
    cqs = [
        {"address_struct": "struct mlx5_ib_cq"},
        {"address_struct": "struct mlx5e_cq"},
        {"address_struct": "struct mlx5_core_cq"},
    ]

    assert all(selection._cq_matches_filter(cq, _args()) for cq in cqs)
    assert [
        selection._cq_matches_filter(cq, _args(ib_cqs=True)) for cq in cqs
    ] == [
        True,
        False,
        False,
    ]
    assert [
        selection._cq_matches_filter(cq, _args(eth_cqs=True)) for cq in cqs
    ] == [
        False,
        True,
        False,
    ]
    assert [
        selection._cq_matches_filter(cq, _args(ib_cqs=True, eth_cqs=True))
        for cq in cqs
    ] == [
        True,
        True,
        False,
    ]


def test_qp_creator_filters():
    qps = [
        {"device": "mlx5_0", "qpn": 1, "creator_type": "kernel"},
        {"device": "mlx5_0", "qpn": 2, "creator_type": "user"},
        {"device": "mlx5_1", "qpn": 3, "creator_type": None},
    ]

    assert selection._qp_matches_filter(qps[0], _args(qp_creators=["kernel"]))
    assert selection._qp_matches_filter(qps[1], _args(qp_creators=["user"]))
    assert not selection._qp_matches_filter(
        qps[2], _args(qp_creators=["kernel", "user"])
    )


def test_balanced_limits_round_robin_and_fully_drain_uneven_buckets():
    rows = [
        {"device": "mlx5_0", "id": 1},
        {"device": "mlx5_0", "id": 2},
        {"device": "mlx5_0", "id": 3},
        {"device": "mlx5_1", "id": 4},
        {"device": "mlx5_1", "id": 5},
        {"device": "mlx5_2", "id": 6},
    ]

    bucket = itemgetter("device")
    assert [
        row["id"] for row in selection._limit_balanced(rows, 4, bucket)
    ] == [1, 4, 6, 2]
    assert [
        row["id"] for row in selection._limit_balanced(rows, len(rows), bucket)
    ] == [1, 4, 6, 2, 5, 3]


@parametrize(
    "filter_args",
    ({"qpn": 20}, {"qp_creators": ["kernel"]}),
    ids=("qpn", "creator"),
)
def test_qp_filters_are_applied_before_row_limit(capsys, filter_args):
    report = {
        "devices": [],
        "qps": [
            {
                "device": "mlx5_0",
                "qpn": 10,
                "address": "0x1111",
                "creator_type": "user",
            },
            {
                "device": "mlx5_0",
                "qpn": 20,
                "address": "0x2222",
                "creator_type": "kernel",
            },
        ],
    }

    _render_qps(report, _args(qps=True, maxqp=1, **filter_args))
    output = capsys.readouterr().out

    assert "0x2222" in output
    assert "0x1111" not in output


def test_findings_are_classified_from_collected_values():
    collector = mlx5.Mlx5Collector(_FAKE_PROG, _args())
    cq = {"device": "0x1", "cqn": 7, "eqn": None, "irqn": 42}
    collector._cqs = {("0x1", 7): mlx5._RingEntry(cq, None)}
    device = DeviceRecord(1)
    device.summary = {"device_state": "INTERNAL_ERROR"}
    device.health = {"fatal_error": 1}
    dumps = [
        {
            "kind": "cqe",
            "device": "0x1",
            "selector_name": "cqn",
            "selector": 7,
            "entries": [
                {
                    "index": 1,
                    "status": "ready",
                    "opcode_value": 0xD,
                    "syndrome_display": "LOCAL_LENGTH_ERR(0x1)",
                }
            ],
        }
    ]

    findings = collector._analyze_findings([device], dumps)
    messages = "\n".join(finding["message"] for finding in findings)

    assert any(finding["severity"] == "HIGH" for finding in findings)
    assert "CQE error" in messages
    assert "no matching EQ linkage" in messages


def test_decode_response_cqe_from_hardware_layout():
    raw = bytearray(64)
    raw[2:4] = (77).to_bytes(2, "big")
    raw[32:36] = (0x12004567).to_bytes(4, "big")
    raw[44:48] = (1514).to_bytes(4, "big")
    raw[56:60] = (0x0A0ABCDE).to_bytes(4, "big")
    raw[60:62] = (123).to_bytes(2, "big")
    raw[63] = 0x21

    assert mlx5._decode_cqe(_FAKE_PROG, bytes(raw)) == {
        "owner_bit": 1,
        "opcode_value": 2,
        "opcode_display": "RESP_SEND(0x2)",
        "req_opcode_display": None,
        "wqe_id": 77,
        "srqn": 0x4567,
        "byte_count_display": 1514,
        "qpn": 0xABCDE,
        "wqe_counter": 123,
    }


def test_ib_wq_wrid_lookup_does_not_truth_test_embedded_struct():
    wq = _FakeAggregateObject(wqe_cnt=8, wrid=range(100, 108))

    assert mlx5._mlx5_ib_wq_wrid_at_counter(wq, 10) == (102, 2)


def test_gsi_wrid_lookup_skips_all_ones_sentinel():
    assert (
        mlx5._mlx5_ib_gsi_saved_wr_id(_FAKE_PROG, 0xFFFFFFFFFFFFFFFF) is None
    )


def test_gsi_wrid_lookup_ignores_unreadable_pointer():
    class _UnreadableCqe:
        @property
        def done(self):
            raise FaultError("missing memory", 0xFFFF888000001000)

    with patch.object(mlx5, "Object", return_value=_UnreadableCqe()):
        assert (
            mlx5._mlx5_ib_gsi_saved_wr_id(_FAKE_PROG, 0xFFFF888000001000)
            is None
        )


def test_decode_request_and_error_cqe_fields():
    request = bytearray(64)
    request[56:60] = (0x0A000087).to_bytes(4, "big")
    request[60:62] = (1536).to_bytes(2, "big")
    request[63] = 0x01
    decoded_request = mlx5._decode_cqe(_FAKE_PROG, bytes(request))

    error = bytearray(64)
    error[54:56] = bytes((0x9, 0x7))
    error[56:60] = (0x0A123456).to_bytes(4, "big")
    error[63] = 0xD1
    decoded_error = mlx5._decode_cqe(_FAKE_PROG, bytes(error))

    assert decoded_request["opcode_display"] == "REQ(0x0)"
    assert decoded_request["req_opcode_display"] == "SEND(0xa)"
    assert decoded_request["qpn"] == 0x87
    assert decoded_request["byte_count_display"] is None
    assert decoded_error["opcode_display"] == "REQ_ERR(0xd)"
    assert decoded_error["vendor_err_synd"] == "0x9"
    assert decoded_error["syndrome"] == "0x7"
    assert decoded_error["error_qpn"] == 0x123456


def test_decode_completion_and_error_eqe_fields():
    completion = bytearray(64)
    completion[1] = 0x00
    completion[3] = 0x03
    completion[56:60] = (0x1234).to_bytes(4, "big")
    completion[63] = 0x01

    error = bytearray(64)
    error[1] = 0x04
    error[32:36] = (0x100).to_bytes(4, "big")
    error[43] = 0xEE

    assert mlx5._decode_eqe(_FAKE_PROG, bytes(completion)) == {
        "owner_bit": 1,
        "type_value": 0,
        "type_display": "COMP(0x0)",
        "sub_type": "0x3",
        "cqn": 0x1234,
    }
    decoded_error = mlx5._decode_eqe(_FAKE_PROG, bytes(error))
    assert decoded_error["type_display"] == "CQ_ERROR(0x4)"
    assert decoded_error["cqn"] == 0x100
    assert decoded_error["syndrome"] == "0xee"


def test_decode_send_and_linked_receive_wqes():
    send = bytearray(64)
    send[0:4] = ((0x02 << 24) | (0x3456 << 8) | 0x0A).to_bytes(4, "big")
    send[4:8] = ((0x123456 << 8) | 0x18).to_bytes(4, "big")

    receive = bytearray(64)
    receive[16:20] = (2048).to_bytes(4, "big")
    receive[20:24] = (0xABCDEF).to_bytes(4, "big")
    receive[24:32] = (0x123456789ABCDEF0).to_bytes(8, "big")

    assert mlx5._decode_wqe(_FAKE_PROG, bytes(send)) == {
        "opcode_display": "SEND(0xa)",
        "wqe_index": 0x3456,
        "qpn": 0x123456,
        "ds": 0x18,
    }
    assert mlx5._decode_rq_wqe(bytes(receive), linked=True) == {
        "byte_count": 2048,
        "lkey": "0xabcdef",
        "dma_addr": "0x123456789abcdef0",
    }


def test_decode_uses_new_program_enum_values_without_a_code_table():
    send = bytearray(64)
    send[0:4] = (0x7F).to_bytes(4, "big")

    assert (
        mlx5._decode_wqe(_FAKE_PROG, bytes(send))["opcode_display"]
        == "TEST_NEW(0x7f)"
    )


def load_tests(loader, standard_tests, pattern):
    return load_test_functions(globals(), standard_tests)
