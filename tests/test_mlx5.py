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
        dict.fromkeys(
            """
        summary full queues cqs ib_cqs eth_cqs eqs qps dump_cqe dump_eqe
        dump_wqe json
        """.split(),
            False,
        ),
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
        lambda wq, _kernel_backed=True: dict(wq)
        if isinstance(wq, dict)
        else {}
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


def _fake_ibdev(qp_list_address):
    return _FakeObject(
        qp_list=_FakeObject(
            address_of_=lambda: _FakeObject(address_=qp_list_address)
        ),
    )


def _fake_ib_wq(wqe_count, **values):
    return _FakeAggregateObject(
        address_=0x1000,
        type_=_FakeObject(type_name=lambda: "struct mlx5_ib_wq"),
        wqe_cnt=wqe_count,
        wqe_shift=6,
        offset=0,
        **values,
    )


def test_ib_wq_summary_uses_only_valid_queue_fields():
    collector = mlx5.Mlx5Collector(_FAKE_PROG, _args())
    kernel = collector._collect_wq_summary(
        _fake_ib_wq(
            8,
            head=7,
            tail=3,
            cur_post=2,
            max_post=4,
            last_poll=1,
            cur_edge=0x2000,
            fbc=_FakeObject(address_=0x3000, sz_m1=3, log_sz=2, log_stride=7),
        )
    )
    user = collector._collect_wq_summary(_fake_ib_wq(8), False)
    empty = collector._collect_wq_summary(_fake_ib_wq(0))
    fields = itemgetter(
        "size", "stride_bytes", "fbc", "head", "last_poll", "max_post"
    )

    assert fields(kernel) == (8, 64, "0x3000", 7, 1, 4)
    assert fields(user) == (8, 64, None, None, None, None)
    assert fields(empty) == (0, None, None, None, None, None)


def test_summary_qp_count_uses_core_device_ibdev(monkeypatch):
    collector = mlx5.Mlx5Collector(_FAKE_PROG, _args(summary=True))
    collector._ibdev_by_mdev[1] = _fake_ibdev(0x1100)
    counted = []
    monkeypatch.setattr(
        mlx5,
        "list_count_nodes",
        lambda head: counted.append(int(head)) or 3,
    )

    assert collector._count_summary_qps(DeviceRecord(1)) == 3
    assert collector._count_summary_qps(DeviceRecord(2)) == 0
    assert counted == [0x1100]


def test_summary_cq_count_uses_async_eq_table(monkeypatch):
    collector = mlx5.Mlx5Collector(_FAKE_PROG, _args(summary=True))
    device = DeviceRecord(1)
    tree = _FakeObject(address_=0x2000)
    tree.address_of_ = lambda: tree
    async_eq = _FakeObject(cq_table=_FakeObject(tree=tree))
    device.mdev = _FakeObject(
        priv=_FakeObject(
            eq_table=_FakeObject(async_eq=_FakeObject(core=async_eq))
        )
    )
    collector._iter_eq_candidates = lambda _device: iter(
        ((_FakeObject(), role) for role in ("cmd", "async", "pages"))
    )
    monkeypatch.setattr(
        mlx5,
        "radix_tree_for_each",
        lambda head: iter(((7, object()), (9, object())))
        if int(head) == 0x2000
        else iter(()),
    )

    assert collector._count_summary_eqs_and_cqs(device) == (3, 2)


def test_eq_collection_caches_layout_metadata(monkeypatch):
    type_calls = []
    prog = _FakeObject(
        type=lambda name: type_calls.append(name) or _FakeObject(size=64)
    )
    collector = mlx5.Mlx5Collector(prog, _args())
    device = DeviceRecord(1)
    member_checks = []
    monkeypatch.setattr(
        mlx5,
        "has_member",
        lambda obj, name: member_checks.append((obj, name))
        or hasattr(obj, name),
    )
    monkeypatch.setattr(mlx5, "_irq_affinity_cpus", lambda _prog, _irqn: None)

    def eq(eqn, cq_count):
        return _FakeObject(
            address_=0x1000 + eqn,
            type_=_FakeObject(type_name=lambda: "struct mlx5_eq"),
            eqn=eqn,
            irqn=40 + eqn,
            vecidx=eqn,
            cons_index=0,
            fbc=_FakeObject(sz_m1=7),
            cq_count=cq_count,
        )

    records = [
        collector._record_eq(eq(1, 3), device, "completion"),
        collector._record_eq(eq(2, 4), device, "completion"),
    ]

    assert [record["cq_count"] for record in records] == [3, 4]
    assert [record["eqe_size"] for record in records] == [64, 64]
    assert len(member_checks) == 1
    assert type_calls == ["struct mlx5_eqe"]


def test_channel_linkage_aggregates_cqs_once(monkeypatch):
    collector = mlx5.Mlx5Collector(_FAKE_PROG, _args())
    device = DeviceRecord(1)
    eq = {
        "device": "0x1",
        "eqn": 7,
        "irqn": 42,
        "vector": 4,
    }
    collector._eqs[("0x1", 7)] = mlx5._EqEntry(eq, None)
    cqs = [
        {"device": "0x1", "cqn": cqn, "vector": 4, "irqn": 42}
        for cqn in (10, 11)
    ]
    collector._cqs = {
        ("0x1", cq["cqn"]): mlx5._RingEntry(cq, None) for cq in cqs
    }
    channel = {
        "rx_rq": {"cq": cqs[0]},
        "tx_sqs": [{"cq": cqs[1]}],
        "vector": None,
        "irqn": None,
        "eqn": None,
        "irq_desc": None,
    }
    device.netdevs = [{"channels": [channel]}]
    irq_lookups = []
    monkeypatch.setattr(
        mlx5,
        "irq_to_desc",
        lambda _prog, irqn: irq_lookups.append(irqn)
        or _FakeObject(address_=0x4200),
    )

    collector._link_cqs_eqs_and_channels([device])

    assert (channel["vector"], channel["irqn"], channel["eqn"]) == (4, 42, 7)
    assert channel["irq_desc"] == "0x4200"
    assert irq_lookups == [42]


def test_summary_qos_count_matches_bounded_channel_walk():
    collector = mlx5.Mlx5Collector(_FAKE_PROG, _args(summary=True))
    collector._constant = lambda _name: 0
    channel = _FakeObject(
        num_tc=2,
        rq=1,
        sq=[1, 1],
        qos_sqs=[1, None, 1, 1],
        qos_sqs_size=3,
        xdp=0,
        xdpsq=_FakeObject(
            type_=_FakeObject(kind=mlx5.TypeKind.POINTER), sqn=0
        ),
        state=[0],
        icosq=1,
        async_icosq=1,
    )
    channels = _FakeObject(num=1, c=[channel], ptp=None)
    device = DeviceRecord(1)
    device.netdevs = [{"_priv_obj": _FakeObject(channels=channels)}]

    walked = list(collector._iter_channel_queues(channel))
    assert len(walked) == 7
    assert collector._count_summary_channels_and_queues(device) == (1, 7)


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


def test_qp_registry_uses_object_addresses_and_qpn_aliases(monkeypatch):
    collector, device = _mapping_collector(monkeypatch)
    port_one = _fake_qp(0x1000, 198)
    port_two = _fake_qp(0x2000, 454)

    record = collector._record_qp(port_one, device)
    collector._record_qp(port_two, device)

    assert record is collector._qps[0x1000].record
    assert record["owner"] == "mlx5_ib_qp_list"
    assert record["qpn_aliases"] == [1, 198]
    assert len(collector._qps) == 2
    assert {entry.record["qpn"] for entry in collector._qps.values()} == {1}
    assert {entry.record["hw_qpn"] for entry in collector._qps.values()} == {
        198,
        454,
    }


def test_qpn_filter_skips_qp_detail_collection(monkeypatch):
    collector, device = _mapping_collector(monkeypatch)
    collector.args.qpn = 9
    collector._qp_creator = lambda _qp: (_ for _ in ()).throw(
        AssertionError("filtered QP details should not be read")
    )

    assert collector._record_qp(_fake_qp(), device) is None
    assert not collector._qps


def test_raw_packet_qp_progress_uses_canonical_embedded_work_queues(
    monkeypatch,
):
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

    record = collector._record_qp(qp, device)
    assert record is not None

    progress = "sq_pc sq_cc rq_pc rq_cc".split()
    assert itemgetter(*progress)(record) == (1, 2, 3, 4)
    assert itemgetter(*(f"{field}_source" for field in progress))(record) == (
        "qp.sq.head",
        "qp.sq.tail",
        "qp.rq.head",
        "qp.rq.tail",
    )


def test_qp_wqe_dump_eligibility(monkeypatch):
    collector, device = _mapping_collector(monkeypatch)
    kernel_sq = {"head": 4, "tail": 2, "last_poll": 7, "size": 8}
    qps = [
        _fake_qp(address=0x1000, sq=kernel_sq),
        _fake_qp(address=0x2000, sq={"size": 8}),
        _fake_qp(address=0x3000, sq={"size": 0}, rq={"size": 8}),
    ]
    qps[1].ibqp.res.user = 1
    for qp in qps:
        collector._record_qp(qp, device)

    entries = {
        entry.record["address"]: entry for entry in collector._qps.values()
    }
    assert entries["0x1000"].sq_wq is kernel_sq
    assert all(
        entries[address].sq_wq is None for address in ("0x2000", "0x3000")
    )
    collector.args.qps = True
    assert {record["address"] for record in collector._report_qps()} == set(
        entries
    )
    assert collector._auto_wqe_qp_dump_keys() == [0x1000]

    dump_arguments = {}
    collector._dump_ring = lambda *_args, **kwargs: (
        dump_arguments.update(kwargs) or []
    )
    monkeypatch.setattr(mlx5.dumps, "_wq_layout_summary", lambda _wq: {})

    collector._dump_wqe_key(0x1000, 8)
    assert dump_arguments["consumer_index"] == 7
    assert [
        collector._dump_wqe_key(address, 8)["status"]
        for address in (0x2000, 0x3000)
    ] == ["unavailable", "unavailable"]


def test_cq_registry_stops_after_duplicate_cqn(monkeypatch):
    collector, device = _mapping_collector(monkeypatch)
    key = ("0x1", 7)
    record = {"owner": "rq0", "owners": ["rq0"]}
    first_wq = object()
    collector._cqs[key] = mlx5._RingEntry(record, first_wq)
    core_cq = _FakeObject(cqn=7)

    merged = collector._record_core_cq(core_cq, device, "eq0", table_key=7)
    collector._record_core_cq(core_cq, device, "eq1", table_key=7)

    entry = collector._cqs[key]
    assert merged is entry.record is record
    assert entry.wq is first_wq
    assert record["owners"] == ["rq0", "eq0", "eq1"]
    assert record["owner"] == "rq0;eq0;eq1"


def test_cli_report_modes_selectors_and_limits():
    parser = _parser()
    args = parser.parse_args(
        "--full --ib-cqs --eth-cqs --qp-creator kernel "
        "--qp-creator user --cqn 0x20 --max-cq 4 --max-cqe 8".split()
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


@parametrize(
    ("filters", "expected"),
    (
        ({}, [True, True, True]),
        ({"ib_cqs": True}, [True, False, False]),
        ({"eth_cqs": True}, [False, True, False]),
        ({"ib_cqs": True, "eth_cqs": True}, [True, True, False]),
    ),
)
def test_cq_filters_match_only_requested_structure_families(filters, expected):
    cqs = [
        {"address_struct": "struct mlx5_ib_cq"},
        {"address_struct": "struct mlx5e_cq"},
        {"address_struct": "struct mlx5_core_cq"},
    ]

    assert [
        selection._cq_matches_filter(cq, _args(**filters)) for cq in cqs
    ] == expected


def test_qp_creator_filters():
    cases = (
        ("kernel", ["kernel"]),
        ("user", ["user"]),
        (None, ["kernel", "user"]),
    )
    assert [
        selection._qp_matches_filter(
            {"creator_type": creator}, _args(qp_creators=filters)
        )
        for creator, filters in cases
    ] == [True, True, False]


def test_balanced_limits_round_robin_and_fully_drain_uneven_buckets():
    rows = [
        {"device": f"mlx5_{device}", "id": id_}
        for id_, device in enumerate((0, 0, 0, 1, 1, 2), 1)
    ]

    bucket = itemgetter("device")
    assert selection._limit_balanced(rows, None, bucket) is rows
    assert [
        row["id"] for row in selection._limit_balanced(rows, 4, bucket)
    ] == [1, 4, 6, 2]
    assert [
        row["id"] for row in selection._limit_balanced(rows, len(rows), bucket)
    ] == [1, 4, 6, 2, 5, 3]


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

    fields = itemgetter(
        "opcode_display", "req_opcode_display", "qpn", "byte_count_display"
    )
    assert fields(decoded_request) == ("REQ(0x0)", "SEND(0xa)", 0x87, None)
    fields = itemgetter(
        "opcode_display", "vendor_err_synd", "syndrome", "error_qpn"
    )
    assert fields(decoded_error) == ("REQ_ERR(0xd)", "0x9", "0x7", 0x123456)


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
    assert itemgetter("type_display", "cqn", "syndrome")(decoded_error) == (
        "CQ_ERROR(0x4)",
        0x100,
        "0xee",
    )


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
