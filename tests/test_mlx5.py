# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Tests for the mlx5 Corelens module."""
import argparse
from operator import itemgetter

from drgn import cast
from drgn import container_of
from drgn.helpers.linux.net import netdev_priv

from drgn_tools import mlx5
from drgn_tools.corelens import all_corelens_modules
from drgn_tools.mlx5_support import selection
from drgn_tools.mlx5_support.collect_device import for_each_mlx5_core_dev
from drgn_tools.mlx5_support.collect_device import mlx5_core_ib_device
from drgn_tools.mlx5_support.collect_device import mlx5_netdev
from drgn_tools.mlx5_support.render import _render_cqs
from drgn_tools.mlx5_support.render import _render_dumps
from drgn_tools.mlx5_support.render import _render_qps
from drgn_tools.mlx5_support.render import render_report
from tests import DrgnToolsTestCase
from tests.unittest_helpers import load_test_functions
from tests.unittest_helpers import parametrize
from tests.unittest_helpers import raises


class TestMlx5DeviceDiscovery(DrgnToolsTestCase):
    def test_driver_device_relationships(self):
        try:
            self.prog["mlx5_core_driver"]
        except LookupError:
            self.skipTest("mlx5_core is not loaded")

        mdevs = list(for_each_mlx5_core_dev(self.prog))
        if not mdevs:
            self.skipTest("no devices are bound to mlx5_core")

        sf_type = int(self.prog.constant("MLX5_COREDEV_SF"))
        for mdev in mdevs:
            self.assertTrue(mdev)
            if int(mdev.coredev_type) == sf_type:
                adev = container_of(
                    cast("struct device *", mdev.device),
                    "struct auxiliary_device",
                    "dev",
                )
                sf_dev = container_of(adev, "struct mlx5_sf_dev", "adev")
                self.assertEqual(int(sf_dev.mdev), int(mdev))
            else:
                self.assertEqual(int(mdev.pdev.dev.driver_data), int(mdev))

            netdev = mlx5_netdev(mdev)
            if netdev:
                priv = netdev_priv(netdev, "struct mlx5e_priv")
                self.assertEqual(int(priv.mdev), int(mdev))

            ib_device = mlx5_core_ib_device(mdev)
            if ib_device:
                ibdev = container_of(ib_device, "struct mlx5_ib_dev", "ib_dev")
                self.assertEqual(int(ibdev.mdev), int(mdev))


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
        walk_limit=mlx5.MAX_DEFAULT_WALK_LIMIT,
    )
    values.update(overrides)
    return argparse.Namespace(**values)


def _parser():
    parser = argparse.ArgumentParser()
    mlx5.Mlx5().add_args(parser)
    return parser


def _mapping_collector(monkeypatch):
    monkeypatch.setattr(
        mlx5.compat,
        "_safe_member",
        lambda obj, name: obj.get(name) if isinstance(obj, dict) else None,
    )
    return mlx5.Mlx5Collector(None, _args()), {"name": "mlx5_core0"}


def _addressed_mapping_collector(monkeypatch):
    collector, device = _mapping_collector(monkeypatch)
    real_addr = mlx5.compat._addr
    monkeypatch.setattr(
        mlx5.compat,
        "_addr",
        lambda obj: obj.get("_address")
        if isinstance(obj, dict)
        else real_addr(obj),
    )
    return collector, device


def _fake_qp(address, hw_qpn):
    return {"_address": address, "ibqp": {"qp_num": 1}, "qpn": hw_qpn}


def test_module_contract():
    module = all_corelens_modules()["mlx5"]

    assert (
        module.name,
        module.run_when,
        module.need_dwarf,
        module.live_ok,
    ) == (
        "mlx5",
        "never",
        False,
        True,
    )
    assert module.skip_unless_have_kmods == ["mlx5_core"]
    assert module.debuginfo_kmods == ["mlx5_core", "mlx5_ib"]


def test_qp_registry_keeps_distinct_objects_with_the_same_logical_qpn(
    monkeypatch,
):
    collector, device = _addressed_mapping_collector(monkeypatch)
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
    first = collector._record_qp({"qpn": 7, "sq": first_sq}, device, "qp_list")
    merged = collector._record_qp({"qpn": 7}, device, "qp_table", table_qpn=9)

    entry = collector._qps[mlx5._QpKey("mlx5_core0", "hw_qpn", 7)]
    assert first is merged is entry.record
    assert entry.record["owners"] == ["qp_list", "qp_table"]
    assert entry.record["qpn_aliases"] == [7, 9]
    assert entry.dump_wq is entry.sq_wq is first_sq


def test_raw_packet_qp_progress_uses_nested_work_queues(monkeypatch):
    collector, device = _mapping_collector(monkeypatch)
    qp = {
        "qpn": 7,
        "type": 8,
        "sq": {"head": 1, "tail": 2},
        "rq": {"head": 3, "tail": 4},
        "raw_packet_qp": {
            "sq": {"sq": {"head": 11, "tail": 12}},
            "rq": {"rq": {"head": 13, "tail": 14}},
        },
    }

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
    key = ("mlx5_core0", 7)
    record = {"owner": "rq0", "owners": ["rq0"], "vector": None}
    collector._cqs[key] = mlx5._RingEntry(record, None)
    collector._mlx5e_cq_from_core_cq = lambda *_args: None
    collector._mlx5_ib_cq_from_core_cq = lambda *_args: None
    collector._mlx5_aso_cq_from_core_cq = lambda core, _device: core["aso"]
    first_wq = object()

    merged = collector._record_core_cq(
        {"cqn": 7, "vector": 4, "aso": {"wq": first_wq}}, device, "eq0"
    )
    collector._record_core_cq(
        {"cqn": 7, "vector": 9, "aso": {"wq": object()}}, device, "eq1"
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
    help_text = parser.format_help()
    assert "--ib-cqs" in help_text
    assert "--eth-cqs" in help_text
    assert "{kernel,user}" in help_text
    assert "unknown" not in help_text
    assert "other" not in help_text
    assert "--strict" not in help_text
    assert "--verbose" not in help_text
    assert "--debug" not in help_text


@parametrize(
    ("arguments", "expected_error"),
    (
        (["--summary", "--full"], SystemExit),
        (["-ib"], SystemExit),
        (["-eth"], SystemExit),
        (["--qp-creator", "unknown"], SystemExit),
        (["--qp-creator", "other"], SystemExit),
        (["--maxcq", "0"], ValueError),
        (["--maxcqe", "0"], ValueError),
        (["--walk-limit", "0"], ValueError),
        (["--layout"], SystemExit),
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
    for default_mode in ("full", "summary"):
        monkeypatch.setattr(selection, "DEFAULT_REPORT_MODE", default_mode)
        args = _args()
        selection._resolve_report_sections(args)
        summary = default_mode == "summary"
        assert args.summary is summary
        assert args._full_report == (not summary)
        assert all(
            getattr(args, name) for name in ("queues", "cqs", "eqs", "qps")
        ) == (not summary)

    for default_mode, requested_mode in (
        ("full", "summary"),
        ("summary", "full"),
    ):
        monkeypatch.setattr(selection, "DEFAULT_REPORT_MODE", default_mode)
        args = _args(**{requested_mode: True})
        selection._resolve_report_sections(args)
        assert args.summary is (requested_mode == "summary")
        assert args._full_report is (requested_mode == "full")

    monkeypatch.setattr(selection, "DEFAULT_REPORT_MODE", "summary")
    args = _args(cqs=True)
    selection._resolve_report_sections(args)
    assert not args.summary and not args._full_report
    assert (args.queues, args.cqs, args.eqs, args.qps) == (
        False,
        True,
        False,
        False,
    )


def test_walk_limits_report_truncation_instead_of_silently_dropping_objects():
    collector = mlx5.Mlx5Collector(object(), _args(walk_limit=2))

    assert collector._walk_count(5, "QP table") == 2
    assert list(collector._iter_walk_limited(range(5), "CQ table")) == [0, 1]
    assert collector._truncated_walks
    assert "--walk-limit=2" in "\n".join(collector.warnings)


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


@parametrize(
    ("raw", "expected"),
    ((None, None), (0, 0), (3, 3), (4, 0), (7, 3)),
)
def test_cq_arm_sn_is_the_two_bit_software_sequence(raw, expected):
    assert mlx5._cq_arm_sn(raw) == expected


def test_cq_table_labels_software_arm_sequence_without_claiming_arm_state(
    capsys,
):
    report = {
        "devices": [],
        "cqs": [
            {
                "device": "mlx5_0",
                "cqn": 9,
                "address": "0x1234",
                "address_struct": "struct mlx5_core_cq",
                "arm_sn": 3,
            }
        ],
    }

    _render_cqs(report, _args(cqs=True))

    output = capsys.readouterr().out
    assert "ARM_SN" in output
    assert "software arm sequence number" in output
    assert "not hardware arm state" in output


@parametrize(
    ("pc", "cc", "expected"),
    ((10, 4, 6), (4, 4, 0), (4, 10, None), (None, 1, None)),
)
def test_inflight_delta_never_invents_wrapped_work(pc, cc, expected):
    assert mlx5._nonnegative_delta(pc, cc) == expected


def test_unresolved_qp_creator_metadata_is_counted_and_not_filterable():
    qps = [
        {"device": "mlx5_0", "qpn": 1, "creator_type": "kernel"},
        {"device": "mlx5_0", "qpn": 2, "creator_type": "user"},
        {"device": "mlx5_1", "qpn": 3, "creator_type": None},
    ]

    assert mlx5._qp_creator_resolution(qps) == {
        "unresolved_count": 1,
        "examples": [{"device": "mlx5_1", "qpn": 3}],
    }
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


def test_dump_output_keeps_preferred_group_and_input_order(capsys):
    dumps = [
        {"kind": "custom", "selector": 1, "entries": []},
        {"kind": "wqe", "selector": 2, "entries": []},
        {"kind": "cqe", "selector": 3, "entries": []},
        {"kind": "custom", "selector": 4, "entries": []},
        {"kind": "eqe", "selector": 5, "entries": []},
    ]

    _render_dumps({"devices": [], "dumps": dumps}, _args())
    output = capsys.readouterr().out

    headers = [
        output.index(f"{kind} dumps")
        for kind in ("CQE", "EQE", "WQE", "CUSTOM")
    ]
    assert headers == sorted(headers)
    assert output.index("selector : id=1") < output.index("selector : id=4")


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


def test_qp_table_calls_out_unresolved_creator_metadata(capsys):
    report = {
        "devices": [],
        "qps": [
            {
                "device": "mlx5_0",
                "qpn": 17,
                "hw_qpn": 17,
                "address": "0x1234",
                "creator": "unresolved",
            }
        ],
        "qp_creator_resolution": {
            "unresolved_count": 1,
            "examples": [{"device": "mlx5_0", "qpn": 17}],
        },
    }

    _render_qps(report, _args(qps=True))

    output = capsys.readouterr().out
    assert "creator could not be determined for 1 QP(s)" in output
    assert "mlx5_0/QPN 17" in output
    assert "unresolved" in output


@parametrize(
    ("statuses", "expected"),
    (
        ([], "empty"),
        (["ready", "ready"], "ready"),
        (["not-ready", "not-ready"], "not-ready"),
        (["ready", "not-ready"], "partial"),
        (["fault", "fault"], "fault"),
    ),
)
def test_descriptor_dump_status_summarizes_the_whole_window(
    statuses, expected
):
    entries = [{"status": status} for status in statuses]
    assert mlx5._descriptor_dump_status(entries) == expected


def test_findings_are_classified_from_collected_values():
    collector = mlx5.Mlx5Collector(object(), _args())
    cq = {"device": "mlx5_0", "cqn": 7, "eqn": None, "irqn": 42}
    collector._cqs = {("mlx5_0", 7): mlx5._RingEntry(cq, None)}
    devices = [
        {
            "name": "mlx5_0",
            "summary": {"device_state": "INTERNAL_ERROR"},
            "health": {"fatal_error": 1, "miss_counter": 2},
            "netdevs": [
                {
                    "name": "eth0",
                    "summary": {
                        "carrier": "down",
                        "stats": {"rx_errors": 3, "tx_errors": 0},
                    },
                    "channels": [
                        {
                            "rx_rq": {
                                "kind": "rq",
                                "number": 8,
                                "enabled": False,
                                "recovering": True,
                                "pc": 2,
                                "cc": 3,
                                "inflight": 8,
                                "wq": {"size": 8},
                            }
                        }
                    ],
                }
            ],
        }
    ]
    dumps = [
        {
            "kind": "cqe",
            "device": "mlx5_0",
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

    findings = collector._analyze_findings(devices, dumps)
    severities = [finding["severity"] for finding in findings]
    messages = "\n".join(finding["message"] for finding in findings)

    assert severities.count("HIGH") == 5
    assert severities.count("MED") == 4
    assert severities.count("LOW") == 2
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

    assert mlx5._decode_cqe(bytes(raw)) == {
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


def test_decode_request_and_error_cqe_fields():
    request = bytearray(64)
    request[56:60] = (0x0A000087).to_bytes(4, "big")
    request[60:62] = (1536).to_bytes(2, "big")
    request[63] = 0x01
    decoded_request = mlx5._decode_cqe(bytes(request))

    error = bytearray(64)
    error[54:56] = bytes((0x9, 0x7))
    error[56:60] = (0x0A123456).to_bytes(4, "big")
    error[63] = 0xD1
    decoded_error = mlx5._decode_cqe(bytes(error))

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

    assert mlx5._decode_eqe(bytes(completion)) == {
        "owner_bit": 1,
        "type_value": 0,
        "type_display": "COMP(0x0)",
        "sub_type": "0x3",
        "cqn": 0x1234,
    }
    decoded_error = mlx5._decode_eqe(bytes(error))
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

    assert mlx5._decode_wqe(bytes(send)) == {
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


def test_short_descriptors_return_unknown_fields_without_index_errors():
    assert mlx5._decode_cqe(b"")["opcode_value"] is None
    assert mlx5._decode_eqe(b"")["type_value"] is None
    assert mlx5._decode_wqe(b"")["qpn"] is None
    assert mlx5._decode_rq_wqe(b"")["dma_addr"] is None


def test_render_report_preserves_compact_summary_contract(capsys):
    report = {
        "mode": "vmcore",
        "selection": {},
        "counts": {
            "devices": 1,
            "netdevs": 1,
            "channels": None,
            "queues": None,
            "cqs": None,
            "eqs": None,
            "qps": None,
        },
        "devices": [],
        "findings": [],
        "warnings": [],
    }

    render_report(report, _args(summary=True))
    output = capsys.readouterr().out

    assert "Report summary" in output
    assert "Executive summary" not in output
    assert "channels     : -" in output
    assert "queues       : -" in output
    assert "CQs/EQs/QPs  : - / - / -" in output
    assert "HIGH=0 MED=0 LOW=0" in output
    assert "not requested" not in output
    assert "not collected" not in output
    assert "(collected scope only)" in output

    default_args = _args()
    selection._resolve_report_sections(default_args)
    render_report(report, default_args)
    default_output = capsys.readouterr().out
    assert default_args._full_report
    assert all(
        getattr(default_args, name) for name in ("queues", "cqs", "eqs", "qps")
    )
    assert "Completion queues" in default_output
    assert "Event queues" in default_output
    assert "Queue pairs" in default_output


def test_json_conversion_removes_private_collection_metadata():
    report = {
        "_kernel_object": object(),
        "public": [{"value": 1, "_source": "member.path"}],
    }

    assert mlx5._jsonable(report) == {"public": [{"value": 1}]}


def load_tests(loader, standard_tests, pattern):
    return load_test_functions(globals(), standard_tests)
