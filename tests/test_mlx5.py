# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Unit tests for logic that does not require real kernel mlx5 objects.

Kernel member paths, container conversions, and version compatibility are
tested against the mlx5 vmcore library.
"""
import argparse
from operator import itemgetter

from drgn_tools import mlx5
from drgn_tools.mlx5_support import defs
from drgn_tools.mlx5_support import render as render_module
from drgn_tools.mlx5_support import selection
from drgn_tools.mlx5_support.format import _count_display
from drgn_tools.mlx5_support.render import _render_cqs
from drgn_tools.mlx5_support.render import _render_dumps
from drgn_tools.mlx5_support.render import _render_qps
from drgn_tools.mlx5_support.render import render_report
from tests.unittest_helpers import load_test_functions
from tests.unittest_helpers import parametrize
from tests.unittest_helpers import raises


def _args(**overrides):
    values = dict.fromkeys(
        "dev netdev ip cqn eqn qpn sqn rqn maxqueues maxcq maxeq maxqp".split()
    )
    values.update(
        {
            name: False
            for name in """
        summary full queues cqs ib_cqs eth_cqs eqs qps dump_cqe dump_eqe
        dump_wqe json strict
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
    module = mlx5.Mlx5()

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
    assert defs.MAX_DEFAULT_WALK_LIMIT == defs.DEFAULT_WALK_LIMIT
    assert defs.MAX_HARD_LIMIT == defs.MAX_DESCRIPTOR_ENTRIES
    assert defs.DEFAULT_DESCRIPTOR_BYTES == defs.DEFAULT_DESCRIPTOR_ENTRY_BYTES
    assert render_module.DUMP_SEPARATOR == "-" * 79


def test_eq_registry_merges_into_first_record_and_preserves_first_handles(
    monkeypatch,
):
    collector, device = _mapping_collector(monkeypatch)
    first_eq = {"eqn": 7, "eqe_size": 64}

    first = collector._record_eq(first_eq, device, "completion")
    merged = collector._record_eq(
        {"eqn": 7, "eqe_size": 64, "vector": 4, "wq": object()},
        device,
        "async",
    )

    entry = collector._eqs[("mlx5_core0", 7)]
    assert first is merged is entry.record
    assert entry.eq is first_eq
    assert entry.wq is None
    assert (first["role"], first["vector"]) == ("completion,async", 4)


def test_core_cq_registry_enriches_queue_record_and_backfills_first_wq(
    monkeypatch,
):
    collector, device = _mapping_collector(monkeypatch)
    key = ("mlx5_core0", 7)
    queue = {
        "cq": {
            "owner": "rq0",
            "owners": ["rq0"],
            "vector": None,
            "queue_kind": "rq",
        }
    }
    collector._cqs[key] = mlx5._RingEntry(queue["cq"], None)
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
    assert merged is entry.record is queue["cq"]
    assert entry.wq is first_wq
    assert queue["cq"]["owner"] == "rq0;eq0;eq1"
    assert queue["cq"]["owners"] == ["rq0", "eq0", "eq1"]
    assert (queue["cq"]["vector"], queue["cq"]["queue_kind"]) == (4, "rq")


def test_mlx5e_queue_registry_keeps_latest_record_and_latest_non_null_wq():
    collector = mlx5.Mlx5Collector(None, _args())
    base = {"device": "mlx5_core0", "kind": "sq", "number": 7, "owner": "sq0"}
    first_wq, latest_wq = object(), object()

    collector._record_queue_wq(dict(base, version=1), first_wq)
    latest_record = dict(base, version=2)
    collector._record_queue_wq(latest_record, None)
    key = ("mlx5_core0", "sqn", 7, "sq0")
    assert collector._mlx5e_queues[key].record is latest_record
    assert collector._mlx5e_queues[key].wq is first_wq

    newest_record = dict(base, version=3)
    collector._record_queue_wq(newest_record, latest_wq)
    assert collector._mlx5e_queues[key].record is newest_record
    assert collector._mlx5e_queues[key].wq is latest_wq


@parametrize("observed", ("both", "sq", "rq", "neither"))
def test_qp_registry_merges_hardware_qpn_fallback_and_updates_handles(
    monkeypatch, observed
):
    collector, device = _mapping_collector(monkeypatch)
    old_sq, old_rq, new_sq, new_rq = object(), object(), object(), object()
    first = collector._record_qp(
        {"qpn": 7, "sq": {"wq": old_sq}, "rq": {"wq": old_rq}},
        device,
        "first",
    )
    later_qp = {"qpn": 7}
    if observed in ("both", "sq"):
        later_qp["sq"] = {"wq": new_sq}
    if observed in ("both", "rq"):
        later_qp["rq"] = {"wq": new_rq}

    merged = collector._record_qp(later_qp, device, "later")
    entry = collector._qps[mlx5._QpKey("mlx5_core0", "hw_qpn", 7)]
    expected = {
        "both": (new_sq, new_sq, new_rq),
        "sq": (new_sq, new_sq, old_rq),
        "rq": (new_rq, old_sq, new_rq),
        "neither": (old_sq, old_sq, old_rq),
    }[observed]

    assert first is merged is entry.record
    handles = (entry.dump_wq, entry.sq_wq, entry.rq_wq)
    assert all(actual is wanted for actual, wanted in zip(handles, expected))


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


def test_qp_registry_rejects_an_address_without_any_qpn(monkeypatch):
    collector, device = _mapping_collector(monkeypatch)
    monkeypatch.setattr(
        mlx5.compat,
        "_addr",
        lambda obj: obj.get("_address") if isinstance(obj, dict) else None,
    )

    collector._record_qp({"_address": 0x1000}, device, "unknown_table")

    assert not collector._qps


def test_summary_and_full_share_qp_sources_and_identity(monkeypatch):
    collector, device = _addressed_mapping_collector(monkeypatch)
    device["_mdev_obj"] = object()
    first = _fake_qp(0x1000, 198)
    second = _fake_qp(0x2000, 454)
    candidates = (
        (first, "mlx5_ib_qp_list", None),
        (first, "core_table", 198),
        (second, "mlx5_ib_qp_list", None),
        (second, "core_table", 454),
    )
    monkeypatch.setattr(
        collector,
        "_iter_qps_from_device",
        lambda _device, *, summary: iter(candidates),
    )

    summary_count = collector._count_summary_qps(device)
    for qp, owner, table_qpn in collector._iter_qps_from_device(
        device, summary=False
    ):
        collector._record_selected_qp(qp, device, owner, table_qpn)

    assert summary_count == len(collector._qps) == 2
    assert all(
        entry.record["owners"] == ["mlx5_ib_qp_list", "core_table"]
        for entry in collector._qps.values()
    )


def test_qp_selector_uses_hardware_qpn_when_logical_qpn_is_ambiguous(
    monkeypatch,
):
    collector, device = _addressed_mapping_collector(monkeypatch)
    collector._record_qp(_fake_qp(0x1000, 198), device, "mlx5_ib_qp_list")
    collector._record_qp(_fake_qp(0x2000, 454), device, "mlx5_ib_qp_list")
    collector._selected_device_names = {"mlx5_core0"}

    selected = collector._select_qp_key(198)

    assert selected == mlx5._QpKey("mlx5_core0", "address", 0x1000)
    assert collector._select_qp_key(1) in collector._qps
    assert any("hardware QPN" in warning for warning in collector.warnings)


def test_cqe_qp_index_is_built_once_for_receive_only_qps(monkeypatch):
    collector = mlx5.Mlx5Collector(None, _args())
    key = mlx5._QpKey("mlx5_core0", "qpn", 7)
    collector._qps[key] = mlx5._QpEntry(
        {"qpn_aliases": [7], "send_cqn": None, "recv_cqn": 5},
        None,
        None,
        None,
    )
    rebuild = collector._rebuild_qp_indexes
    rebuild_count = 0

    def counted_rebuild():
        nonlocal rebuild_count
        rebuild_count += 1
        rebuild()

    monkeypatch.setattr(collector, "_rebuild_qp_indexes", counted_rebuild)
    for _ in range(2):
        assert (
            collector._find_ib_qp_for_cqe(("mlx5_core0", 5), {"qpn": 7})
            is None
        )
    assert rebuild_count == 1


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
    assert "--strict" in help_text
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
        (["--cqn", "-1"], ValueError),
        (["--dev", "0000:zz:00.0"], ValueError),
        (["--layout"], SystemExit),
    ),
)
def test_invalid_cli_values_are_rejected(arguments, expected_error):
    parser = _parser()
    with raises(expected_error):
        mlx5._validate_args(parser.parse_args(arguments))


@parametrize(
    ("overrides", "expected"),
    (
        (
            {"summary": True},
            {"channels": False, "eqs": False, "cqs": False, "qps": False},
        ),
        (
            {"queues": True},
            {"channels": True, "eqs": True, "cqs": False, "qps": False},
        ),
        (
            {"eqs": True},
            {"channels": False, "eqs": True, "cqs": False, "qps": False},
        ),
        (
            {"cqs": True},
            {"channels": True, "eqs": True, "cqs": True, "qps": False},
        ),
        (
            {"ib_cqs": True},
            {"channels": False, "eqs": True, "cqs": True, "qps": False},
        ),
        (
            {"dump_cqe": True},
            {"channels": True, "eqs": True, "cqs": True, "qps": True},
        ),
        (
            {"dump_wqe": True},
            {"channels": True, "eqs": True, "cqs": False, "qps": True},
        ),
        (
            {"_full_report": True},
            {"channels": True, "eqs": True, "cqs": True, "qps": True},
        ),
    ),
)
def test_collection_plan_contains_required_dependencies(overrides, expected):
    plan = mlx5._collection_plan(_args(**overrides))
    assert plan == expected


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


def test_shared_known_value_ignores_missing_values_and_rejects_conflicts():
    assert mlx5._shared_known_value([None, 7, 7]) == 7
    assert mlx5._shared_known_value([None, None]) is None
    assert mlx5._shared_known_value([7, 8]) is None


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
        assert mlx5._summary_counts_only(args) is summary

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


def test_invalid_default_report_mode_is_rejected(monkeypatch):
    monkeypatch.setattr(selection, "DEFAULT_REPORT_MODE", "invalid")

    with raises(ValueError, match="DEFAULT_REPORT_MODE"):
        selection._resolve_report_sections(_args())


def test_summary_count_path_is_used_only_for_an_unfocused_summary():
    assert mlx5._summary_counts_only(_args(summary=True))
    for override in (
        {"full": True},
        {"queues": True},
        {"dump_cqe": True},
        {"qpn": 1},
        {"_full_report": True},
    ):
        assert not mlx5._summary_counts_only(_args(summary=True, **override))


def test_walk_limits_report_truncation_instead_of_silently_dropping_objects():
    collector = mlx5.Mlx5Collector(object(), _args(walk_limit=2))

    assert collector._walk_count(5, "QP table") == 2
    assert list(collector._iter_limited(range(5), "CQ table")) == [0, 1]
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


def test_automatic_wqe_queue_selector_respects_device_keys():
    args = _args(dump_wqe=True)
    selected = {("mlx5_0", "sqn", 7), (None, "rqn", 8)}
    send_queue = {"device": "stale", "kind": "sq", "number": 7}

    assert selection._queue_matches_wqe_selector(
        send_queue, args, selected, "mlx5_0"
    )
    assert not selection._queue_matches_wqe_selector(
        send_queue, args, selected, "mlx5_1"
    )
    assert selection._queue_matches_wqe_selector(
        {"device": "mlx5_1", "kind": "xskrq", "number": 8},
        args,
        selected,
    )
    assert not selection._queue_matches_wqe_selector(
        {"device": "mlx5_0", "kind": "rq", "number": None},
        args,
        selected,
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


def test_cq_owner_lookup_does_not_replace_netdev_helper():
    original = mlx5.compat.netdev_name
    collector = object.__new__(mlx5.Mlx5Collector)

    owner = collector._mlx5e_core_cq_owner(
        None,
        None,
        {"name": "mlx5_0", "netdevs": []},
    )

    assert owner["netdev"] is None
    assert mlx5.compat.netdev_name is original


@parametrize(
    ("pc", "cc", "expected"),
    ((10, 4, 6), (4, 4, 0), (4, 10, None), (None, 1, None)),
)
def test_inflight_delta_never_invents_wrapped_work(pc, cc, expected):
    assert mlx5._nonnegative_delta(pc, cc) == expected


def test_qp_aliases_normalize_and_match_each_real_identifier():
    assert selection._qp_aliases(None, 12, "10", 12, "invalid", 11) == [
        10,
        11,
        12,
    ]
    record = {
        "qpn": 10,
        "ib_qpn": 11,
        "hw_qpn": 12,
        "table_qpn": 13,
    }

    assert all(
        selection._qp_record_matches_qpn(record, qpn) for qpn in range(10, 14)
    )
    assert not selection._qp_record_matches_qpn(record, 14)


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
    assert _count_display(None) == "-"

    default_args = _args()
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
