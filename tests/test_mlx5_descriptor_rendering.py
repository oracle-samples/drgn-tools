# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools import mlx5
from drgn_tools.mlx5_support.dumps import _annotate_owner_status
from tests.unittest_helpers import load_test_functions
from tests.unittest_helpers import parametrize


_CONSTANTS = {
    "MLX5_CQE_REQ": 0,
    "MLX5_CQE_SIG_ERR": 12,
    "MLX5_CQE_REQ_ERR": 13,
    "MLX5_CQE_RESP_ERR": 14,
    "MLX5_EVENT_TYPE_CQ_ERROR": 4,
}


class _Wq:
    def __init__(self, wrids):
        self._wrids = wrids
        self.reads = []

    def __getattr__(self, name):
        if name not in ("wqe_cnt", "wrid"):
            raise AttributeError(name)
        self.reads.append(name)
        return len(self._wrids) if name == "wqe_cnt" else self._wrids


def _collector():
    class Program:
        cache = {}
        calls = []

        def constant(self, name):
            self.calls.append(name)
            return _CONSTANTS[name]

    collector = object.__new__(mlx5.Mlx5Collector)
    collector.prog = Program()
    collector.warnings = []
    return collector


def _cqes(*pairs):
    return [
        dict(status="ready", opcode_value=0, qpn=qpn, wqe_counter=counter)
        for qpn, counter in pairs
    ]


@parametrize(
    ("kind", "owner", "opcode", "absolute", "consumer", "expected"),
    (
        ("cqe", 0, 0x2, 0, 0, ("ready", True, None)),
        ("cqe", 0, 0xF, 0, 0, ("not-ready", True, "invalid-sentinel")),
        ("cqe", 1, 0x2, 0, 0, ("not-ready", False, "owner-mismatch")),
        ("cqe", 0, 0x2, 9, 10, ("not-ready", True, "consumed")),
        ("cqe", 0, 0xD, 0, 0, ("ready", True, None)),
        ("eqe", 0, None, 0, 1, ("ready", True, None)),
    ),
)
def test_descriptor_pollability(
    kind, owner, opcode, absolute, consumer, expected
):
    decoded = {"owner_bit": owner, "opcode_value": opcode, "status": "ok"}
    _annotate_owner_status(decoded, absolute, 64, kind, consumer)

    assert (
        decoded["status"],
        decoded["owner_match"],
        decoded.get("not_ready_reason"),
    ) == expected


def test_descriptor_dump_summary_counts_bad_statuses():
    assert mlx5._descriptor_dump_summary([]) == ("empty", {})
    entries = [{"status": "ok"}] + [{"status": "read-unavailable"}] * 2
    assert mlx5._descriptor_dump_summary(entries) == (
        "partial",
        {"read-unavailable": 2},
    )


@parametrize(
    ("kind", "expected_calls"),
    (
        (None, []),
        ("wqe", []),
        ("eqe", ["MLX5_EVENT_TYPE_CQ_ERROR"]),
        (
            "cqe",
            ["MLX5_CQE_SIG_ERR", "MLX5_CQE_REQ_ERR", "MLX5_CQE_RESP_ERR"],
        ),
    ),
)
def test_descriptor_constants_are_lazy(kind, expected_calls):
    collector = _collector()
    reports = [] if kind is None else [{"kind": kind, "entries": []}]
    assert collector._descriptor_findings(reports) == []
    assert collector.prog.calls == expected_calls


def test_descriptor_dump_reuses_wq_layout(monkeypatch):
    collector = _collector()
    wq, layout, calls = object(), {"wq": "0x1"}, []
    collector._dump_ring = lambda *_args, **_kwargs: [{"status": "broken"}]
    monkeypatch.setattr(
        mlx5.dumps,
        "_wq_layout_summary",
        lambda value: calls.append(value) or layout,
    )
    record = {"size": 8, "consumer_index": 2}
    collector._cqs = {("dev", 7): mlx5._RingEntry(record, wq)}
    report = collector._dump_cqe_key(("dev", 7), 4, [])
    assert (calls, report["wq"], len(collector.warnings)) == ([wq], layout, 1)


def test_cqe_wrid_annotation_reuses_qp_data_and_gsi_lookup(monkeypatch):
    collector = _collector()
    pointer = 1 << 63
    wqs = [
        _Wq(range(100, 108)),
        _Wq(range(200, 208)),
        _Wq([pointer] * 8),
    ]
    qps = [
        mlx5._QpEntry({"qpn_aliases": aliases, "creator_type": creator}, wq)
        for aliases, creator, wq in (
            ([7, 70], "user", wqs[0]),
            ([8, 70], "user", wqs[1]),
            ([9], "kernel", wqs[2]),
        )
    ]
    entries = _cqes((7, 10), (7, 11), (8, 17), (70, 1), (9, 2), (9, 3))
    gsi_calls = []
    monkeypatch.setattr(
        mlx5,
        "_mlx5_ib_gsi_saved_wr_id",
        lambda _prog, value: gsi_calls.append(value) or 77,
    )

    cq = {"address_struct": "struct mlx5_ib_cq"}
    assert collector._annotate_ib_cqe_wr_ids(cq, entries, qps) == 5
    assert tuple(entry.get("wr_id") for entry in entries) == (
        102,
        103,
        201,
        None,
        77,
        77,
    )
    assert [entry.get("wr_id_index") for entry in entries[:3]] == [2, 3, 1]
    assert all(wq.reads == ["wqe_cnt", "wrid"] for wq in wqs)
    assert gsi_calls == [pointer]

    single_wq = _Wq(range(300, 308))
    single = _cqes((0, 9), (99, 9), (7, 9))
    assert (
        collector._annotate_ib_cqe_wr_ids(
            cq, single, [mlx5._QpEntry({"qpn_aliases": [7]}, single_wq)]
        )
        == 1
    )
    assert [entry.get("wr_id") for entry in single] == [None, None, 301]
    assert collector.prog.calls == ["MLX5_CQE_REQ", "MLX5_CQE_REQ_ERR"]


def load_tests(loader, standard_tests, pattern):
    return load_test_functions(globals(), standard_tests)
