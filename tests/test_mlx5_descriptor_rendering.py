# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools.mlx5_support.dumps import _annotate_owner_status
from drgn_tools.mlx5_support.render import _cqe_path_display
from drgn_tools.mlx5_support.render import _dump_group_legend_lines
from drgn_tools.mlx5_support.render import _render_descriptor_entries
from tests.unittest_helpers import load_test_functions
from tests.unittest_helpers import parametrize


def _cqe(owner, opcode, absolute_index=0, consumer_index=0, ring_size=64):
    decoded = {
        "owner_bit": owner,
        "opcode_value": opcode,
        "status": "ok",
    }
    _annotate_owner_status(
        decoded,
        absolute_index,
        ring_size,
        "cqe",
        consumer_index=consumer_index,
    )
    return decoded


@parametrize(
    ("owner", "opcode", "absolute", "consumer", "status", "match", "reason"),
    (
        (0, 0x2, 0, 0, "ready", True, None),
        (0, 0xF, 0, 0, "not-ready", True, "invalid-sentinel"),
        (1, 0x2, 0, 0, "not-ready", False, "owner-mismatch"),
        (0, 0x2, 9, 10, "not-ready", True, "consumed"),
        (0, 0xD, 0, 0, "ready", True, None),
    ),
)
def test_cqe_pollability(
    owner, opcode, absolute, consumer, status, match, reason
):
    decoded = _cqe(owner, opcode, absolute, consumer)

    assert decoded["status"] == status
    assert decoded["owner_match"] is match
    if reason is None:
        assert "not_ready_reason" not in decoded
    else:
        assert decoded["not_ready_reason"] == reason


def test_eqe_owner_status_is_unchanged():
    decoded = {"owner_bit": 0, "status": "ok"}

    _annotate_owner_status(
        decoded,
        absolute_index=0,
        ring_size=64,
        owner_mode="eqe",
        consumer_index=1,
    )

    assert decoded["status"] == "ready"


def test_cqe_legend_describes_two_state_pollability():
    lines = _dump_group_legend_lines(
        "cqe",
        [
            {
                "entries": [
                    {
                        "status": "not-ready",
                        "not_ready_reason": "invalid-sentinel",
                    }
                ]
            }
        ],
    )
    text = "\n".join(lines)

    assert "ready means the CQE is pollable now" in text
    assert "not-ready means" in text
    assert "invalid means" not in text
    assert "WHY" not in text


def test_rqn_dumps_use_only_receive_wqe_legend_and_columns(capsys):
    missing = {
        "kind": "wqe",
        "selector_name": "rqn",
        "selector": 7,
        "entries": [],
    }
    text = "\n".join(
        _dump_group_legend_lines(
            "wqe",
            [
                {"selector_name": "rqn", "wqe_kind": "rq", "entries": [{}]},
                missing,
            ],
        )
    )

    assert "RQ WQEs use" in text
    assert "SQ/QP WQEs use" not in text
    _render_descriptor_entries(missing, missing["entries"])
    header = capsys.readouterr().out
    assert "RQ_IDX" in header
    assert "off_in_bbs" not in header


@parametrize("value", (0, False, "0", "0x0", "decoded(0)", "decoded(0x0)"))
def test_zero_descriptor_values_do_not_add_optional_columns(capsys, value):
    dump = {
        "kind": "cqe",
        "entries": [{"wqe_id": value}],
    }

    _render_descriptor_entries(dump, dump["entries"])

    assert "WQE_ID" not in capsys.readouterr().out


@parametrize("value", (1, True, "1", "0x1", "", "decoded(1)"))
def test_nonzero_descriptor_values_add_optional_columns(capsys, value):
    dump = {
        "kind": "cqe",
        "entries": [{"wqe_id": value}],
    }

    _render_descriptor_entries(dump, dump["entries"])

    assert "WQE_ID" in capsys.readouterr().out


def test_cqe_path_displays_completion_interrupt_linkage():
    text = _cqe_path_display(
        {
            "kind": "cqe",
            "selector_name": "cqn",
            "selector": 3255,
            "cq": {
                "cqn": 3255,
                "eqn": 7,
                "eq_role": "completion",
                "eq_vector": 1,
                "eq_irqn": 48,
                "eq_irq_cpu": "1",
            },
        }
    )

    assert text == "CQN=3255 EQN=7 IRQN=48 CPU=1"


def test_cqe_path_marks_unavailable_linkage():
    text = _cqe_path_display(
        {
            "kind": "cqe",
            "selector_name": "cqn",
            "selector": 42,
            "cq": {},
        }
    )

    assert text == "CQN=42 EQN=- IRQN=- CPU=-"


def load_tests(loader, standard_tests, pattern):
    return load_test_functions(globals(), standard_tests)
