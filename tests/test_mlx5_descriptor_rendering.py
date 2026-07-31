# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from drgn_tools.mlx5_support.dumps import _annotate_owner_status
from tests.unittest_helpers import load_test_functions
from tests.unittest_helpers import parametrize


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
    decoded = {
        "owner_bit": owner,
        "opcode_value": opcode,
        "status": "ok",
    }
    _annotate_owner_status(
        decoded,
        absolute,
        64,
        "cqe",
        consumer_index=consumer,
    )

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
        descriptor_kind="eqe",
        consumer_index=1,
    )

    assert decoded["status"] == "ready"


def load_tests(loader, standard_tests, pattern):
    return load_test_functions(globals(), standard_tests)
