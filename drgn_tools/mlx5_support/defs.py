# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Report limits and structure paths for the mlx5 Corelens report."""
import re


_PCI_BDF_RE = re.compile(
    r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$"
)

MAX_DEFAULT_DESCRIPTOR_ENTRIES = 32
MAX_DESCRIPTOR_ENTRIES = 4096
MAX_DEFAULT_WALK_LIMIT = None
MAX_WALK_LIMIT = 1048576
MAX_PLAUSIBLE_RING_ENTRIES = MAX_DESCRIPTOR_ENTRIES * 1024
MAX_CHANNELS = 4096
MAX_EQS = 4096
MAX_MLX5_IB_PORTS = 256
MAX_TC = 16
DEFAULT_DESCRIPTOR_ENTRY_BYTES = 64

_MLX5_EQ_TABLE_COMP_ARRAY_COUNT_PATHS = (
    ("struct mlx5_eq_table.num_comp_eqs", ["num_comp_eqs"]),
    ("struct mlx5_eq_table.curr_comp_eqs", ["curr_comp_eqs"]),
    ("struct mlx5_eq_table.max_comp_eqs", ["max_comp_eqs"]),
    ("struct mlx5_eq_table.num_comp_vectors", ["num_comp_vectors"]),
    ("struct mlx5_eq_table.ncomp_eqs", ["ncomp_eqs"]),
)

_MLX5_CORE_QP_TABLE_PATHS = (
    ["priv", "qp_table", "tree"],
    ["priv", "qp_table", "idrs"],
    ["priv", "qp_table", "qpn_table"],
    ["priv", "qp_table", "xarray"],
    ["priv", "qp_table", "xa"],
)

_MLX5_QPN_PATHS = (
    ["qpn"],
    ["mqp", "qpn"],
    ["core_qp", "qpn"],
    ["base", "mqp", "qpn"],
    ["trans_qp", "base", "mqp", "qpn"],
    ["raw_packet_qp", "sq", "base", "mqp", "qpn"],
    ["raw_packet_qp", "rq", "base", "mqp", "qpn"],
    ["dct", "mdct", "mqp", "qpn"],
)
