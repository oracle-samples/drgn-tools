# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Static definitions for the mlx5 Corelens report."""
import re
from typing import List
from typing import Tuple


_PCI_BDF_RE = re.compile(
    r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$"
)
_MLX5_DEVICE_STATE = {1: "UP", 2: "INTERNAL_ERROR"}
_MLX5_PCI_STATUS = {0: "DISABLED", 1: "ENABLED"}
_MLX5_COREDEV_TYPE = {0: "PF", 1: "VF", 2: "SF"}
_MLX5_CMDIF_STATE = {0: "UNINITIALIZED", 1: "UP", 2: "DOWN"}
_MLX5_CQE_OPCODE = {
    0x0: "REQ",
    0x1: "RESP_WR_IMM",
    0x2: "RESP_SEND",
    0x3: "RESP_SEND_IMM",
    0x4: "RESP_SEND_INV",
    0x5: "RESIZE_CQ",
    0xC: "SIG_ERR",
    0xD: "REQ_ERR",
    0xE: "RESP_ERR",
    0xF: "INVALID",
    0x16: "RESIZE",
    0x1E: "ERROR",
}
_MLX5_CQE_ERROR_OPCODES = {0xC, 0xD, 0xE, 0x1E}
_MLX5_CQE_RESPONDER_OPCODES = {0x1, 0x2, 0x3, 0x4}
_MLX5_CQE_BYTE_COUNT_REQ_OPCODES = {0x10}
_MLX5_CQE_SYNDROME = {
    0x01: "LOCAL_LENGTH_ERR",
    0x02: "LOCAL_QP_OP_ERR",
    0x04: "LOCAL_PROT_ERR",
    0x05: "WR_FLUSH_ERR",
    0x06: "MW_BIND_ERR",
    0x10: "BAD_RESP_ERR",
    0x11: "LOCAL_ACCESS_ERR",
    0x12: "REMOTE_INVAL_REQ_ERR",
    0x13: "REMOTE_ACCESS_ERR",
    0x14: "REMOTE_OP_ERR",
    0x15: "TRANSPORT_RETRY_EXC_ERR",
    0x16: "RNR_RETRY_EXC_ERR",
    0x22: "REMOTE_ABORTED_ERR",
}
_MLX5_EQE_TYPE = {
    0x0: "COMP",
    0x1: "PATH_MIG",
    0x2: "COMM_EST",
    0x3: "SQ_DRAINED",
    0x4: "CQ_ERROR",
    0x5: "WQ_CATAS_ERROR",
    0x7: "PATH_MIG_FAILED",
    0x8: "INTERNAL_ERROR",
    0x9: "PORT_CHANGE",
    0xA: "CMD",
    0xB: "PAGE_REQUEST",
    0xC: "PAGE_FAULT",
    0xD: "NIC_VPORT_CHANGE",
    0xE: "ESW_FUNCTIONS_CHANGED",
    0xF: "VHCA_STATE_CHANGE",
    0x10: "WQ_INVAL_REQ_ERROR",
    0x11: "WQ_ACCESS_ERROR",
    0x12: "SRQ_CATAS_ERROR",
    0x13: "SRQ_LAST_WQE",
    0x14: "SRQ_RQ_LIMIT",
    0x15: "GPIO_EVENT",
    0x16: "PORT_MODULE_EVENT",
    0x17: "TEMP_WARN_EVENT",
    0x18: "XRQ_ERROR",
    0x19: "REMOTE_CONFIG",
    0x1A: "DB_BF_CONGESTION",
    0x1B: "STALL_EVENT",
    0x1C: "DCT_DRAINED",
    0x1D: "DCT_KEY_VIOLATION",
    0x20: "FPGA_ERROR",
    0x21: "FPGA_QP_ERROR",
    0x22: "GENERAL_EVENT",
    0x24: "MONITOR_COUNTER",
    0x25: "PPS_EVENT",
    0x26: "DEVICE_TRACER",
    0x27: "OBJECT_CHANGE",
}
_MLX5_EQE_QP_SRQ_TYPES = {
    0x1,
    0x2,
    0x3,
    0x5,
    0x7,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
}
_MLX5_CQ_ERROR_SYNDROME = {
    0x01: "CQ_OVERRUN",
    0x02: "CQ_ACCESS_VIOLATION_ERROR",
}
_MLX5_WQE_OPCODE = {
    0x00: "NOP",
    0x01: "SEND_INVAL",
    0x08: "RDMA_WRITE",
    0x09: "RDMA_WRITE_IMM",
    0x0A: "SEND",
    0x0B: "SEND_IMM",
    0x0E: "LSO",
    0x10: "RDMA_READ",
    0x11: "ATOMIC_CS",
    0x12: "ATOMIC_FA",
    0x14: "ATOMIC_MASKED_CS",
    0x15: "ATOMIC_MASKED_FA",
    0x18: "BIND_MW",
    0x1F: "CONFIG_CMD",
    0x20: "SET_PSV",
    0x21: "GET_PSV",
    0x22: "CHECK_PSV",
    0x23: "DUMP",
    0x25: "UMR",
    0x26: "RGET_PSV",
    0x27: "RCHECK_PSV",
    0x29: "ENHANCED_MPSW",
    0x2C: "FLOW_TBL_ACCESS",
    0x2D: "ACCESS_ASO",
}
_IB_QP_TYPE = {
    0: "IB_QPT_SMI",
    1: "IB_QPT_GSI",
    2: "IB_QPT_RC",
    3: "IB_QPT_UC",
    4: "IB_QPT_UD",
    5: "IB_QPT_RAW_IPV6",
    6: "IB_QPT_RAW_ETHERTYPE",
    8: "IB_QPT_RAW_PACKET",
    9: "IB_QPT_XRC_INI",
    10: "IB_QPT_XRC_TGT",
    11: "IB_QPT_MAX",
    255: "IB_QPT_DRIVER",
    4096: "MLX5_IB_QPT_REG_UMR",
    4097: "IB_QPT_GSI/MLX5_IB_QPT_HW_GSI",
    4098: "MLX5_IB_QPT_DCI",
    4099: "MLX5_IB_QPT_DCT",
    4100: "IB_QPT_RESERVED5",
    4101: "IB_QPT_RESERVED6",
    4102: "IB_QPT_RESERVED7",
    4103: "IB_QPT_RESERVED8",
    4104: "IB_QPT_RESERVED9",
    4105: "IB_QPT_RESERVED10",
}
_IB_QP_STATE = {
    0: "IB_QPS_RESET",
    1: "IB_QPS_INIT",
    2: "IB_QPS_RTR",
    3: "IB_QPS_RTS",
    4: "IB_QPS_SQD",
    5: "IB_QPS_SQE",
    6: "IB_QPS_ERR",
}

# mlx5e state bit positions from drivers/net/ethernet/mellanox/mlx5/core/en.h.
_MLX5E_SQ_STATE_BITS = {
    0: "ENABLED",
    1: "MPWQE",
    2: "RECOVERING",
    3: "IPSEC",
    4: "DIM",
    5: "PENDING_XSK_TX",
    6: "PENDING_TLS_RX_RESYNC",
    7: "LOCK_NEEDED",
}
_MLX5E_RQ_STATE_BITS = {
    0: "ENABLED",
    1: "RECOVERING",
    2: "DIM",
    3: "NO_CSUM_COMPLETE",
    4: "CSUM_FULL",
    5: "MINI_CQE_HW_STRIDX",
    6: "SHAMPO",
    7: "MINI_CQE_ENHANCED",
    8: "XSK",
}
_MLX5E_ICOSQ_STATE_BITS = {0: "ENABLED", 2: "RECOVERING"}
_NETDEV_QUEUE_STATE_BITS = {0: "DRV_XOFF", 1: "STACK_XOFF", 2: "FROZEN"}

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

_MLX5E_CHANNELS_OBJECT_PATHS = (
    ("struct mlx5e_priv.channels", ["channels"]),
    ("struct mlx5e_priv.channels_info", ["channels_info"]),
)

_MLX5E_CHANNEL_COUNT_PATHS = (
    ("struct mlx5e_channels.num", ["num"]),
    ("struct mlx5e_channels.num_channels", ["num_channels"]),
    ("struct mlx5e_channels.params.num_channels", ["params", "num_channels"]),
    (
        "struct mlx5e_channels.params.mqprio.num_tc",
        ["params", "mqprio", "num_tc"],
    ),
)

_MLX5E_CHANNEL_ARRAY_PATHS: Tuple[Tuple[str, List[str]], ...] = (
    ("struct mlx5e_channels.c", ["c"]),
    ("struct mlx5e_channels.channels", ["channels"]),
    ("struct mlx5e_channels.channel", ["channel"]),
    ("struct mlx5e_channels[]", []),
)

_MLX5E_CHANNEL_RQ_PATHS = (
    ("struct mlx5e_channel.rq", ["rq"]),
    ("struct mlx5e_channel.rx_rq", ["rx_rq"]),
)

_MLX5E_CHANNEL_SQ_PATHS = (
    ("struct mlx5e_channel.sq", ["sq"]),
    ("struct mlx5e_channel.sqs", ["sqs"]),
    ("struct mlx5e_channel.txqsq", ["txqsq"]),
)

_MLX5E_CQ_CORE_PATHS = (
    ("struct mlx5e_cq.mcq", ["mcq"]),
    ("struct mlx5e_cq.core", ["core"]),
)

_MLX5E_CQ_WQ_PATHS = (
    ("struct mlx5e_cq.wq", ["wq"]),
    ("struct mlx5e_cq.cqwq", ["cqwq"]),
)

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
