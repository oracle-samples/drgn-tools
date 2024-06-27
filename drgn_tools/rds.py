# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for examining rds related info.
"""
import argparse
import ipaddress
import re
import struct
from datetime import timedelta
from typing import Any
from typing import Dict
from typing import Iterable
from typing import Iterator
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Tuple
from typing import Union

import drgn
from drgn import cast
from drgn import container_of
from drgn import Object
from drgn import PlatformFlags
from drgn import Program
from drgn.helpers.linux import for_each_online_cpu
from drgn.helpers.linux import per_cpu
from drgn.helpers.linux.list import hlist_for_each_entry
from drgn.helpers.linux.list import list_empty
from drgn.helpers.linux.list import list_for_each
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.pid import find_task

from drgn_tools.corelens import CorelensModule
from drgn_tools.module import ensure_debuginfo
from drgn_tools.table import print_table
from drgn_tools.table import Table

# Golbal variables and definitions #

RDS_IN_XMIT = 2

RDS_CP_STATES = {
    0: "RDS_CONN_DOWN",
    1: "RDS_CONN_CONNECTING",
    2: "RDS_CONN_DISCONNECTING",
    3: "RDS_CONN_UP",
    4: "RDS_CONN_RESETTING",
    5: "RDS_CONN_ERROR",
}

IB_CM_STATES = {
    0: "IB_CM_IDLE",
    1: "IB_CM_LISTEN",
    2: "IB_CM_REQ_SENT",
    3: "IB_CM_REQ_RCVD",
    4: "IB_CM_MRA_REQ_SENT",
    5: "IB_CM_MRA_REQ_RCVD",
    6: "IB_CM_REP_SENT",
    7: "IB_CM_REP_RCVD",
    8: "IB_CM_MRA_REP_SENT",
    9: "IB_CM_MRA_REP_RCVD",
    10: "IB_CM_ESTABLISHED",
    11: "IB_CM_DREQ_SENT",
    12: "IB_CM_DREQ_RCVD",
    13: "IB_CM_TIMEWAIT",
    14: "IB_CM_SIDR_REQ_SENT",
    15: "IB_CM_SIDR_REQ_RCVD",
}

RDMA_CM_STATES = {
    0: "RDMA_CM_IDLE",
    1: "RDMA_CM_ADDR_QUERY",
    2: "RDMA_CM_ADDR_RESOLVED",
    3: "RDMA_CM_ROUTE_QUERY",
    4: "RDMA_CM_ROUTE_RESOLVED",
    5: "RDMA_CM_CONNECT",
    6: "RDMA_CM_DISCONNECT",
    7: "RDMA_CM_ADDR_BOUND",
    8: "RDMA_CM_LISTEN",
    9: "RDMA_CM_DEVICE_REMOVAL",
    10: "RDMA_CM_DESTROYING",
}

# Helpers #


def be64_to_host(prog: drgn.Program, value: int) -> int:
    """
    Convert 64 byte value from big endian to host order

    :param prog: drgn program
    :param value: The value to be converted
    """
    # If the platform byte order differs from ours, drgn will
    # transparently handle that. We only need to do a byte
    # swap if the program byte order is little endian.
    if prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN:
        return struct.unpack("<Q", struct.pack(">Q", value))[0]
    return value


def be32_to_host(prog: drgn.Program, value: int) -> int:
    """
    Convert 32 byte value from big endian to host order

    :param prog: drgn program
    :param value: The value to be converted
    """
    # If the platform byte order differs from ours, drgn will
    # transparently handle that. We only need to do a byte
    # swap if the program byte order is little endian.
    if prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN:
        return struct.unpack("<L", struct.pack(">L", value))[0]
    return value


def be16_to_host(prog: drgn.Program, value: int) -> int:
    """
    Convert 16 byte value from big endian to host order

    :param prog: drgn program
    :param value: The value to be converted
    """
    # If the platform byte order differs from ours, drgn will
    # transparently handle that. We only need to do a byte
    # swap if the program byte order is little endian.
    if prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN:
        return struct.unpack("<H", struct.pack(">H", value))[0]
    return value


def rds_inet_ntoa(addr_obj: Object) -> str:
    """
    Convert addr from sin6_addr to string

    :param addr_obj: ``struct in6_addr`` to convert to string
    :returns: the address in string form
    """
    addr = list(map(int, addr_obj.in6_u.u6_addr8))
    addr_bytes = bytes(addr)
    ip = ipaddress.IPv6Address(addr_bytes)
    if ip.ipv4_mapped:
        ip_str = str(ip.ipv4_mapped)
    else:
        ip_str = str(ip)

    return ip_str


def get_connection_uptime(conn: Object) -> timedelta:
    """
    Return the time the connection was in the "UP" state..

    :param conn: ``struct rds_connection`` Object.
    :returns: Conn up time as a string
    """
    prog = conn.prog_
    curr_time = prog["tk_core"].timekeeper.xtime_sec
    conn_restart_time = conn.c_path.cp_reconnect_start
    time_since = curr_time - conn_restart_time
    return timedelta(seconds=int(time_since))


def rds_sk_sndbuf(rs: Object) -> int:
    """
    Extract the sndbuf from the socket

    :param rs: ``struct rds_sock`` to extract sndbuf
    :returns: sndbuf from ``struct rds_sock``
    """
    return rs.rs_sk.sk_sndbuf.value_() // 2


def rds_sk_rcvbuf(rs: Object) -> int:
    """
    Extract the rcvbuf from the socket

    :param rs: ``struct rds_sock`` to extract rcvbuf
    :returns: rcvbuf from ``struct rds_sock``
    """
    return rs.rs_sk.sk_rcvbuf.value_() // 2


def rds_conn_path_state(conn: Object) -> str:
    """
    Get the connection state for a given RDS connection.

    :param conn: ``struct rds_connection`` Object.
    :returns: The RDS connection state in string format.
    """

    key = conn.c_path.cp_state.counter.value_()

    return RDS_CP_STATES.get(key, "N/A")


def ib_cm_state(cm_id: Object) -> str:
    """
    Get the IB CM state for a given RDS connection.

    :param conn: ``struct ib_cm_id`` Object.
    :returns: The RDS connection IB CM state in string format.
    """

    if cm_id is None:
        return "N/A"

    key = cm_id.state.value_()
    if key not in IB_CM_STATES.keys():
        return "N/A"

    return IB_CM_STATES[key]


def rdma_cm_state(rdma_id_priv: Object) -> str:
    """
    Get the RDMA CM state for a given RDS connection.

    :param conn: ``struct rdma_id_private`` Object.
    :returns: The RDS connection RDMA CM state in string format.
    """

    if rdma_id_priv is None:
        return "N/A"

    key = rdma_id_priv.state.value_()
    if key not in RDMA_CM_STATES.keys():
        return "N/A"

    return RDMA_CM_STATES[key]


def fields_to_list(fields: str) -> List[str]:
    """
    Create a list of fields from a given string

    :param fields: Input string containing ',' separated fields
    :returns: List of fields
    """
    return [s.lower().strip() for s in fields.split(",")]


def for_each_rds_ib_device(prog: drgn.Program) -> Iterable[Object]:
    """
    Provide the list of ``struct rds_ib_device`` as an iterable object

    :param prog: drgn program
    :returns: A List of ``struct rds_ib_device`` as an iterable object
    """

    return list_for_each_entry(
        "struct rds_ib_device", prog["rds_ib_devices"].address_of_(), "list"
    )


def for_each_rds_sock(prog: drgn.Program) -> Iterable[Object]:
    """
    Provide the list of ``struct rds_sock`` as an iterable object

    :param prog: drgn program
    :returns: A list of ``struct rds_sock`` as an iterable object
    """

    return list_for_each_entry(
        "struct rds_sock", prog["rds_sock_list"].address_of_(), "rs_item"
    )


def for_each_rds_ib_conn(
    dev: Object,
    laddr: Optional[str] = None,
    faddr: Optional[str] = None,
    tos: Optional[str] = None,
    states: Optional[str] = None,
) -> Iterator[Object]:
    """
    Provide the list of ``struct rds_ib_connection`` as an iterable object

    :param dev: ``struct rds_ib_device`` Object.
    :returns: A list of ``struct rds_ib_connection`` as an iterable object
    """

    if laddr:
        laddr_list = fields_to_list(laddr)
    if faddr:
        faddr_list = fields_to_list(faddr)
    if tos:
        tos_list = fields_to_list(tos)
    if states:
        states_list = fields_to_list(states)

    for rds_ib_conn in list_for_each_entry(
        "struct rds_ib_connection", dev.conn_list.address_of_(), "ib_node"
    ):
        conn_laddr = rds_inet_ntoa(rds_ib_conn.conn.c_laddr)
        conn_faddr = rds_inet_ntoa(rds_ib_conn.conn.c_faddr)
        conn_tos = int(rds_ib_conn.conn.c_tos)
        conn_state = rds_conn_path_state(rds_ib_conn.conn)

        if laddr and conn_laddr not in laddr_list:
            continue
        if faddr and conn_faddr not in faddr_list:
            continue
        if tos and str(conn_tos) not in tos_list:
            continue
        if states and not (
            any(state in conn_state.lower() for state in states_list)
        ):
            continue

        yield rds_ib_conn


def for_each_rds_ib_ipaddr(dev: Object) -> Iterable[Object]:
    """
    Provide the list of ``struct rds_ib_ipaddr`` as an iterable object

    :param dev: ``struct rds_ib_device`` Object.
    :returns: A list of ``struct rds_ib_ipaddr`` as an iterable object
    """
    return list_for_each_entry(
        "struct rds_ib_ipaddr", dev.ipaddr_list.address_of_(), "list"
    )


def for_each_rds_conn(
    prog: drgn.Program,
    laddr: Optional[str] = None,
    faddr: Optional[str] = None,
    tos: Optional[str] = None,
    states: Optional[str] = None,
) -> Iterator[Object]:
    """
    Provide the list of ``struct rds_connection`` from the conn hash list as an iterable object

    :param prog: drgn program
    :returns: A list of ``struct rds_connection`` as an iterable object
    """

    if laddr:
        laddr_list = fields_to_list(laddr)
    if faddr:
        faddr_list = fields_to_list(faddr)
    if tos:
        tos_list = fields_to_list(tos)
    if states:
        states_list = fields_to_list(states)

    conn_hash = prog["rds_conn_hash"]
    for conns in conn_hash:
        for conn in hlist_for_each_entry(
            "struct rds_connection", conns.address_of_(), "c_hash_node"
        ):
            conn_tos = int(conn.c_tos)
            conn_laddr = rds_inet_ntoa(conn.c_laddr)
            conn_faddr = rds_inet_ntoa(conn.c_faddr)
            conn_state = rds_conn_path_state(conn)
            if laddr and conn_laddr not in laddr_list:
                continue
            if faddr and conn_faddr not in faddr_list:
                continue
            if tos and str(conn_tos) not in tos_list:
                continue
            if states and not (
                any(state in conn_state.lower() for state in states_list)
            ):
                continue

            yield conn


def rds_get_stats(
    prog: drgn.Program, rds_stat_list: str, fields: Optional[List[str]] = None
) -> List[List[Any]]:
    """
    Get the rds stats and counters from the stat list provided.

    :param prog: drgn program
    :param rds_stat_list: The per_cpu list to get the stats from
    :param fields: The list of fields to filter the results on
    :returns: A nested list of the type [[stat_name, value], ...]
    """

    rds_stats = []
    stat_list: List[Object] = []
    for cpu in for_each_online_cpu(prog):
        stat_list.append(per_cpu(prog[rds_stat_list], cpu))

    attrs = [attr.name for attr in stat_list[0].type_.members if attr.name]
    stats = {attr: 0 for attr in attrs}
    for stat in stat_list:
        for attr in attrs:
            stats[attr] += stat.member_(attr)

    for attr in stats:
        fixed_attr = re.sub(r"^{0}".format(re.escape("s_")), "", attr)
        if fields and not (
            any(field in fixed_attr.lower() for field in fields)
        ):
            continue

        # Use a list of lists rather than list of tuples. This is so the
        # result can eventually be given directly to print_table() and
        # satisfy type checks.
        rds_stats.append([fixed_attr, int(stats[attr])])

    return rds_stats


class RdsIbConnInfo(NamedTuple):
    i_cm_id_val: int
    rdma_cm_state_val: str
    ib_cm_id_val: int
    ib_cm_state_val: str


def rds_get_ib_conn_info(ic: Object) -> RdsIbConnInfo:
    """
    Get the ``struct rds_ib_connection`` specific info

    :param ic: ``struct rds_ib_connection`` Object
    :returns: A namedtuple of type RdsIbConnInfo
    """

    i_cm_id_val = 0
    rdma_cm_state_val = "N/A"
    ib_cm_id_val = 0
    ib_cm_state_val = "N/A"

    ret = RdsIbConnInfo(
        i_cm_id_val,
        rdma_cm_state_val,
        ib_cm_id_val,
        ib_cm_state_val,
    )

    if ic is None:
        return ret

    i_cm_id = ic.i_cm_id
    ret = ret._replace(i_cm_id_val=i_cm_id.value_())

    if not i_cm_id:
        return ret

    id_priv = container_of(i_cm_id, "struct rdma_id_private", "id")
    ret = ret._replace(rdma_cm_state_val=rdma_cm_state(id_priv))

    ib_cm_id = cast("struct ib_cm_id *", id_priv.cm_id.ib)
    ret = ret._replace(ib_cm_id_val=ib_cm_id.value_())
    if ib_cm_id:
        ret = ret._replace(ib_cm_state_val=ib_cm_state(ib_cm_id))

    return ret


def rds_ip_state_list(dev: Object) -> Dict[str, Tuple[int, int]]:
    """
    The number of connections and its state associated to a rds_ib_device

    :param dev: ``struct rds_ib_device`` Object.
    :returns: A dictionary where IP is the key and the value is a tuple of the form (num_conns_up, num_conns)
    """
    ip_list: Dict[str, Tuple[int, int]] = {}
    for rds_ib_conn in for_each_rds_ib_conn(dev):
        ipaddr = str(rds_inet_ntoa(rds_ib_conn.conn.c_laddr))
        num_conns = 0
        num_conns_up = 0
        if ipaddr in ip_list:
            ip_state = ip_list[ipaddr]
            num_conns_up = ip_state[0]
            num_conns = ip_state[1]

        if rds_conn_path_state(rds_ib_conn.conn) == "RDS_CONN_UP":
            ip_list[ipaddr] = (num_conns_up + 1, num_conns + 1)
        else:
            ip_list[ipaddr] = (num_conns_up, num_conns + 1)
    return ip_list


def ensure_mlx_core_ib_debuginfo(prog: drgn.Program, dev_name: str) -> bool:
    """
    Ensure that the correct mlx[5/4]_core debuginfo is present.

    :param prog: drgn program
    :param dev_name: Name of the device
    :returns: True if the mlx_core module is present and false otherwise.
    """

    if "mlx5" in dev_name:
        module = ["mlx5_core", "mlx5_ib"]
    elif "mlx4" in dev_name:
        module = ["mlx4_core", "mlx4_ib"]
    else:
        return False

    msg = ensure_debuginfo(prog, module)
    if msg:
        print(msg)
        return False

    return True


# RDS Corelens module functions #


def rds_dev_info(
    prog: drgn.Program,
    ret: bool = False,
    outfile: Optional[str] = None,
    report: bool = False,
) -> Optional[List[Object]]:
    """
    Print the IB device info

    :param prog: drgn program
    :param ret: If true the function returns the ``struct rds_ib_device`` list and None if the arg is false
    :param outfile: A file to write the output to.
    :param report: Open the file in append mode. Used to generate a report of all the functions in the rds module.
    :returns: A List of ``struct rds_ib_device`` or None
    """

    msg = ensure_debuginfo(prog, ["rds"])
    if msg:
        print(msg)
        return None

    rds_ib_dev_list = []
    index = -1
    info: List[List[Any]] = [
        [
            "",  # index
            "rds_ib_device",
            "ib_device",
            "dev_name",
            "node_name",
            "IP (state)",
        ]
    ]
    for rds_ib_dev in for_each_rds_ib_device(prog):
        dev_name = rds_ib_dev.dev.name.string_().decode("utf-8")
        node_name = rds_ib_dev.dev.node_desc.string_().decode("utf-8")
        rds_ib_device = hex(rds_ib_dev.value_())
        ib_device = hex(rds_ib_dev.dev.value_())
        ip_list = rds_ip_state_list(rds_ib_dev)
        ip_str = ""
        for ip in for_each_rds_ib_ipaddr(rds_ib_dev):
            ipaddr = rds_inet_ntoa(ip.ipaddr)
            num_conns = 0
            num_conns_up = 0
            if ipaddr in ip_list:
                ip_state = ip_list[ipaddr]
                num_conns_up = ip_state[0]
                num_conns = ip_state[1]
            ip_str += f" {ipaddr}({num_conns_up}/{num_conns})"

        index += 1
        rds_ib_dev_list.append(rds_ib_dev)
        info.append(
            [index, rds_ib_device, ib_device, dev_name, node_name, ip_str]
        )

    print_table(info, outfile, report)

    if ret:
        return rds_ib_dev_list
    else:
        return None


def rds_stats(
    prog: drgn.Program,
    fields: Optional[str] = None,
    outfile: Optional[str] = None,
    report: bool = False,
) -> None:
    """
    Print the RDS stats and counters.

    :param prog: drgn program
    :param fields: List of comma separated fields to print. It also supports substring matching for the fields provided. Ex: 'conn_reset,  ib_tasklet_call, send, ...'
    :param outfile: A file to write the output to.
    :param report: Open the file in append mode. Used to generate a report of all the functions in the rds module.
    :returns: None
    """
    msg = ensure_debuginfo(prog, ["rds"])
    if msg:
        print(msg)
        return

    fields_list = None
    if fields:
        fields_list = fields_to_list(fields)

    rds_stats: List[List[Any]] = [["CounterName", "Value"]]

    rds_stats.extend(rds_get_stats(prog, "rds_stats", fields_list))
    rds_stats.extend(rds_get_stats(prog, "rds_ib_stats", fields_list))

    print_table(rds_stats, outfile, report)


def rds_conn_info(
    prog: drgn.Program,
    laddr: Optional[str] = None,
    faddr: Optional[str] = None,
    tos: Optional[str] = None,
    state: Optional[str] = None,
    ret: bool = False,
    outfile: Optional[str] = None,
    report: bool = False,
) -> Optional[List[Object]]:
    """
    Display all RDS connections

    :param prog: drgn program
    :param laddr: comma separated string list of LOCAL-IP.  Ex: '192.168.X.X, 10.211.X.X, ...'
    :param faddr: comma separated string list of REMOTE-IP.  Ex: '192.168.X.X, 10.211.X.X, ...'
    :param tos: comma separated string list of TOS.  Ex: '0, 3, ...'
    :param state: comma separated string list of conn states. Ex 'RDS_CONN_UP, CONNECTING, ...'
    :param ret: If true the function returns the ``struct rds_ib_connection`` list and None if the arg is false
    :param outfile: A file to write the output to.
    :param report: Open the file in append mode. Used to generate a report of all the functions in the rds module.
    :returns: A List of ``struct rds_ib_connection`` that match the filters provided or None
    """
    msg = ensure_debuginfo(prog, ["rds"])
    if msg:
        print(msg)
        return None

    index = -1
    ib_conn_list = []
    conn_list: List[List[Any]] = [
        [
            "",  # index
            "rds_conn",
            "ib_conn",
            "Conn Path",
            "ToS",
            "Local Addr",
            "Remote Addr",
            "State",
            "NextTX",
            "NextRX",
            "Flags",
            "Conn-Time",
            "i_cm_id",
            "RDMA CM State",
            "ib_cm_id",
            "IB CM State",
        ]
    ]
    for conn in for_each_rds_conn(prog, laddr, faddr, tos, state):
        conn_val = hex(conn.value_())
        trans_name = "".join(re.findall('"([^"]*)"', str(conn.c_trans.t_name)))
        if trans_name == "infiniband":
            ic: Any = cast(
                "struct rds_ib_connection *", conn.c_path.cp_transport_data
            )
            ib_conn = hex(ic.value_())
        else:
            ic = None
            ib_conn = "N/A"
        conn_tos = int(conn.c_tos)
        conn_path = hex(conn.c_path.value_())
        conn_laddr = rds_inet_ntoa(conn.c_laddr)
        conn_faddr = rds_inet_ntoa(conn.c_faddr)
        conn_state = rds_conn_path_state(conn)
        conn_next_tx = int(conn.c_path.cp_next_tx_seq.value_())
        conn_next_rx = int(conn.c_path.cp_next_rx_seq.value_())
        conn_time = "N/A"
        if conn_state == "RDS_CONN_UP":
            conn_time = str(get_connection_uptime(conn))
        flags = "----"
        if conn_state == "RDS_CONN_UP":
            flags = flags[:2] + "C" + flags[3:]
        if conn_state == "RDS_CONN_CONNECTING":
            flags = flags[:1] + "c" + flags[2:]
        if int(conn.c_path.cp_flags.value_()) & RDS_IN_XMIT:
            flags = "s" + flags[1:]
        if int(conn.c_path.cp_pending_flush):
            flags = flags[:3] + "E"

        ib_conn_info = rds_get_ib_conn_info(ic)

        index += 1
        ib_conn_list.append(ic)
        conn_list.append(
            [
                index,
                conn_val,
                ib_conn,
                conn_path,
                conn_tos,
                conn_laddr,
                conn_faddr,
                conn_state,
                conn_next_tx,
                conn_next_rx,
                flags,
                conn_time,
                hex(ib_conn_info.i_cm_id_val),
                ib_conn_info.rdma_cm_state_val,
                hex(ib_conn_info.ib_cm_id_val),
                ib_conn_info.ib_cm_state_val,
            ]
        )

    print_table(conn_list, outfile, report)

    if ret:
        return ib_conn_list
    else:
        return None


def rds_ib_conn_ring_info(
    prog_or_obj: Union[Program, Object], ic_ptr: Optional[int] = None
) -> None:
    """
    Display the ring info for a particular RDS connection.

    :param prog_or_obj: drgn program or ``struct rds_ib_connection`` Object
    :param ic_ptr: ``struct rds_ib_connection`` address as an integer.
    :returns: None
    """
    if ic_ptr == 0xDEADBEEF:
        return

    if isinstance(prog_or_obj, Program):
        if ic_ptr is None:
            raise ValueError("Provide a connection pointer")
        prog = prog_or_obj
        ic = Object(prog, "struct rds_ib_connection *", value=ic_ptr)
        ic_addr: int = ic_ptr
    else:
        prog = prog_or_obj.prog_
        ic = prog_or_obj
        ic_addr = ic.value_()

    msg = ensure_debuginfo(prog, ["rds"])
    if msg:
        print(msg)
        return

    ring_info = [
        [
            "Ring",
            "ptr",
            "NR",
            "Alloc",
            "Free",
            "Entries",
            "Alloc_ctr",
            "Free_ctr",
        ]
    ]
    conn = ic.conn
    cp = conn.c_path
    conn_laddr = rds_inet_ntoa(conn.c_laddr)
    conn_faddr = rds_inet_ntoa(conn.c_faddr)
    conn_tos = conn.c_tos.value_()
    sring = ic.i_send_ring
    rring = ic.i_recv_ring

    print(
        "\nDetails of rds connection - <{},{},{}>\n".format(
            conn_laddr, conn_faddr, conn_tos
        )
    )
    print(
        "rds_connection={} rds_conn_path={} rds_ib_connection={}\n".format(
            hex(conn.value_()), hex(cp.value_()), hex(ic_addr)
        )
    )
    ring_info.append(
        [
            "SEND",
            hex(sring.address_),
            sring.w_nr.value_(),
            sring.w_alloc_ptr.value_(),
            sring.w_free_ptr.value_(),
            (sring.w_alloc_ctr.value_() - sring.w_free_ctr.counter.value_()),
            sring.w_alloc_ctr.value_(),
            sring.w_free_ctr.counter.value_(),
        ]
    )
    ring_info.append(
        [
            "RECV",
            hex(rring.address_),
            rring.w_nr.value_(),
            rring.w_alloc_ptr.value_(),
            rring.w_free_ptr.value_(),
            (rring.w_alloc_ctr.value_() - rring.w_free_ctr.counter.value_()),
            rring.w_alloc_ctr.value_(),
            rring.w_free_ctr.counter.value_(),
        ]
    )

    print_table(ring_info)


def rds_info_verbose(
    prog: drgn.Program,
    laddr: Optional[str] = None,
    faddr: Optional[str] = None,
    tos: Optional[str] = None,
    fields: Optional[str] = None,
    ret: bool = False,
    outfile: Optional[str] = None,
    report: bool = False,
) -> Optional[List[Object]]:
    """
    Print the rds conn stats similar to rds-info -Iv

    :param prog: drgn program
    :param laddr: comma separated string list of LOCAL-IP.  Ex: '192.168.X.X, 10.211.X.X, ...'
    :param faddr: comma separated string list of REMOTE-IP.  Ex: '192.168.X.X, 10.211.X.X, ...'
    :param tos: comma separated string list of TOS.  Ex: '0, 3, ...'
    :param fields: List of comma separated fields to display. It also supports substring matching for the fields provided.  Ex: 'Recv_alloc_ctr,  Cache Allocs, Tx, ...'
    :param ret: If true the function returns the ``struct rds_ib_connection`` list and None if the arg is false
    :param outfile: A file to write the output to.
    :param report: Open the file in append mode. Used to generate a report of all the functions in the rds module.
    :returns: A List of ``struct rds_ib_connection`` that match the filters provided or None
    """
    msg = ensure_debuginfo(prog, ["rds"])
    if msg:
        print(msg)
        return None

    now = prog["jiffies"]
    ics = []
    index = -1
    conn_info: List[List[Any]] = [
        [
            "",  # index
            "LocalAddr",
            "RemoteAddr",
            "Tos",
            "SL",
            "SrcQPNo",
            "DstQPNo",
            "Cache_allocs",
            "Recv_alloc_ctr",
            "Recv_free_ctr",
            "Send_alloc_ctr",
            "Send_free_ctr",
            "Send_bytes KiB",
            "Recv_bytes KiB",
            "R_read_bytes KiB",
            "R_write_bytes KiB",
            "Tx_poll_ts_jiffies",
            "Rx_poll_ts_jiffies",
            "Tx_poll_cnt",
            "Rx_poll_cnt",
            "SCQ vector",
            "RCQ vector",
            "SND IRQN",
            "RCV IRQN",
        ]
    ]
    for rds_ib_dev in for_each_rds_ib_device(prog):
        dev_name = rds_ib_dev.dev.name.string_().decode("utf-8")
        debuginfo = ensure_mlx_core_ib_debuginfo(prog, dev_name)
        for con in for_each_rds_ib_conn(rds_ib_dev, laddr, faddr, tos):
            conn_laddr = rds_inet_ntoa(con.conn.c_laddr)
            conn_faddr = rds_inet_ntoa(con.conn.c_faddr)
            conn_tos = int(con.conn.c_tos)
            try:
                srcqpnum: Any = int(con.i_qp_num)
            except AttributeError:
                srcqpnum = "N/A"
            try:
                dstqpnum: Any = int(con.i_dst_qp_num)
            except AttributeError:
                dstqpnum = "N/A"
            sl = int(con.i_sl)
            cache_allocs = int(con.i_cache_allocs.counter)
            recv_free_ctr = int(con.i_recv_ring.w_free_ctr.counter)
            try:
                recv_alloc_ctr = int(con.i_recv_ring.w_alloc_ctr)
            except TypeError:
                recv_alloc_ctr = int(con.i_recv_ring.w_alloc_ctr.counter)
            try:
                send_alloc_ctr = int(con.i_send_ring.w_alloc_ctr)
            except TypeError:
                send_alloc_ctr = int(con.i_send_ring.w_alloc_ctr.counter)
            send_free_ctr = int(con.i_send_ring.w_free_ctr.counter)
            send_bytes = 0
            recv_bytes = 0

            try:
                send_bytes = int((con.conn.c_send_bytes.value_())["counter"])
                send_bytes_kB = "{:0.2f}".format(send_bytes / 1024)
            except AttributeError:
                send_bytes_kB = "N/A"

            try:
                recv_bytes = int((con.conn.c_recv_bytes.value_())["counter"])
                recv_bytes_kB = "{:0.2f}".format(recv_bytes / 1024)
            except AttributeError:
                recv_bytes_kB = "N/A"

            try:
                r_read_bytes = int((con.i_r_read_bytes.value_())["counter"])
                r_read_bytes_kB = "{:0.2f}".format(r_read_bytes / 1024)
            except AttributeError:
                r_read_bytes_kB = "N/A"

            try:
                r_write_bytes = int((con.i_r_write_bytes.value_())["counter"])
            except AttributeError:
                r_read_bytes_kB = "N/A"

            try:
                r_write_bytes = int((con.i_r_write_bytes.value_())["counter"])
                r_write_bytes_kB = "{:0.2f}".format(r_write_bytes / 1024)
            except AttributeError:
                r_write_bytes_kB = "N/A"

            try:
                tx_poll_ts = str(int(now - con.i_tx_poll_ts.value_()))
            except AttributeError:
                tx_poll_ts = "N/A"

            try:
                rx_poll_ts = str(int(now - con.i_rx_poll_ts.value_()))
            except AttributeError:
                rx_poll_ts = "N/A"

            try:
                tx_poll_cnt = str(int((con.i_tx_poll_cnt.value_())["counter"]))
            except AttributeError:
                tx_poll_cnt = "N/A"

            try:
                rx_poll_cnt = str(int((con.i_rx_poll_cnt.value_())["counter"]))
            except AttributeError:
                rx_poll_cnt = "N/A"

            try:
                scq_vector = str(int(con.i_scq_vector.value_()))
            except AttributeError:
                scq_vector = "N/A"

            try:
                rcq_vector = str(int(con.i_rcq_vector.value_()))
            except AttributeError:
                rcq_vector = "N/A"

            if debuginfo:
                is_mlx5 = False
                if "mlx5" in dev_name:
                    mlx_ib_cq = "struct mlx5_ib_cq"
                    mlx_core_cq = "struct mlx5_core_cq *"
                    is_mlx5 = True
                elif "mlx4" in dev_name:
                    mlx_ib_cq = "struct mlx4_ib_cq"
                    mlx_core_cq = "struct mlx4_cq *"

                try:
                    scq = container_of(con.i_scq, mlx_ib_cq, "ibcq")
                    send_mcq = cast(mlx_core_cq, scq.mcq.address_of_())
                    if is_mlx5:
                        snd_irqn = hex(send_mcq.irqn)
                    else:
                        snd_irqn = hex(send_mcq.irq)
                except AttributeError:
                    snd_irqn = "N/A"

                try:
                    rcq = container_of(con.i_rcq, mlx_ib_cq, "ibcq")
                    recv_mcq = cast(mlx_core_cq, rcq.mcq.address_of_())
                    if is_mlx5:
                        rcv_irqn = hex(recv_mcq.irqn)
                    else:
                        rcv_irqn = hex(recv_mcq.irq)
                except AttributeError:
                    rcv_irqn = "N/A"
            else:
                snd_irqn = "N/A"
                rcv_irqn = "N/A"

            ics.append(con)
            index += 1
            conn_info.append(
                [
                    index,
                    conn_laddr,
                    conn_faddr,
                    conn_tos,
                    sl,
                    srcqpnum,
                    dstqpnum,
                    cache_allocs,
                    recv_alloc_ctr,
                    recv_free_ctr,
                    send_alloc_ctr,
                    send_free_ctr,
                    send_bytes_kB,
                    recv_bytes_kB,
                    r_read_bytes_kB,
                    r_write_bytes_kB,
                    tx_poll_ts,
                    rx_poll_ts,
                    tx_poll_cnt,
                    rx_poll_cnt,
                    scq_vector,
                    rcq_vector,
                    snd_irqn,
                    rcv_irqn,
                ]
            )

    index_list = []
    if fields:
        fields += ", LocalAddr, RemoteAddr, ToS, SL, SrcQPNo, DstQPNo"
        fields_list = fields_to_list(fields)
        for col in conn_info[0]:
            if col == " ":
                continue
            if not (any(field in col.lower() for field in fields_list)):
                index_list.append(conn_info[0].index(col))

    index_list.sort(reverse=True)
    for index in index_list:
        for col in conn_info:
            del col[index]

    print_table(conn_info, outfile, report)

    if ret:
        return ics
    else:
        return None


def rds_sock_info(
    prog: drgn.Program,
    ret: bool = False,
    outfile: Optional[str] = None,
    report: bool = False,
) -> Optional[List[Object]]:
    """
    Print the rds socket info similar to rds-tools -k

    :param prog: drgn program
    :param ret: If true the function returns the ``struct rds_sock`` list and None if the arg is false
    :param outfile: A file to write the output to.
    :param report: Open the file in append mode. Used to generate a report of all the functions in the rds module.
    :returns: A List of ``struct rds_sock`` or None
    """
    msg = ensure_debuginfo(prog, ["rds"])
    if msg:
        print(msg)
        return None

    index = -1
    sock_list = []
    fields: List[List[Any]] = [
        [
            "",  # index
            "BoundAddr",
            "Bport",
            "ConnAddr",
            "CPort",
            "SndBuf",
            "RcvBuf",
            "Inode",
            "Cong",
            "Pid",
            "Comm",
        ]
    ]
    for sock in for_each_rds_sock(prog):
        sin6_addr = sock.rs_bound_sin6.sin6_addr
        bound_addr = sin6_addr
        local_ip = rds_inet_ntoa(bound_addr)
        bport = struct.unpack("!H", sock.rs_bound_sin6.sin6_port.to_bytes_())[
            0
        ]
        conn_addr = sock.rs_conn_addr
        local_conn_ip = rds_inet_ntoa(conn_addr)
        conn_port = int(sock.rs_conn_port)
        try:
            pid: Any = int(sock.rs_pid.value_())
            task = find_task(prog, pid)
            comm: Any = "".join(re.findall('"([^"]*)"', str(task.comm)))
        except AttributeError:
            pid = "N/A"
            comm = "N/A"
        try:
            cong: Any = int(sock.rs_congested)
        except AttributeError:
            cong = "N/A"
        send_buf = rds_sk_sndbuf(sock)
        recv_buf = rds_sk_rcvbuf(sock)
        if sock.rs_sk.sk_socket:
            sock_inode = container_of(
                sock.rs_sk.sk_socket, "struct socket_alloc", "socket"
            ).vfs_inode
            inum = int(sock_inode.i_ino)
        else:
            inum = 0

        index += 1
        sock_list.append(sock)
        fields.append(
            [
                index,
                local_ip,
                bport,
                local_conn_ip,
                conn_port,
                send_buf,
                recv_buf,
                inum,
                cong,
                pid,
                comm,
            ]
        )
    print_table(fields, outfile, report)

    if ret:
        return sock_list
    else:
        return None


def rds_print_recv_msg_queue(
    prog: drgn.Program,
    laddr: Optional[str] = None,
    raddr: Optional[str] = None,
    tos: Optional[str] = None,
    lport: Optional[str] = None,
    rport: Optional[str] = None,
    ret: Optional[bool] = False,
    outfile: Optional[str] = None,
    report: bool = False,
) -> None:
    """
    Print the rds recv msg queue similar rds-info -r

    :param prog: drgn program
    :param laddr: comma separated string list of LOCAL-IP.  Ex: '192.168.X.X, 10.211.X.X, ...'
    :param raddr: comma separated string list of REMOTE-IP.  Ex: '192.168.X.X, 10.211.X.X, ...'
    :param tos: comma separated string list of TOS.  Ex: '0, 3, ...'
    :param lport: comma separated string list of lport.  Ex: 2259, 36554, ...'
    :param rport: comma separated string list of rport.  Ex: 2259, 36554, ...'
    :param outfile: A file to write the output to.
    :param report: Open the file in append mode. Used to generate a report of all the functions in the rds module.
    :returns: None

    """

    index = -1
    msg_queue = Table(
        [
            " ",
            "LocalAddr",
            "LPort",
            "RemoteAddr",
            "RPort",
            "Tos",
            "Seq",
            "Bytes",
        ],
        outfile=outfile,
        report=report,
    )

    if laddr:
        laddr_list = fields_to_list(laddr)
    if raddr:
        raddr_list = fields_to_list(raddr)
    if tos:
        tos_list = fields_to_list(tos)
    if lport:
        lport_list = fields_to_list(lport)
    if rport:
        rport_list = fields_to_list(rport)

    rds_sock_list_p = prog["rds_sock_list"].address_of_()

    for rs in list_for_each_entry(
        "struct rds_sock", rds_sock_list_p, "rs_item"
    ):
        for inc in list_for_each_entry(
            "struct rds_incoming", rs.rs_recv_queue.address_of_(), "i_item"
        ):
            lport_rm = be16_to_host(prog, inc.i_hdr.h_dport)
            rport_rm = be16_to_host(prog, inc.i_hdr.h_sport)
            seq = be64_to_host(prog, inc.i_hdr.h_sequence)
            num_bytes = be32_to_host(prog, inc.i_hdr.h_len)
            local_addr = rds_inet_ntoa(rs.rs_bound_sin6.sin6_addr)
            remote_addr = rds_inet_ntoa(inc.i_saddr)
            tos_rm = int(inc.i_conn.c_tos)

            if laddr and local_addr not in laddr_list:
                continue
            if raddr and remote_addr not in raddr_list:
                continue
            if tos and str(tos_rm) not in tos_list:
                continue
            if lport and str(lport_rm) not in lport_list:
                continue
            if rport and str(rport_rm) not in rport_list:
                continue

            index = index + 1
            msg_queue.row(
                index,
                local_addr,
                lport_rm,
                remote_addr,
                rport_rm,
                tos_rm,
                seq,
                num_bytes,
            )

    print("Receive Message Queue:")
    msg_queue.write()
    return None


def rds_print_send_retrans_msg_queue(
    prog: drgn.Program,
    queue: str,
    laddr: Optional[str] = None,
    raddr: Optional[str] = None,
    tos: Optional[str] = None,
    lport: Optional[str] = None,
    rport: Optional[str] = None,
    ret: Optional[bool] = False,
    outfile: Optional[str] = None,
    report: bool = False,
) -> None:
    """
    Print the rds send or retransmit msg queue similar rds-info -st

    :param prog: drgn program
    :prarm queue: The msg queue to be displaed. Ex: 'send', 'recv'
    :param laddr: comma separated string list of LOCAL-IP.  Ex: '192.168.X.X, 10.211.X.X, ...'
    :param raddr: comma separated string list of REMOTE-IP.  Ex: '192.168.X.X, 10.211.X.X, ...'
    :param tos: comma separated string list of TOS.  Ex: '0, 3, ...'
    :param lport: comma separated string list of lport.  Ex: 2259, 36554, ...'
    :param rport: comma separated string list of rport.  Ex: 2259, 36554, ...'
    :param outfile: A file to write the output to.
    :param report: Open the file in append mode. Used to generate a report of all the functions in the rds module.
    :returns: None

    """
    index = -1
    msg_queue = Table(
        [
            " ",
            "LocalAddr",
            "LPort",
            "RemoteAddr",
            "RPort",
            "Tos",
            "Seq",
            "Bytes",
        ],
        outfile=outfile,
        report=report,
    )

    if laddr:
        laddr_list = fields_to_list(laddr)
    if raddr:
        raddr_list = fields_to_list(raddr)
    if tos:
        tos_list = fields_to_list(tos)
    if lport:
        lport_list = fields_to_list(lport)
    if rport:
        rport_list = fields_to_list(rport)

    conn_hash = prog["rds_conn_hash"]
    for conns in conn_hash:
        for conn in hlist_for_each_entry(
            "struct rds_connection", conns.address_of_(), "c_hash_node"
        ):
            conn_tos = int(conn.c_tos)
            conn_laddr = rds_inet_ntoa(conn.c_laddr)
            conn_raddr = rds_inet_ntoa(conn.c_faddr)
            cp = cast("struct rds_conn_path *", conn.c_path)
            if queue.lower() == "send":
                msg_list = cp.cp_send_queue
            elif queue.lower() == "retrans":
                msg_list = cp.cp_retrans
            else:
                print("Invalid queue name provided in args !")
                return None

            for rm in list_for_each_entry(
                "struct rds_message", msg_list.address_of_(), "m_conn_item"
            ):
                lport_rm = be16_to_host(prog, rm.m_inc.i_hdr.h_sport)
                rport_rm = be16_to_host(prog, rm.m_inc.i_hdr.h_dport)
                seq = be64_to_host(prog, rm.m_inc.i_hdr.h_sequence)
                num_bytes = be32_to_host(prog, rm.m_inc.i_hdr.h_len)

                if laddr and conn_laddr not in laddr_list:
                    continue
                if raddr and conn_raddr not in raddr_list:
                    continue
                if tos and str(conn_tos) not in tos_list:
                    continue
                if lport and str(lport_rm) not in lport_list:
                    continue
                if rport and str(rport_rm) not in rport_list:
                    continue

                index = index + 1
                msg_queue.row(
                    index,
                    conn_laddr,
                    lport_rm,
                    conn_raddr,
                    rport_rm,
                    conn_tos,
                    seq,
                    num_bytes,
                )

    if queue.lower() == "send":
        print("Send Message Queue:")
    elif queue.lower() == "retrans":
        print("Retransmit Message Queue:")

    msg_queue.write()
    return None


def rds_print_msg_queue(
    prog: drgn.Program,
    queue: str = "All",
    laddr: Optional[str] = None,
    raddr: Optional[str] = None,
    tos: Optional[str] = None,
    lport: Optional[str] = None,
    rport: Optional[str] = None,
    ret: Optional[bool] = False,
    outfile: Optional[str] = None,
    report: bool = False,
) -> None:
    """
    Print the rds msg queue similar rds-info -srt

    :param prog: drgn program
    :prarm queue: The msg queue to be displaed. Ex: 'send', 'recv' , 'retrans', 'All'. Default: 'All'
    :param laddr: comma separated string list of LOCAL-IP.  Ex: '192.168.X.X, 10.211.X.X, ...'
    :param raddr: comma separated string list of REMOTE-IP.  Ex: '192.168.X.X, 10.211.X.X, ...'
    :param tos: comma separated string list of TOS.  Ex: '0, 3, ...'
    :param lport: comma separated string list of lport.  Ex: 2259, 36554, ...'
    :param rport: comma separated string list of rport.  Ex: 2259, 36554, ...'
    :param outfile: A file to write the output to.
    :param report: Open the file in append mode. Used to generate a report of all the functions in the rds module.
    :returns: None

    """
    msg = ensure_debuginfo(prog, ["rds"])
    if msg:
        print(msg)
        return None

    queue = queue.lower()
    if queue not in ("all", "send", "snd", "retrans", "re", "recv", "rcv"):
        print(
            f"Unknown queue type '{queue}'. Expected: all, send, retrans, or recv"
        )
        return
    if queue in ("send", "snd", "all"):
        rds_print_send_retrans_msg_queue(
            prog, "send", laddr, raddr, tos, lport, rport, ret, outfile, report
        )
        print("\n")
    if queue in ("retrans", "re", "all"):
        rds_print_send_retrans_msg_queue(
            prog,
            "retrans",
            laddr,
            raddr,
            tos,
            lport,
            rport,
            ret,
            outfile,
            report,
        )
        print("\n")
    if queue in ("recv", "rcv", "all"):
        rds_print_recv_msg_queue(
            prog, laddr, raddr, tos, lport, rport, ret, outfile, report
        )


def print_mr_list_head_info(
    prog: drgn.Program, list_head: Object, pool_name: str, list_name: str
) -> None:
    """
    Print the specific MR list info for busy_list or clean_list

    :pram prog: drgn.Program
    :param list_head: The ``struct list_head`` Object
    :param pool_name: The name of the pool the given list belongs to.
    :param list_name: The name of the list. Ex 'busy_list', 'clean_list'
    :returns: None

    """
    if list_empty(list_head.address_of_()):
        print("\nrds_ib_mr->{}->{} is empty!\n".format(pool_name, list_name))
        return
    index = 0

    list_info = Table(
        [
            "Index",
            "IB device",
            "RDS_IB_MR",
            "IB_MR",
            "lkey",
            "rkey",
            "page_size",
            "need_inval",
            "mr_type",
            "length",
            "pd",
        ],
        outfile=None,
        report=False,
    )

    for list_ptr in list_for_each(list_head.address_of_()):
        rds_ib_mr = container_of(list_ptr, "struct rds_ib_mr", "pool_list")
        rds_ib_mr_addr = hex(rds_ib_mr.value_())
        ib_mr = cast("struct ib_mr *", rds_ib_mr.mr)
        if ib_mr.value_() == 0x0:
            continue
        ib_mr_addr = hex(ib_mr.value_())
        lkey = int(ib_mr.lkey)
        rkey = int(ib_mr.rkey)
        page_size = int(ib_mr.page_size)
        need_inval = bool(ib_mr.need_inval)
        mr_type = ib_mr.type.format_(type_name=False)
        length = int(ib_mr.length)
        device_addr = hex(ib_mr.device.value_())
        pd_addr = hex(ib_mr.pd.value_())
        list_info.row(
            index,
            device_addr,
            rds_ib_mr_addr,
            ib_mr_addr,
            lkey,
            rkey,
            page_size,
            need_inval,
            mr_type,
            length,
            pd_addr,
        )
        index = index + 1
    print("\nrds_ib_mr->{}->{}\n".format(pool_name, list_name))
    list_info.write()


def rds_get_mr_list_info(
    prog_or_obj: Union[Program, Object], dev_ptr: Optional[int] = None
) -> None:
    """
    Print the MR list info

    :param prog_or_obj: drgn program or ``struct rds_ib_device`` Object
    :prarm dev_ptr: ``struct rds_ib_device`` address as an integer.
    returns: None
    """

    if isinstance(prog_or_obj, Program):
        if dev_ptr is None:
            raise ValueError("Provide a rds_ib_device pointer")
        prog = prog_or_obj
        dev = cast("struct rds_ib_device *", dev_ptr)
    else:
        prog = prog_or_obj.prog_
        dev = prog_or_obj

    msg = ensure_debuginfo(prog, ["rds"])
    if msg:
        print(msg)
        return

    rds_mr_1m_pool = cast("struct rds_ib_mr_pool *", dev.mr_1m_pool)
    rds_mr_8k_pool = cast("struct rds_ib_mr_pool *", dev.mr_8k_pool)

    print_mr_list_head_info(
        prog, rds_mr_8k_pool.busy_list, "rds_mr_8k_pool", "busy_list"
    )
    print_mr_list_head_info(
        prog, rds_mr_8k_pool.clean_list, "rds_mr_8k_pool", "clean_list"
    )
    print_mr_list_head_info(
        prog, rds_mr_1m_pool.busy_list, "rds_mr_1m_pool", "busy_list"
    )
    print_mr_list_head_info(
        prog, rds_mr_1m_pool.clean_list, "rds_mr_1m_pool", "clean_list"
    )


def report(prog: drgn.Program, outfile: Optional[str] = None) -> None:
    """
    Generate a report of RDS related data.
    This functions runs all the functions in the module and saves the results to the output file provided.

    :param prog: drgn.Program
    :param outfile: A file to write the output to.
    :returns: None
    """
    msg = ensure_debuginfo(prog, ["rds"])
    if msg:
        print(msg)
        return None

    rds_dev_info(prog, outfile=outfile, report=False)
    rds_sock_info(prog, outfile=outfile, report=True)
    rds_conn_info(prog, outfile=outfile, report=True)
    rds_info_verbose(prog, outfile=outfile, report=True)
    rds_stats(prog, outfile=outfile, report=True)
    rds_print_msg_queue(prog, queue="All", outfile=outfile, report=True)


class Rds(CorelensModule):
    """Print info about RDS devices, sockets, connections, and stats"""

    name = "rds"
    skip_unless_have_kmod = "rds"

    # We access information from the following modules #
    debuginfo_kmods = ["mlx5_core", "mlx4_core", "mlx5_ib", "mlx4_ib"]

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        report(prog)
        rds_ib_conn_ring_info(prog, 0xDEADBEEF)
