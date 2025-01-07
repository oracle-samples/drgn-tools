# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper for iscsi
"""
import argparse
from typing import Iterator
from typing import Dict
from typing import Any

import drgn
import socket
from drgn import cast

from drgn import Object
from drgn import Program
from drgn.helpers.common import escape_ascii_string
from drgn.helpers.common.type import enum_type_to_class
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.corelens import CorelensModule
from drgn_tools.module import ensure_debuginfo
from drgn_tools.scsi import for_each_scsi_host
from drgn_tools.scsi import for_each_scsi_host_device
from drgn_tools.scsi import host_module_name
from drgn_tools.scsi import scsi_device_name
from drgn_tools.table import print_dictionary
from drgn_tools.util import enum_name_get

# Available Hardware and Software iSCSI Transports
iscsi_transports = ["bnx2i",
                    "cxgb3i",
                    "cxgb4i",
                    "iser",
                    "qedi",
                    "bfin dpmc",
                    "h1940-bt",
                    "tcp"]

# iSCSI Session States
iscsi_session_states = ["UNKNOWN",
                        "FREE",
                        "LOGGED_IN",
                        "FAILED",
                        "TERMINATE",
                        "IN_RECOVERY",
                        "RECOVERY_FAILED",
                        "LOGGING_OUT"
                        ]

# iSCSI Connection Stages
iscsi_connection_stages = ["INITIAL_STAGE",
                           "STARTED",
                           "STOPPED",
                           "CLEANUP_WAIT"
                           ]
# iSCSI Connection States
iscsi_connection_states = ["UP",
                           "DOWN",
                           "FAILED",
                           "BOUND"
                           ]

# SCSI device States
scsi_device_states = ["unknown",
                      "created",
                      "running",
                      "cancel",
                      "del",
                      "quiesce",
                      "offline",
                      "transport offline",
                      "blocked",
                      "created block"
                      ]

# Scsi_Host states
scsi_host_states = ["UNKNOWN",
                    "CREATED",
                    "RUNNING",
                    "CANCEL",
                    "DEL",
                    "RECOVERY",
                    "CANCEL_RECOVERY",
                    "DEL_RECOVERY"
                    ]
# Sub-Headings
sub_headings = ["Interface",
                "CHAP",
                "Timeouts",
                "Negotiated iSCSI params",
                "Attached SCSI devices"
                ]

def print_iscsi_info(info: Dict[str, Any]) -> None:
    for line in info:
        if "Target IQN" in line:
            print(f"{line}: {info[line]}")
        elif line == "Current Portal" or line == "Persistent Portal":
            print(f"\t{line}: {info[line]}")
        elif any(line in s for s in sub_headings):
            print(f"\t\t"+"*" * (len(line) + 1))
            print(f"\t\t{line}: {info[line]}")
            print(f"\t\t"+"*" * (len(line) + 1))
        else:
            print(f"\t\t{line}: {info[line]}")

def for_each_iscsi_host(prog: Program) -> Iterator[Object]:
    """
    Iterate through all scsi host devices and returns an
    iterator of hosts backed by iscsi drivers.
    :returns: an iterator of ``struct Scsi_Host *``
    """

    # additional iscsi drivers
    ISCSI_MODS = [
        "qla4xxx",
        "bnx2i",
        "cxgb3i",
        "cxgb4i",
        "qedi",
        "iscsi_tcp",
        "be2iscsi",
    ]
    for shost in for_each_scsi_host(prog):
        mod_name = host_module_name(shost).lower()
        if mod_name in ISCSI_MODS:
            yield shost


def for_each_iscsi_session(prog: Program) -> Iterator[Object]:
    """
    Iterate through all iscsi_cls_session and gets the associated iscsi_session.
    :returns: an iterator of ``struct iscsi_session *``

    """
    for cls_session in list_for_each_entry(
        "struct iscsi_cls_session", prog["sesslist"].address_of_(), "sess_list"
    ):
        yield Object(
            prog,
            prog.type("struct iscsi_session", filename="libiscsi.h"),
            address=cls_session.dd_data,
        )

def get_iscsi_info(iscsi_conn: Object, prog: Program ) -> Dict[str, Any]:

    iscsi_session = iscsi_conn.session
    iscsi_cls_conn = iscsi_conn.cls_conn
    iscsi_cls_session = iscsi_session.cls_session
    iscsi_tcp_conn = cast("struct iscsi_tcp_conn *", iscsi_conn.dd_data)
    iscsi_sw_tcp_conn = cast("struct iscsi_sw_tcp_conn *", iscsi_tcp_conn.dd_data)
    iscsi_socket = iscsi_sw_tcp_conn.sock
    iscsi_sock = iscsi_socket.sk
    scsi_host = iscsi_session.host
    iscsi_host_data = scsi_host.hostdata
    iscsi_host = cast("struct iscsi_host *", iscsi_host_data)

    try:
        if iscsi_sock.__sk_common.skc_family == 2:
            current_address = iscsi_sock.__sk_common.skc_daddr
            current_address = prog.read_u32(current_address.address_of_())
            current_ip = socket.inet_ntoa(bytes([(current_address) & 0xFF,
                                        (current_address >> 8) & 0xFF,
                                        (current_address >> 16) & 0xFF,
                                        (current_address >> 24) & 0xFF]))
            current_port = iscsi_sock.__sk_common.skc_dport
            current_port = prog.read_u16(current_port.address_of_())
            current_port = socket.ntohs(current_port)
            local_address = iscsi_sock.__sk_common.skc_rcv_saddr
            local_address = prog.read_u32(local_address.address_of_())
            local_ip = socket.inet_ntoa(bytes([(local_address) & 0xFF,
                                        (local_address >> 8) & 0xFF,
                                        (local_address >> 16) & 0xFF,
                                        (local_address >> 24) & 0xFF]))
    except  drgn.FaultError:
            current_ip = "[default]"
            local_ip = "[default]"
            current_port = ""
    return {
            "Target IQN":escape_ascii_string(iscsi_session.targetname.string_()),
            "Current Portal":(current_ip+":"+str(current_port)),
            "Persistent Portal": escape_ascii_string(iscsi_conn.persistent_address.string_())+
                                ":"+str(iscsi_conn.persistent_port.value_())+","+
                                str(iscsi_session.tpgt.value_()),
            "Interface":"",
            "Iface Name":escape_ascii_string(iscsi_session.ifacename.string_()),
            "Iface Transport":escape_ascii_string(iscsi_cls_session.transport.name.string_()),
            "Iface Initiatorname": escape_ascii_string(iscsi_session.initiatorname.string_()),
            "Iface IPaddress": local_ip,
            "Iface HWaddress": escape_ascii_string(iscsi_host.hwaddress.string_()) if iscsi_host.hwaddress else "default",
            "Iface Netdev": escape_ascii_string(iscsi_host.netdev.string_()) if iscsi_host.netdev else "default",
            "SID": iscsi_cls_session.sid.value_(),
            "iSCSI Connection State": iscsi_connection_states[iscsi_cls_conn.state.value_()],
            "iSCSI Session State": iscsi_session_states[iscsi_session.state.value_()],
            "Internal iscsid Session State": iscsi_session_states[iscsi_session.state.value_()],
            "Timeouts":"",
            "Recovery Timeout": iscsi_cls_session.recovery_tmo.value_(),
            "Target Reset Timeout": iscsi_session.tgt_reset_timeout.value_(),
            "LUN Reset Timeout": iscsi_session.lu_reset_timeout.value_(),
            "Abort Timeout": iscsi_session.abort_timeout.value_(),
            "CHAP":"",
            "username": (escape_ascii_string(iscsi_session.username.string_()) if iscsi_session.username else "<empty>"),
            "password": (escape_ascii_string(iscsi_session.password.string_()) if iscsi_session.password else "********"),
            "username_in": (escape_ascii_string(iscsi_session.username_in.string_()) if iscsi_session.username_in else "<empty>"),
            "password_in": (escape_ascii_string(iscsi_session.password_in.string_()) if iscsi_session.password_in else "********"),
            "Negotiated iSCSI params":"",
            "HeaderDigest": (iscsi_conn.hdrdgst_en.value_() if iscsi_conn.hdrdgst_en else "None"),
            "DataDigest": (iscsi_conn.datadgst_en.value_() if iscsi_conn.datadgst_en else "None"),
            "MaxRecvDataSegmentLength": iscsi_conn.max_recv_dlength.value_(),
            "MaxXmitDataSegmentLength": iscsi_conn.max_xmit_dlength.value_(),
            "FirstBurstLength": iscsi_session.first_burst.value_(),
            "MaxBurstLength": iscsi_session.max_burst.value_(),
            "ImmediateData": ("Yes" if iscsi_session.imm_data_en.value_() else "No"),
            "InitialR2T": ("Yes" if iscsi_session.initial_r2t_en.value_() else "No"),
            "MaxOutstandingR2T": iscsi_session.max_r2t.value_(),
            "Attached SCSI devices":"",
            f"Host Number: {scsi_host.host_no.value_()}  State": scsi_host_states[scsi_host.shost_state.value_()]
           }

def get_iscsi_disks_info(scsi_device: Object, prog: Program) -> Dict[str, Any]:
    scsi_host = scsi_device.host
    lun = scsi_device.lun.value_()
    host_no = scsi_host.host_no.value_()
    Id = scsi_device.id.value_()
    channel = scsi_device.channel.value_()
    sdev_state = scsi_device_states[scsi_device.sdev_state.value_()]
    sdev_name = scsi_device_name(prog, scsi_device)
    return {
            f"scsi{host_no} channel {channel} id {Id} Lun": lun,
            f"\tAttached scsi disk {sdev_name}\tState": sdev_state
            }

def dump_iscsi_sessions(prog: Program) -> None:
    """
    Dump iscsi sessions.

    """
    msg = ensure_debuginfo(prog, ["libiscsi", "scsi_transport_iscsi"])
    if msg:
        print(msg)
        return

    for session in reversed(list(for_each_iscsi_session(prog))):
        conn = session.leadconn

        iscsi_info = get_iscsi_info(conn, prog)
        print_iscsi_info(iscsi_info)

        for scsi_dev in for_each_scsi_host_device(prog, session.host):
            iscsi_disks_info = get_iscsi_disks_info(scsi_dev, prog)
            print_iscsi_info(iscsi_disks_info)

class Iscsi(CorelensModule):
    """
    Print iscsi sessions.
    """

    name = "iscsi"
    skip_unless_have_kmod = ["libiscsi", "scsi_transport_iscsi"]

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        dump_iscsi_sessions(prog)
