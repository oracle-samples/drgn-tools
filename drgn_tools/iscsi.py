# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper for iscsi
"""
import argparse
from typing import Iterator

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

ISCSI_SESSION_STATES = ["LOGGED_IN", "FAILED", "FREE"]


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


def print_iscsi_sessions(prog: Program) -> None:
    """
    Dump iscsi sessions.

    """
    msg = ensure_debuginfo(prog, ["libiscsi", "scsi_transport_iscsi"])
    if msg:
        print(msg)
        return

    output = {}

    for session in reversed(list(for_each_iscsi_session(prog))):
        print("**********")
        conn = session.leadconn

        persistent_address = escape_ascii_string(
            conn.persistent_address.string_()
        )
        persistent_port = int(conn.persistent_port)
        output[
            "Scsi_Host"
        ] = f"host{session.host.host_no.value_()} ({hex(session.host.value_())})"
        output["Session"] = hex(session.address_of_())
        output["SID"] = str(int(session.cls_session.sid))
        output["Persistent Portal"] = f"{persistent_address}:{persistent_port}"
        output["Iface Name"] = escape_ascii_string(session.ifacename.string_())
        output["Session State"] = ISCSI_SESSION_STATES[
            session.cls_session.state
        ]
        connstate = enum_type_to_class(
            prog.type("enum iscsi_connection_state"), "connstate"
        )
        output["Connection State"] = str(
            enum_name_get(
                connstate,
                conn.cls_conn.state,
                "UNKNOWN",
            )
        )
        output["Initiatorname"] = escape_ascii_string(
            session.initiatorname.string_()
        )
        output["Targetname"] = escape_ascii_string(
            session.targetname.string_()
        )

        print_dictionary(output)

        print("Attached SCSI devices: ")
        print("**********")
        print(
            "Host Number: {}  STATE: {}".format(
                session.host.host_no.value_(),
                session.host.shost_state.format_(type_name=False),
            )
        )

        for scsi_dev in for_each_scsi_host_device(session.host):
            name = scsi_device_name(scsi_dev)
            print(
                "scsi{} Channel {} Id {} Lun: {}".format(
                    session.host.host_no.value_(),
                    int(scsi_dev.channel),
                    int(scsi_dev.id),
                    int(scsi_dev.lun),
                )
            )
            sdev_state = enum_type_to_class(
                prog.type("enum scsi_device_state"), "sdev_state"
            )
            state = enum_name_get(
                sdev_state,
                scsi_dev.sdev_state,
                "UNKNOWN",
            )
            print("  Attached iscsi disk: {}  State: {}".format(name, state))

        print()


class Iscsi(CorelensModule):
    """
    Print iscsi sessions.
    """

    name = "iscsi"
    skip_unless_have_kmod = ["libiscsi", "scsi_transport_iscsi"]

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_iscsi_sessions(prog)
