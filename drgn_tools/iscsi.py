# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper for iscsi
"""
import argparse
from typing import Iterator
from typing import Tuple

from drgn import container_of
from drgn import Object
from drgn import Program
from drgn import sizeof
from drgn.helpers.common import escape_ascii_string
from drgn.helpers.common.type import enum_type_to_class
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.corelens import CorelensModule
from drgn_tools.scsi import for_each_scsi_host
from drgn_tools.scsi import host_module_name
from drgn_tools.table import print_dictionary
from drgn_tools.table import print_table
from drgn_tools.util import enum_name_get
from drgn_tools.util import has_member

ISCSI_SESSION_STATES = ["LOGGED_IN", "FAILED", "FREE"]


def for_each_iscsi_tcp_host(prog: Program) -> Iterator[Object]:
    """
    Iterates through all scsi host devices and returns a
    iterator of hosts of iscsi_tcp type
    :returns: a iterator of ``struct Scsi_Host *``
    """
    for shost in for_each_scsi_host(prog):
        if host_module_name(shost) == "iscsi_tcp":
            yield shost


def __get_iscsi_sw_tcp_host(prog: Program, iscsi_tcp_host: Object) -> Object:
    """
    Get the iscsi_sw_tcp_host asscociated with an iscsi tcp host
    :returns: ``struct iscsi_sw_tcp_host``
    """
    return Object(
        prog,
        "struct iscsi_sw_tcp_host",
        address=iscsi_tcp_host.hostdata.address_of_().value_()
        + sizeof(prog.type("struct iscsi_host")),
    )


def shost_for_each_device(prog: Program, shost: Object) -> Iterator[Object]:
    """
    Get a list of scsi_devices asscociated with an Scsi_Host
    :returns: a iterator of ``struct scsi_device``
    """
    return list_for_each_entry(
        "struct scsi_device", shost.__devices.address_of_(), "siblings"
    )


def get_dev_name(prog: Program, sdev: Object) -> str:
    """
    Get the device name associated with scsi_device.
    :return ``str``
    """
    rq = sdev.request_queue
    dev = container_of(rq.kobj.parent, "struct device", "kobj")
    return dev.kobj.name.string_().decode()


def for_each_iscsi_session(prog: Program) -> Iterator[Object]:
    """
    Iterates through all iscsi tcp hosts, gets their associated iscsi_sw_tcp_hosts and return a
    iterator of their sessions.
    :returns: a iterator of ``struct iscsi_session *``

    """
    for h in for_each_iscsi_tcp_host(prog):
        yield __get_iscsi_sw_tcp_host(prog, h).session


def print_iscsi_table(prog: Program) -> None:
    """
    Prints basic iscsi information
    """
    output = [
        [
            "SCSI_HOST",
            "NAME",
            "DRIVER",
            "Busy",
            "Blocked",
            "Fail",
            "State",
            "ISCSI_SESSION",
        ]
    ]
    for shost in for_each_iscsi_tcp_host(prog):
        """
        Since 6eb045e092ef ("scsi: core: avoid host-wide host_busy counter for scsi_mq"),
        host_busy is no longer a member of struct Scsi_Host.
        """
        if has_member(shost, "host_busy"):
            host_busy = shost.host_busy.counter.value_()
        else:
            host_busy = "n/a"
        output.append(
            [
                hex(shost.value_()),
                f"host{shost.host_no.value_()}",
                host_module_name(shost),
                host_busy,
                shost.host_blocked.counter.value_(),
                shost.host_failed.value_(),
                shost.shost_state.format_(type_name=False),
                hex(__get_iscsi_sw_tcp_host(prog, shost).session.value_()),
            ]
        )
    print_table(output)


def for_each_attached_device(
    prog: Program, shost: Object
) -> Iterator[Tuple[Object, str]]:
    for scsi_dev in shost_for_each_device(prog, shost):
        name = get_dev_name(prog, scsi_dev)
        yield scsi_dev, name


def print_iscsi_report(prog: Program) -> None:
    """
    Prints a comprehensive report including iscsi table and session stats. More info can be added later if needed.
    """
    print_iscsi_table(prog)
    print()
    output = {}

    for session in for_each_iscsi_session(prog):
        print("**********")
        conn = session.leadconn

        persistent_address = escape_ascii_string(
            conn.persistent_address.string_()
        )
        persistent_port = int(conn.persistent_port)
        output["Session"] = hex(session.value_())
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

        for scsi_dev, name in for_each_attached_device(prog, session.host):
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


class IscsiDump(CorelensModule):
    """
    Dump iscsi info
    """

    name = "iscsi"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_iscsi_report(prog)
