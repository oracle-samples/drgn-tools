# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper for iscsi
"""
import argparse
from typing import Iterator

from drgn import container_of
from drgn import Object
from drgn import Program
from drgn import sizeof
from drgn.helpers.common import escape_ascii_string
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.corelens import CorelensModule
from drgn_tools.scsi import host_module_name
from drgn_tools.table import print_dictionary
from drgn_tools.table import print_table
from drgn_tools.util import has_member


def for_each_iscsi_device(prog: Program) -> Iterator[Object]:
    """
    Iterates through all iscsi devices and returns a
    iterator.
    :returns: a iterator of ``struct dev *``
    """
    class_in_private = prog.type("struct device_private").has_member(
        "knode_class"
    )

    devices = Object(
        prog,
        "struct class",
        address=prog["iscsi_host_class"].address_of_().value_(),
    ).p.klist_devices.k_list.address_of_()

    if class_in_private:
        for device_private in list_for_each_entry(
            "struct device_private", devices, "knode_class.n_node"
        ):
            yield device_private.device
    else:
        return list_for_each_entry(
            "struct device", devices, "knode_class.n_node"
        )


def for_each_iscsi_host_device(prog: Program) -> Iterator[Object]:
    """
    Iterates through all iscsi devices and returns a
    iterator of their host devices.
    :returns: a iterator of ``struct dev *``
    """
    for dev in for_each_iscsi_device(prog):
        while not (
            dev.type and dev.type.name.string_().decode() == "scsi_host"
        ):
            if not dev.parent:
                break
            dev = dev.parent

        if dev.type and dev.type.name.string_().decode() == "scsi_host":
            yield dev


def for_each_scsi_host(prog: Program) -> Iterator[Object]:
    """
    Iterates through all iscsi host devices and returns a
    iterator of their hosts.
    :returns: a iterator of ``struct Scsi_Host *``
    """
    for dev in for_each_iscsi_host_device(prog):
        yield container_of(dev, "struct Scsi_Host", "shost_gendev")


def for_each_iscsi_session(prog: Program) -> Iterator[Object]:
    """
    Iterates through all iscsi hosts and returns a
    iterator of their associated sessions.
    :returns: a iterator of ``struct iscsi_session *``

    """
    for h in for_each_scsi_host(prog):
        yield __get_iscsi_session(prog, h)


def __get_iscsi_session(prog: Program, Scsi_Host: Object) -> Object:
    """
    Get the associated session given the scsi host.
    returns: ``struct iscsi_session *``
    """
    iscsi_sw_tcp_host_addr = (
        Scsi_Host.value_()
        + sizeof(prog.type("struct Scsi_Host"))
        + sizeof(prog.type("struct iscsi_host"))
    )
    iscsi_sw_tcp_host = Object(
        prog, "struct iscsi_sw_tcp_host", address=iscsi_sw_tcp_host_addr
    )

    return iscsi_sw_tcp_host.session


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
    for shost in for_each_scsi_host(prog):
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
                hex(__get_iscsi_session(prog, shost).value_()),
            ]
        )
    print_table(output)


def print_iscsi_report(prog) -> None:
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
        output["Initiatorname"] = escape_ascii_string(
            session.initiatorname.string_()
        )
        output["Targetname"] = escape_ascii_string(
            session.targetname.string_()
        )

        print_dictionary(output)
        print()


class IscsiDump(CorelensModule):
    """
    Dump iscsi info
    """

    name = "iscsi"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_iscsi_report(prog)
