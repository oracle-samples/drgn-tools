# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper for iscsi
"""
from typing import Iterator

from drgn import container_of
from drgn import Object
from drgn import Program
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.scsi import host_module_name
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


def for_each_iscsi_host(prog: Program) -> Iterator[Object]:
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
    for h in for_each_iscsi_host(prog):
        yield __get_iscsi_session(h)


def __get_iscsi_session(iscsi_host: Object) -> Object:
    """
    Get the associated session given the scsi host.
    returns: ``struct iscsi_session *``
    """
    return container_of(iscsi_host, "struct iscsi_session", "host")


def print_iscsi_hosts(prog: Program) -> None:
    """
    Prints iscsi information

    TODO: we need to retrieve data from iscsi_session and dump them as the ones we get from "iscsiadm -m session -P 3".
    However, most of the fields in iscsi_session seem empty. We need to figure out why. May need to rework on __get_iscsi_session.
    """
    output = [
        [
            "ISCSI_HOST",
            "NAME",
            "DRIVER",
            "Busy",
            "Blocked",
            "Fail",
            "State",
            "ISCSI_SESSION",
        ]
    ]
    for shost in for_each_iscsi_host(prog):
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
                hex(__get_iscsi_session(shost).value_()),
            ]
        )
    print_table(output)
