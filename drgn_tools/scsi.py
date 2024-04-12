# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper to print scsi hosts
"""
from typing import Iterator

import drgn
from drgn import container_of
from drgn import Object
from drgn import Program
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.table import print_table
from drgn_tools.util import has_member


def for_each_scsi_host(prog: Program) -> Iterator[Object]:
    """
    Iterates through all scsi hosts and returns a
    iterator.
    :returns: a iterator of ``struct Scsi_Host *``
    """
    class_in_private = prog.type("struct device_private").has_member(
        "knode_class"
    )

    devices = prog["shost_class"].p.klist_devices.k_list.address_of_()

    if class_in_private:
        for device_private in list_for_each_entry(
            "struct device_private", devices, "knode_class.n_node"
        ):
            dev = device_private.device
            yield container_of(dev, "struct Scsi_Host", "shost_dev")
    else:
        for dev in list_for_each_entry(
            "struct device", devices, "knode_class.n_node"
        ):
            yield container_of(dev, "struct Scsi_Host", "shost_dev")


def host_module_name(shost: Object) -> str:
    """
    Fetch the module name associated with the scsi host.
    returns: the module name string.
    """
    try:
        name = shost.hostt.module.name.string_().decode()
    except drgn.FaultError:
        name = "unknown"
    return name


def print_scsi_hosts(prog: Program) -> None:
    """
    Prints scsi host information
    """
    output = [
        ["SCSI_HOST", "NAME", "DRIVER", "Busy", "Blocked", "Fail", "State"]
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
            ]
        )
    print_table(output)
