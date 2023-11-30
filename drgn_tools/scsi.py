# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper to print scsi hosts
"""
from typing import List

from drgn import container_of
from drgn import Object
from drgn import Program
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.table import print_table


def for_each_scsi_host(prog: Program) -> List[Object]:
    """
    Iterates through all scsi hosts and returns a
    list of scsi devices
    :returns: a list of ``struct Scsi_Host *``
    """
    class_in_private = prog.type("struct device_private").has_member(
        "knode_class"
    )

    devices = prog["shost_class"].p.klist_devices.k_list.address_of_()

    shostlist = []

    if class_in_private:
        for device_private in list_for_each_entry(
            "struct device_private", devices, "knode_class.n_node"
        ):
            dev = device_private.device
            shostlist.append(
                container_of(dev, "struct Scsi_Host", "shost_dev")
            )
        return shostlist
    else:
        for devs in list_for_each_entry(
            "struct device", devices, "knode_class.n_node"
        ):
            shostlist.append(
                container_of(devs, "struct Scsi_Host", "shost_dev")
            )
        return shostlist


def print_scsi_hosts(prog: Program) -> None:
    """
    Prints scsi host information
    """
    shostlist = for_each_scsi_host(prog)
    output = [["HOST", "NAME"]]
    for x in range(len(shostlist)):
        output.append(
            [
                hex(shostlist[x].value_()),
                f"host{shostlist[x].host_no.value_()}",
            ]
        )
    print_table(output)
