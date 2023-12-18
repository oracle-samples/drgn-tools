# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper to print scsi hosts
"""
import argparse
from typing import Iterator

from drgn import container_of
from drgn import Object
from drgn import Program
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table


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


def print_scsi_hosts(prog: Program) -> None:
    """
    Prints scsi host information
    """
    output = [["HOST", "NAME"]]
    for x in for_each_scsi_host(prog):
        output.append([hex(x.value_()), f"host{x.host_no.value_()}"])
    print_table(output)


class ScsiInfo(CorelensModule):
    """
    Corelens Module for scsi device information
    """

    name = "scsiinfo"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_scsi_hosts(prog)
