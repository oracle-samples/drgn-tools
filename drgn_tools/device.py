# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for working with the Linux kernel device model
"""
from drgn import Object
from drgn.helpers.linux.list import list_for_each_entry


def bus_to_subsys(bus_type: Object) -> Object:
    """
    Return the ``struct subsys_private *`` corresponding to a
    ``struct bus_type *``. See the kernel function of the same name.
    """
    if hasattr(bus_type, "p"):
        return bus_type.p

    # Since v6.3, commit d2bf38c088e0d ("driver core: remove private pointer
    # from struct bus_type"), the private pointer is gone. We now need to lookup
    # subsys_private by iterating over the bus list and finding the one related
    # to this.
    bus_kset = bus_type.prog_["bus_kset"]
    for subsys in list_for_each_entry(
        "struct subsys_private",
        bus_kset.list.address_of_(),
        "subsys.kobj.entry",
    ):
        if subsys.bus == bus_type:
            return subsys
    bus_name = bus_type.name.string_().decode()
    raise ValueError(f"Could not find subsys_private for bus_type {bus_name}")


def class_to_subsys(class_: Object) -> Object:
    """
    Return the ``struct subsys_private *`` corresponding to a
    ``struct class *``. See the kernel function of the same name.
    """
    if hasattr(class_, "p"):
        return class_.p

    # Since v6.4, commit 2df418cf4b720 ("driver core: class: remove subsystem
    # private pointer from struct class"), the private pointer is gone. We now
    # need to lookup subsys_private by iterating over the class list and finding
    # the one related to this.
    class_kset = class_.prog_["class_kset"]
    for subsys in list_for_each_entry(
        "struct subsys_private",
        class_kset.list.address_of_(),
        "subsys.kobj.entry",
    ):
        if subsys.member_("class") == class_:
            return subsys
    class_name = class_.name.string_().decode()
    raise ValueError(f"Could not find subsys_private for class {class_name}")
