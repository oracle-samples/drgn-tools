# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Eventpoll
--------------

The ``drgn.helpers.linux.eventpoll`` module provides helpers for working with the
Linux eventpoll or epoll interface.
"""
from typing import Iterator
from typing import List
from typing import Set
from typing import Tuple

from drgn import cast
from drgn import Object
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.fs import d_path
from drgn.helpers.linux.fs import for_each_file
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.pid import for_each_task
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry

from drgn_tools.table import FixedTable


def for_each_eventpoll_of_task(task: Object) -> Iterator[Object]:
    """
    Iterate through eventpoll files opened by a task

    :param task: ``struct task_struct *`` of intended task.
    :returns: Iterator of ``struct eventpoll *`` corresponding to each
              eventpoll file opened by this task.
    """
    eventpoll_type = task.prog_.type("struct eventpoll *")
    for _, file in for_each_file(task):
        if file.f_path.dentry.d_name.name.string_().decode() == "[eventpoll]":
            yield cast(eventpoll_type, file.private_data)


def for_each_eventpoll(prog: Program) -> Iterator[Object]:
    """
    Iterate through all eventpoll files

    :param prog: drgn.Program
    :returns: Iterator of ``struct eventpoll *`` corresponding to all
              open eventpoll files.
    """
    eventpoll_addresses: Set[int] = set()
    for task in for_each_task(prog):
        for eventpoll in for_each_eventpoll_of_task(task):
            if eventpoll.value_() in eventpoll_addresses:
                continue
            eventpoll_addresses.add(eventpoll.value_())
            yield eventpoll


def for_each_epitem_in_monitor_list(eventpoll: Object) -> Iterator[Object]:
    """
    Iterate through epitem(s) in an eventpoll's monitor list.

    :param eventpoll: ``struct eventpoll *``
    :returns: Iterator of ``struct epitem *``.
    """
    for epitem in rbtree_inorder_for_each_entry(
        "struct epitem", eventpoll.rbr.rb_root.address_of_(), "rbn"
    ):
        yield epitem


def for_each_epitem_in_ready_list(eventpoll: Object) -> Iterator[Object]:
    """
    Iterate through epitem(s) in an eventpoll's ready list.

    :param eventpoll: ``struct eventpoll *``
    :returns: Iterator of ``struct epitem *``.

    """

    for epitem in list_for_each_entry(
        "struct epitem", eventpoll.rdllist.address_of_(), "rdllink"
    ):
        yield epitem


def for_each_epitem_in_overflow_list(eventpoll: Object) -> Iterator[Object]:
    """
    Iterate through epitem(s) in an eventpoll's overflow list.

    :param eventpoll: ``struct eventpoll *``
    :returns: Iterator of ``struct epitem *``.

    """
    epitem = eventpoll.ovflist
    while epitem.value_() != 0xFFFFFFFFFFFFFFFF:
        yield epitem
        epitem = epitem.next


def for_each_file_in_monitor_list(
    eventpoll: Object,
) -> Iterator[Tuple[int, Object]]:
    """
    Iterate through files in an eventpoll's monitor list.

    :param eventpoll: ``struct eventpoll *``
    :returns: Iterator of file descriptor and ``struct file *``.
    """
    for epitem in for_each_epitem_in_monitor_list(eventpoll):
        yield epitem.ffd.fd.value_(), epitem.ffd.file


def for_each_file_in_ready_list(
    eventpoll: Object,
) -> Iterator[Tuple[int, Object]]:
    """
    Iterate through files in an eventpoll's ready list.

    :param eventpoll: ``struct eventpoll *``
    :returns: Iterator of file descriptor and ``struct file *``.
    """
    for epitem in for_each_epitem_in_ready_list(eventpoll):
        yield epitem.ffd.fd.value_(), epitem.ffd.file


def for_each_file_in_overflow_list(
    eventpoll: Object,
) -> Iterator[Tuple[int, Object]]:
    """
    Iterate through files in an eventpoll's overflow list.

    :param eventpoll: ``struct eventpoll *``
    :returns: Iterator of file descriptor and ``struct file *``.
    """
    for epitem in for_each_epitem_in_overflow_list(eventpoll):
        yield epitem.ffd.fd.value_(), epitem.ffd.file


def print_file_list(file_list: List[Tuple[int, Object]]) -> None:
    """
    Print information about files in a given list.

    param file_list: list of file descriptor(s) and ``struct file *``
    """
    tbl = FixedTable(
        [
            "fd:>",
            "(struct file *):016x",
            "(struct dentry *):016x",
            "(struct inode *):016x",
            "path:>",
        ]
    )
    for fd, file in file_list:
        path = d_path(file.f_path)
        escaped_path = escape_ascii_string(path, escape_backslash=True)
        dentry = file.f_path.dentry.value_()
        inode = file.f_path.dentry.d_inode.value_()
        tbl.row(fd, file.value_(), dentry, inode, escaped_path)
    tbl.write()


def get_eventpoll_monitor_info(eventpoll: Object) -> None:
    """
    Dump information about files in eventpoll's monitor list.

    param eventpoll: ``struct eventpoll *``
    """
    monitor_list = [
        (fd, file) for fd, file in for_each_file_in_monitor_list(eventpoll)
    ]
    if not len(monitor_list):
        print("  There are no files in monitor list.")
    else:
        print("  Files in monitor list are as follows: ")
        print_file_list(monitor_list)


def get_eventpoll_ready_info(eventpoll: Object) -> None:
    """
    Dump information about files in eventpoll's ready list.

    param eventpoll: ``struct eventpoll *``
    """
    ready_list = [
        (fd, file) for fd, file in for_each_file_in_ready_list(eventpoll)
    ]
    if not len(ready_list):
        print("  There are no files in ready list.")
    else:
        print("  Files in ready list are as follows: ")
        print_file_list(ready_list)


def get_eventpoll_overflow_info(eventpoll: Object) -> None:
    """
    Dump information about files in eventpoll's monitor list.

    param eventpoll: ``struct eventpoll *``
    """
    ovflow_list = [
        (fd, file) for fd, file in for_each_file_in_overflow_list(eventpoll)
    ]
    if not len(ovflow_list):
        print("  There are no files in overflow list.")
    else:
        print("  Files in overflow list are as follows: ")
        print_file_list(ovflow_list)


def dump_eventpoll_info(prog: Program, ready_only: bool = True) -> None:
    """
    Dump information about all eventpoll objects.

    param prog: drgn.Program
    param ready_only: If True then only files with ready events are shown, otherwise
                      all files being managed by all eventpoll objects are shown.
    """
    for eventpoll in for_each_eventpoll(prog):
        print(f"({eventpoll.type_.type_name()})0x{eventpoll.value_():x}")
        if not ready_only:
            get_eventpoll_monitor_info(eventpoll)
            print("\n")
        get_eventpoll_ready_info(eventpoll)
        print("\n")
        get_eventpoll_overflow_info(eventpoll)
        print("\n")
