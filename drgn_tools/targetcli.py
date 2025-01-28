# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers to retrieve iscsi target info and reconstruct targetcli structure on iscsi target server.

Configuration could be found under /sys/kernel/config/target/
"""
import argparse
from typing import Iterable

from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.list import hlist_for_each_entry
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.corelens import CorelensModule
from drgn_tools.dentry import dentry_for_each_child
from drgn_tools.module import ensure_debuginfo

######################################
# iscsi
######################################


def for_each_iqn(prog: Program) -> Iterable[Object]:
    """
    List tiqn from g_tiqn_list

    :returns: Iterator of ``struct iscsi_tiqn *``
    """
    tiqn_list = prog["g_tiqn_list"]

    return list_for_each_entry(
        "struct iscsi_tiqn", tiqn_list.address_of_(), "tiqn_list"
    )


def for_each_iscsi_tpg(tiqn: Object) -> Iterable[Object]:
    """
    Get a list of tpg from tiqn

    :param tiqn: ``struct iscsi_tiqn *``
    :returns: Iterator of ``struct iscsi_portal_group *``
    """
    return list_for_each_entry(
        "struct iscsi_portal_group",
        tiqn.tiqn_tpg_list.address_of_(),
        "tpg_list",
    )


def for_each_portal(tpg: Object) -> Iterable[Object]:
    """
    Get a list of portals under tpg

    :param tpg: ``struct se_portal_group``
    :returns:  Iterator of str
    """
    np_dentry = tpg.tpg_np_group.cg_item.ci_dentry
    for portal in dentry_for_each_child(np_dentry):
        yield escape_ascii_string(portal.d_name.name.string_())


def print_iscsi_info(prog) -> None:
    """Dump iscsi section info"""

    msg = ensure_debuginfo(prog, ["target_core_mod", "iscsi_target_mod"])
    if msg:
        print(msg)
        return

    print("o- iscsi")
    indent = "  "
    for tiqn in for_each_iqn(prog):
        print(
            "{}o- {} (struct iscsi_tiqn * {})".format(
                indent,
                get_tiqn_name(tiqn),
                hex(tiqn.value_()),
            )
        )

        for tpg in for_each_iscsi_tpg(tiqn):
            se_tpg = tpg.tpg_se_tpg
            print(
                "{}o- {} (struct se_portal_group {})".format(
                    indent * 2,
                    get_tpg_name(se_tpg),
                    hex(se_tpg.address_of_()),
                )
            )
            print(f"{indent * 3}o- acls")
            for acl in list_for_each_entry(
                "struct se_node_acl",
                se_tpg.acl_node_list.address_of_(),
                "acl_list",
            ):
                print(
                    "{}o- {} (struct se_node_acl * {})".format(
                        indent * 4,
                        get_acl_name(acl),
                        hex(acl),
                    )
                )
                print(f"{indent * 4}o- mapped_luns")
                for se_dev in hlist_for_each_entry(
                    "struct se_dev_entry",
                    acl.lun_entry_hlist.address_of_(),
                    "link",
                ):
                    print_lun_info(se_dev.se_lun, nr_indent=5)

            print(f"{indent * 3}o- luns")
            for lun in hlist_for_each_entry(
                "struct se_lun",
                se_tpg.tpg_lun_hlist.address_of_(),
                "link",
            ):
                print_lun_info(lun, nr_indent=4)

            print(f"{indent * 3}o- portals")
            for portal in for_each_portal(se_tpg):
                print(f"{indent * 4}o- {portal}")


######################################
# vhost
######################################


def for_each_vhost_tpg(prog) -> Iterable[Object]:
    """
    List vhost_scsi_tpg from vhost_scsi_list

    :returns: Iterator of ``struct vhost_scsi_tpg *``
    """

    vhost_scsi_list = prog["vhost_scsi_list"]

    return list_for_each_entry(
        "struct vhost_scsi_tpg", vhost_scsi_list.address_of_(), "tv_tpg_list"
    )


def print_vhost_info(prog) -> None:
    """Dump vhost section info"""

    msg = ensure_debuginfo(prog, ["vhost", "vhost_scsi", "target_core_mod"])
    if msg:
        print(msg)
        return

    print("o- vhost")
    for tpg in for_each_vhost_tpg(prog):
        indent = "  "
        se_tpg = tpg.se_tpg
        print(
            "{}o- {} (struct se_portal_group {}) ({})".format(
                indent,
                get_tpg_name(se_tpg),
                hex(se_tpg.address_of_()),
                get_ci_name_from_cg(tpg.tport.tport_wwn.wwn_group),
            )
        )

        print(f"{indent * 2}o- acls")
        for acl in list_for_each_entry(
            "struct se_node_acl",
            se_tpg.acl_node_list.address_of_(),
            "acl_list",
        ):
            acl_name = get_acl_name(acl)
            if not acl_name:
                continue

            print(
                "{}o- {} (struct se_node_acl * {})".format(
                    indent * 3,
                    acl_name,
                    hex(acl),
                )
            )

            print(f"{indent * 3}o- mapped_luns")
            for se_dev in hlist_for_each_entry(
                "struct se_dev_entry",
                acl.lun_entry_hlist.address_of_(),
                "link",
            ):
                print_lun_info(se_dev.se_lun, nr_indent=4)

        print(f"{indent * 2}o- luns")
        for lun in hlist_for_each_entry(
            "struct se_lun", se_tpg.tpg_lun_hlist.address_of_(), "link"
        ):
            print_lun_info(lun, nr_indent=3)


def print_lun_info(lun: Object, nr_indent: int = 1) -> None:
    """
    Dump lun info

    :param lun: ``struct se_lun *``
    :param nr_indent: int indicating numbers of indentations
    """
    print(
        "{}o- {} (struct se_lun * {}) \n{}o- BACKSTORE: {} \n{}o- DEVICE: {}".format(
            "  " * nr_indent,
            get_lun_name(lun),
            hex(lun),
            "  " * (nr_indent + 1),
            get_backstore_name_from_lun(lun),
            "  " * (nr_indent + 1),
            get_device_path_from_lun(lun),
        )
    )


def get_ci_name_from_cg(cg: Object) -> str:
    """
    Get ci_name given a config group

    :param cg: ``struct config_group *``
    :returns: str
    """
    try:
        return cg.cg_item.ci_name.string_().decode()
    except FaultError:
        return ""


def get_backstore_name_from_lun(lun: Object) -> str:
    """
    Get backstore name given a lun

    :param lun: ``struct se_lun *``
    :returns: str
    """
    return get_ci_name_from_cg(lun.lun_se_dev.dev_group)


def get_tpg_name(tpg: Object) -> str:
    """
    Get tpg name

    :param tpg: ``struct se_portal_group``
    :returns: str
    """
    return get_ci_name_from_cg(tpg.tpg_group)


def get_acl_name(acl: Object) -> str:
    """
    Get acl name. If the name is empty, it could mean the acl is not configured or potentially corrupted.

    :param acl: ``struct se_node_acl *``
    :returns: str
    """
    return get_ci_name_from_cg(acl.acl_group)


def get_tiqn_name(tiqn: Object) -> str:
    """
    Get tiqn name

    :param tiqn: ``struct iscsi_tiqn *``
    :returns: str
    """
    return tiqn.tiqn.string_().decode()


def get_lun_name(lun: Object) -> str:
    """
    Get lun name

    :param lun: ``struct se_lun *``
    :returns: str
    """
    return get_ci_name_from_cg(lun.lun_group)


def get_device_path_from_lun(lun: Object) -> str:
    """
    Get block backend device path given lun

    :param lun: ``struct se_lun *``
    :returns: str
    """
    return lun.lun_se_dev.udev_path.string_().decode()


def dump_targetcli(prog) -> None:
    """Dump targetcli structure"""

    print_iscsi_info(prog)
    print_vhost_info(prog)


class TargetCli(CorelensModule):
    """
    Dump targetcli structure on iscsi target
    """

    name = "targetcli"
    skip_unless_have_kmod = ["target_core_mod"]

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        dump_targetcli(prog)
