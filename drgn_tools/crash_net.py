# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
import ipaddress
import socket as socketlib
from typing import Iterator
from typing import List
from typing import Tuple

from drgn import Object
from drgn import PlatformFlags
from drgn import Program
from drgn.helpers.linux import net as network
from drgn.helpers.linux.fs import for_each_file
from drgn.helpers.linux.list import hlist_for_each_entry
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.net import SOCKET_I
from drgn.helpers.linux.pid import find_task

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table

_NETDEV_HASHBITS = 8
_NETDEV_HASHENTRIES = 1 << _NETDEV_HASHBITS

sockfamily_dict = {
    0: "AF_UNSPEC",
    1: "AF_UNIX",
    2: "AF_INET",
    10: "AF_INET6",
    16: "AF_NETLINK/ROUTE",
}

socktype_dict = {
    1: "SOCK_STREAM",
    2: "SOCK_DGRAM",
    3: "SOCK_RAW",
    4: "SOCK_RDM",
    5: "SOCK_SEQPACKET",
    6: "SOCK_DCCP",
    10: "SOCK_PACKET",
}

hwtype_dict = {
    0: "ARPHRD_NETROM",
    1: "ARPHRD_ETHER",
    2: "ARPHRD_EETHER",
    3: "ARPHRD_AX25",
    4: "ARPHRD_PRONET",
    5: "ARPHRD_CHAOS",
    6: "ARPHRD_IEEE802",
    7: "ARPHRD_ARCNET",
    8: "ARPHRD_APPLETLK",
    15: "ARPHRD_DLCI",
    19: "ARPHRD_ATM",
    23: "ARPHRD_METRICOM",
    24: "ARPHRD_IEEE1394",
    27: "ARPHRD_EUI64",
    32: "ARPHRD_INFINIBAND",
}

state_dict = {
    1: "NUD_INCOMPLETE",
    2: "NUD_REACHABLE",
    4: "NUD_STALE",
    8: "NUD_DELAY",
    16: "NUD_PROBE",
    32: "NUD_FAILED",
    64: "NUD_NOARP",
    128: "NUD_PERMANENT",
}


def netdev_ipv4s(dev: Object) -> List[ipaddress.IPv4Address]:
    """
    Return a list of IPv4 addresses associated with a net_device.

    :param dev: ``struct net_device *``
    :returns: list of IPv4 addresses
    """
    ips = []
    prog = dev.prog_
    if dev.ip_ptr:
        ifa = dev.ip_ptr.ifa_list
        while ifa:
            # ifa_address is already in network byte order: don't allow drgn to
            # use the platform endianness to mangle it
            addr_bytes = prog.read(ifa.ifa_address.address_of_(), 4)
            ips.append(ipaddress.IPv4Address(addr_bytes))
            ifa = ifa.ifa_next
    return ips


def netdev_ipv6s(dev: Object) -> List[ipaddress.IPv6Address]:
    """
    Return a list of IPv6 addresses associated with a net_device.

    :param dev: ``struct net_device *``
    :returns: list of IPv6 addresses
    """
    ips = []
    prog = dev.prog_
    if dev.ip6_ptr:
        for addr in list_for_each_entry(
            "struct inet6_ifaddr",
            dev.ip6_ptr.addr_list.address_of_(),
            "if_list",
        ):
            addr_bytes = prog.read(addr.addr.in6_u.u6_addr8.address_of_(), 16)
            ips.append(ipaddress.IPv6Address(addr_bytes))
    return ips


def for_each_netdev(ns: Object) -> Iterator[Tuple[str, Object]]:
    """
    Iterate over each ``struct net_device *`` of a net namespace

    :param ns: ``struct net *``
    :returns: an iterator of ``struct net_device *``
    """
    # Since commit ff92741270bf ("net: introduce name_node struct
    # to be used in hashlist"), net.dev_name_head is a list of name nodes. Prior
    # to that, it contains the net_devices directly.
    # The below approach is similar to what's already in drgn's
    # netdev_get_by_name().
    try:
        entry_type = ns.prog_.type("struct netdev_name_node")
        member = "hlist"
        entry_is_name_node = True
    except LookupError:
        entry_type = ns.prog_.type("struct net_device")
        member = "name_hlist"
        entry_is_name_node = False

    for i in range(_NETDEV_HASHENTRIES):
        head = ns.dev_name_head[i]
        for dev_node in hlist_for_each_entry(entry_type, head, member):
            dev = dev_node.dev if entry_is_name_node else dev_node
            yield (dev_node.name.string_().decode("utf-8"), dev)


def print_net_devices(prog: Program) -> None:
    """
    Display the network devices, their names and addresses.
    :param prog: drgn program
    :returns: None.
    """
    rows = [["NET_DEVICE", "NAME", "IP ADDRESS(ES)"]]
    net_namespaces = network.for_each_net(prog)

    for net_namespace in net_namespaces:
        for name, dev in for_each_netdev(net_namespace):
            net_device_ptr = hex(dev.dev.platform_data)
            net_device_name = dev.dev.kobj.name.string_().decode()
            ip_list = [str(a) for a in netdev_ipv4s(dev) + netdev_ipv6s(dev)]
            ips = ", ".join(ip_list)
            rows.append(
                [
                    net_device_ptr,
                    net_device_name,
                    ips,
                ]
            )
    print_table(rows)

def get_ipv4(prog: Program, ptr: Object) -> ipaddress.IPv4Address:
    """
    Provides python IPv4 data structure in return to
    a pointer to IPv4 address.
    """
    return ipaddress.IPv4Address(prog.read(ptr, 4))


def get_ipv6(prog: Program, ptr: Object) -> ipaddress.IPv6Address:
    """
    Provides python IPv6 data structure in return to
    a pointer to IPv6 address.
    """
    addr = list(map(int, ptr.in6_u.u6_addr8))
    addr_bytes = bytes(addr)
    return ipaddress.IPv6Address(addr_bytes)


def for_each_neighbor(prog: Program, nht: Object) -> List[Object]:
    """
    Provides a list of neighbours in return to
    the corresponding neighbour hash table.
    """
    hash_shift = nht.hash_shift.value_()
    nhash_buckets = 1 << hash_shift
    hash_buckets = nht.hash_buckets

    neighbors = []
    for i in range(nhash_buckets):
        neigh = hash_buckets[i]
        while neigh:
            neighbors.append(neigh)
            neigh = neigh.next

    return neighbors


def print_arp_cache(prog: Program) -> None:
    """
    Displays the arp cache.
    :param prog: drgn program
    :returns: None.
    """

    rows = [
        ["NEIGHBOUR", "IP ADDRESS", "HW TYPE", "HW ADDRESS", "DEVICE", "STATE"]
    ]

    nht = prog["arp_tbl"].nht

    for neigh in for_each_neighbor(prog, nht):
        neigh_addr = hex(neigh.value_())[2:]
        ip_bytes = prog.read(neigh.primary_key.address_of_(), 4)
        ip_addr = str(ipaddress.IPv4Address(ip_bytes))

        addr_len = neigh.dev.addr_len
        
        mac_bytes = prog.read(neigh.ha.address_of_(), addr_len)
        hw_addr = ":".join(f"{b:02x}" for b in mac_bytes)
        dev_name = neigh.dev.name.string_().decode()

        hw_type = str(hwtype_dict.get(int(neigh.dev.type)))
        if int(neigh.dev.type) not in hwtype_dict.keys():
            hw_type = "ARPHRD_UNKNOWN"
        hw_type = hw_type[7:]
        dev_state = str(state_dict.get(int(neigh.nud_state.value_())))[4:]
        rows.append(
            [
                neigh_addr,
                ip_addr,
                hw_type,
                hw_addr,
                dev_name,
                dev_state,
            ]
        )
        neigh = neigh.next
    print_table(rows)


def print_task_sockets(prog: Program, pid: int, print_full_data: bool) -> None:
    """
    Displays the socket addreses, family type, source and destination
    addresses and corresponding ports along with the dump of data
    structures. If print_full_data is true, it prints detailed data
    structure dumps.
    :param prog: drgn program
    :param pid: pid of the process.
    :returns: None.
    """

    task = find_task(prog, int(pid))
    if not task:
        print("Invalid PID.")
        return

    print(
        "PID: "
        + str(pid)
        + "    TASK: "
        + hex(task.value_())[2:]
        + "    CPU: "
        + str(int(task.cpu))
        + "    COMMAND: "
        + task.comm.string_().decode("utf-8")
    )

    if print_full_data:
        print(
            "%-5s %-20s %-20s %-20s %-20s %-20s"
            % (
                "FD",
                "SOCKET",
                "SOCK",
                "FAMILY:TYPE",
                "SOURCE-PORT",
                "DESTINATION-PORT",
            )
        )

    rows = [
        [
            "FD",
            "SOCKET",
            "SOCK",
            "FAMILY:TYPE",
            "SOURCE-PORT",
            "DESTINATION-PORT",
        ]
    ]

    cnt = 0

    for fd, fp in for_each_file(task):
        if not fp:
            continue
        try:
            socket = SOCKET_I(fp.f_path.dentry.d_inode)
        except ValueError:
            continue

        sock_family = str(
            sockfamily_dict.get(int(socket.sk.__sk_common.skc_family))
        )
        if (
            int(socket.sk.__sk_common.skc_family)
        ) not in sockfamily_dict.keys():
            sock_family = "AF_"

        sock_family = sock_family[3:]
        sock_type = str(socktype_dict.get(int(socket.type)))

        if int(socket.type) not in socktype_dict.keys():
            sock_type = "SOCK_"
            sock_type = sock_type[5:]

        if sock_family == "INET":
            skc = socket.sk.__sk_common
            saddr = get_ipv4(prog, skc.skc_rcv_saddr.address_of_())
            daddr = get_ipv4(prog, skc.skc_daddr.address_of_())
            sport = int(skc.skc_num)
            dport = int(skc.skc_dport)
            if prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN:
                dport = socketlib.ntohs(dport)

            source_port = f"{saddr}:{sport}"
            destination_port = f"{daddr}:{dport}"

        elif sock_family == "INET6":
            skc = socket.sk.__sk_common
            saddr_6 = get_ipv6(prog, skc.skc_v6_rcv_saddr.address_of_())
            daddr_6 = get_ipv6(prog, skc.skc_v6_daddr.address_of_())
            sport_6 = int(skc.skc_num)
            dport_6 = int(skc.skc_dport)
            if prog.platform.flags & PlatformFlags.IS_LITTLE_ENDIAN:
                dport_6 = socketlib.ntohs(dport_6)

            source_port = f"{saddr_6}:{sport_6}"
            destination_port = f"{daddr_6}:{dport_6}"

        else:
            source_port = ""
            destination_port = ""

        cnt = cnt + 1
        rows.append(
            [
                fd,
                hex(socket.value_())[2:],
                hex(socket.sk.value_())[2:],
                sock_family + ":" + sock_type,
                source_port,
                destination_port,
            ]
        )
        if print_full_data:
            print(
                "%-5s %-20s %-20s %-20s %-20s %-20s"
                % (
                    str(cnt),
                    hex(socket.value_())[2:],
                    hex(socket.sk.value_())[2:],
                    sock_family + ":" + sock_type,
                    source_port,
                    destination_port,
                )
            )
            print(socket)
            print(socket.sk)
        """
        except Exception as e:
            print(i)
            print(e)
            continue
        """

    if not (print_full_data):
        print_table(rows)


class NetInfo(CorelensModule):
    """
    Display network related information.

    """

    name = "net"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "-a",
            dest="all_data",
            action="store_true",
            help="Displays the ARP table",
        )
        group.add_argument(
            "-s",
            type=int,
            dest="socket_data",
            metavar="PID",
            help="Display a list of open sockets for PID",
        )
        group.add_argument(
            "-S",
            type=int,
            dest="socket_full_data",
            metavar="PID",
            help="Display open sockets for PID, with detailed data structure dumps",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if args.all_data:
            print_arp_cache(prog)
        elif args.socket_data:
            print_task_sockets(prog, args.socket_data, False)
        elif args.socket_full_data:
            print_task_sockets(prog, args.socket_full_data, True)
        else:
            print_net_devices(prog)
