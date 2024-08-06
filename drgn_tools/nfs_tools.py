# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helpers for NFS (client-side only) and SUNRPC subsystem.
"""
import argparse
import errno
import ipaddress
import socket
import typing as t
from itertools import chain

import drgn
from drgn import Object
from drgn import Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.common.type import enum_type_to_class
from drgn.helpers.linux.fs import d_path
from drgn.helpers.linux.fs import for_each_mount
from drgn.helpers.linux.fs import inode_path
from drgn.helpers.linux.list import list_count_nodes
from drgn.helpers.linux.list import list_for_each_entry

from drgn_tools.corelens import CorelensModule
from drgn_tools.itertools import take
from drgn_tools.rds import rds_inet_ntoa
from drgn_tools.util import BitNumberFlags
from drgn_tools.util import enum_name_get
from drgn_tools.util import has_member
from drgn_tools.util import redirect_stdout

__all__ = (
    "nfsshow",
    "show_nfs_clients",
    "show_rpc_clnts",
    "show_rpc_xprts",
    "show_rpc_tasks",
)

""" include/linux/sunrpc/sched.h """


class RpcTaskState_1(BitNumberFlags):
    RPC_TASK_RUNNING = 0
    RPC_TASK_QUEUED = 1
    RPC_TASK_ACTIVE = 2


# 729749bb8da1 SUNRPC: Don't hold the transport lock across socket copy operations
class RpcTaskState_2(BitNumberFlags):
    RPC_TASK_RUNNING = 0
    RPC_TASK_QUEUED = 1
    RPC_TASK_ACTIVE = 2
    RPC_TASK_MSG_RECV = 3
    RPC_TASK_MSG_RECV_WAIT = 4


# 7ebbbc6e7bd0 SUNRPC: Simplify identification of when the message send/receive is complete
class RpcTaskState_3(BitNumberFlags):
    RPC_TASK_RUNNING = 0
    RPC_TASK_QUEUED = 1
    RPC_TASK_ACTIVE = 2
    RPC_TASK_NEED_XMIT = 3
    RPC_TASK_NEED_RECV = 4
    RPC_TASK_MSG_RECV = 5
    RPC_TASK_MSG_RECV_WAIT = 6


# cf9946cd6144 SUNRPC: Refactor the transport request pinning
class RpcTaskState_4(BitNumberFlags):
    RPC_TASK_RUNNING = 0
    RPC_TASK_QUEUED = 1
    RPC_TASK_ACTIVE = 2
    RPC_TASK_NEED_XMIT = 3
    RPC_TASK_NEED_RECV = 4
    RPC_TASK_MSG_PIN_WAIT = 5


# ae67bd3821bb SUNRPC: Fix up task signalling
class RpcTaskState_5(BitNumberFlags):
    RPC_TASK_RUNNING = 0
    RPC_TASK_QUEUED = 1
    RPC_TASK_ACTIVE = 2
    RPC_TASK_NEED_XMIT = 3
    RPC_TASK_NEED_RECV = 4
    RPC_TASK_MSG_PIN_WAIT = 5
    RPC_TASK_SIGNALLED = 6


def does_func_exist(prog: drgn.Program, func: str) -> bool:
    try:
        prog.symbol(func)
        return True
    except LookupError:
        return False


def decode_tk_runstate(prog: drgn.Program, task: Object) -> str:
    """
    Given a rpc_task, return the string representation of tk_runstate

    :param task: rpc_task object
    :returns: tk_runstate decoded as string.
    """

    if does_func_exist(prog, "xprt_pin_rqst") is False:
        return RpcTaskState_1.decode(task.tk_runstate.value_())
    elif does_func_exist(prog, "xprt_request_data_received") is False:
        return RpcTaskState_2.decode(task.tk_runstate.value_())
    elif has_member(task.tk_rqstp, "rq_pin") is False:
        return RpcTaskState_3.decode(task.tk_runstate.value_())
    elif does_func_exist(prog, "rpc_signal_task") is False:
        return RpcTaskState_4.decode(task.tk_runstate.value_())
    else:
        return RpcTaskState_5.decode(task.tk_runstate.value_())


""" include/linux/sunrpc/xprt.h """


class RpcXprtState(BitNumberFlags):
    XPRT_LOCKED = 0
    XPRT_CONNECTED = 1
    XPRT_CONNECTING = 2
    XPRT_CLOSE_WAIT = 3
    XPRT_BOUND = 4
    XPRT_BINDING = 5
    XPRT_CLOSING = 6
    XPRT_CONGESTED = 9
    XPRT_CWND_WAIT = 10
    XPRT_WRITE_SPACE = 11
    XPRT_SND_IS_COOKIE = 12


""" include/linux/nfs_fs_sb.h """


class NfsClientFlag(BitNumberFlags):
    NFS_CS_NORESVPORT = 0
    NFS_CS_DISCRTRY = 1
    NFS_CS_MIGRATION = 2
    NFS_CS_INFINITE_SLOTS = 3
    NFS_CS_NO_RETRANS_TIMEOUT = 4
    NFS_CS_TSM_POSSIBLE = 5


"""
include/uapi/linux/nfs_mount.h
include/linux/nfs_fs_sb.h
"""


class NfsServerFlag(BitNumberFlags):
    NFS_MOUNT_SOFT = 0
    NFS_MOUNT_INTR = 1
    NFS_MOUNT_SECURE = 2
    NFS_MOUNT_POSIX = 3
    NFS_MOUNT_NOCTO = 4
    NFS_MOUNT_NOAC = 5
    NFS_MOUNT_TCP = 6
    NFS_MOUNT_VER3 = 7
    NFS_MOUNT_KERBEROS = 8
    NFS_MOUNT_NONLM = 9
    NFS_MOUNT_BROKEN_SUID = 10
    NFS_MOUNT_NOACL = 11
    NFS_MOUNT_STRICTLOCK = 12
    NFS_MOUNT_SECFLAVOUR = 13
    NFS_MOUNT_NORDIRPLUS = 14
    NFS_MOUNT_UNSHARED = 15
    NFS_MOUNT_LOOKUP_CACHE_NONEG = 16
    NFS_MOUNT_LOOKUP_CACHE_NONE = 17
    NFS_MOUNT_NORESVPORT = 18
    NFS_MOUNT_LEGACY_INTERFACE = 19
    NFS_MOUNT_LOCAL_FLOCK = 20
    NFS_MOUNT_LOCAL_FCNTL = 21
    NFS_MOUNT_SOFTERR = 22


class NfsDelegFlag(BitNumberFlags):
    NFS_DELEGATION_NEED_RECLAIM = 0
    NFS_DELEGATION_RETURN = 1
    NFS_DELEGATION_RETURN_IF_CLOSED = 2
    NFS_DELEGATION_REFERENCED = 3
    NFS_DELEGATION_RETURNING = 4
    NFS_DELEGATION_REVOKED = 5
    NFS_DELEGATION_TEST_EXPIRED = 6
    NFS_DELEGATION_INODE_FREEING = 7
    NFS_DELEGATION_RETURN_DELAYED = 8


""" include/linux/sunrpc/sched.h """
task_priority = [
    "RPC_PRIORITY_NORMAL",
    "RPC_PRIORITY_HIGH",
    "RPC_PRIORITY_PRIVILEGED",
    "INVALID",
]


def tk_status_to_str(status: int) -> str:
    """
    Given the tk_status of a rpc_task, return the status string.

    :param status: tk_status value in int
    :returns: tk_status in string. If the status is not defined,
              return the status value itself as a string.
    """

    status_str = errno.errorcode.get(-status)
    if status_str is None:
        if status == 0:
            status_str = "OK"
        else:
            status_str = str(status)
    return status_str


def display_nfs_delegations(
    server: Object, max_count: t.Optional[int] = None
) -> None:
    """
    Display all nfs_delegation's owned by the given nfs_server.
    Default to the 1st 10 delegations. Set max_count to -1 to display all.

    Example:
        display_nfs_delegations(nfs_server, -1)

    :param server: nfs_server object
    :param max_count: max number of delegations to display, default to display all.
    :returns: None
    """

    n = list_count_nodes(server.delegations.address_of_())
    delegs = list_for_each_entry(
        "struct nfs_delegation", server.delegations.address_of_(), "super_list"
    )
    if max_count is not None:
        if max_count < n:
            print(
                "          ------------------ printing 1st %d out of total %d delegations ------------------"
                % (max_count, n)
            )
            print(
                "                             see help(display_nfs_delegations)"
            )
        delegs = take(max_count, delegs)

    for deleg in delegs:
        print(
            "          <nfs_delegation: 0x%x>  inode: 0x%x  (%s)"
            % (
                deleg.value_(),
                deleg.inode.value_(),
                escape_ascii_string(inode_path(deleg.inode)),
            )
        )
        type = deleg.type
        if type == 1:
            typestr = "READ"
        elif type == 2:
            typestr = "WRITE"
        else:
            typestr = "INVALID [" + str(type) + "]"

        print("             type: %d (%s)" % (type, typestr))
        print(
            "             flags: 0x%lx (%s)"
            % (deleg.flags, NfsDelegFlag.decode(deleg.flags.value_()))
        )


def display_rpc_wait_queue(
    prog: drgn.Program, wqueue: Object, qname: str
) -> None:
    """
    Display all rpc_task's in the given rpc_xprt's wait queue.

    :param prog: drgn program
    :param wqueue: rpc_xprt's rpc_wait_queue
    :param qname: the name of the rpc_wait_queue
    :returns: None
    """

    print("     <%s Queue>" % qname)
    for pri in range(2):
        for task in list_for_each_entry(
            "struct rpc_task", wqueue.tasks[pri].address_of_(), "u.tk_wait"
        ):
            s = "NULL"
            a = "NULL"
            if task.tk_ops:
                s = lookup_ksym(prog, task.tk_ops.value_())
            if task.tk_action:
                a = lookup_ksym(prog, task.tk_action.value_())
            print(
                "        rpc_task[%s]: 0x%x  tk_status[%d] (%s)"
                % (
                    task_priority[pri & 0x3],
                    task.value_(),
                    task.tk_status.value_(),
                    tk_status_to_str(task.tk_status.value_()),
                ),
                end="",
            )

            # 5ad64b36dda96: SUNRPC: Add tracking of RPC level errors
            if has_member(task, "tk_rpc_status"):
                print(
                    " tk_rpc_status[%d] (%s)"
                    % (
                        task.tk_rpc_status.value_(),
                        tk_status_to_str(task.tk_rpc_status.value_()),
                    )
                )
            else:
                print()  # print end of line

            print("            tk_ops: %s  tk_action: %s" % (s, a))


def namespaces(prog: drgn.Program, id: int) -> t.List[Object]:
    """return a list of system namespaces contain the specified id"""

    ns = []
    for net in list_for_each_entry(
        "struct net", prog["net_namespace_list"].address_of_(), "list"
    ):
        if has_member(net.gen, "s"):
            net_len = net.gen.s.len
        else:
            net_len = net.gen.len
            id -= 1
        if id >= net_len or net.gen.ptr[id] is None:
            continue
        ns.append(net)
    return ns


def for_each_rpc_clnt(prog: drgn.Program) -> t.Iterator[Object]:
    """
    Return a list of all rpc_clnt in the system

    Example:
        clnt_list = for_each_rpc_clnt(prog)
        display_rpc_clnts(clnt_list)

    :param prog: drgn program
    :returns: list of struct rpc_clnt
    """

    rpc_clnts: t.Iterator[Object] = iter([])
    rpc_id = prog["sunrpc_net_id"]

    for net in namespaces(prog, rpc_id):
        # 6af2d5fff2fdc: netns: fix net_generic() "id - 1" bloat
        if not has_member(net.gen, "s"):
            rpc_id -= 1
        sunrpc_net = Object(
            prog, "struct sunrpc_net *", value=net.gen.ptr[rpc_id].value_()
        )
        nn = list_for_each_entry(
            "struct rpc_clnt",
            sunrpc_net.all_clients.address_of_(),
            "cl_clients",
        )
        rpc_clnts = chain(rpc_clnts, nn)
    return rpc_clnts


def rpc_xprt_list(prog) -> t.List[Object]:
    """
    Return a list rpc_xprt
    """

    xprts = []
    s_xprts = set()
    rpc_clnts = for_each_rpc_clnt(prog)
    for clnt in rpc_clnts:
        s_xprts.add(clnt.cl_xprt.value_())
    for x in s_xprts:
        xprts.append(Object(prog, "struct rpc_xprt *", x))
    return xprts


def rpc_task_list(prog: drgn.Program) -> t.Iterator[Object]:
    """
    Return a list of all rpc_task of all rpc_clnt

    :param prog: drgn program
    :returns: list of all rpc_task
    """

    for clnt in for_each_rpc_clnt(prog):
        yield from list_for_each_entry(
            "struct rpc_task", clnt.cl_tasks.address_of_(), "tk_task"
        )


def display_rpc_tasks(
    prog: drgn.Program,
    rpc_clnt: Object,
    skip_xprt: bool = False,
    max_tasks: t.Optional[int] = None,
) -> None:
    """
    Given a rpc_clnt struct or an rpc_clnt address, display info of all,
    or the number specified by 'max_tasks', RPC tasks for this rpc_clnt.

    :param prog: drgn program
    :param rpc_clnt: struct rpc_clnt
    :param skip_xprt: don't display associated rpc_xprt. Default is False
    :param max_tasks: maximum number of rpc_task to display. Default is display all
    :returns: None
    """

    prog = rpc_clnt.prog_
    tasks = list_for_each_entry(
        "struct rpc_task", rpc_clnt.cl_tasks.address_of_(), "tk_task"
    )
    if max_tasks is not None:
        tasks = take(max_tasks, tasks)
    for task in tasks:
        s = "NULL"
        a = "NULL"
        if task.tk_ops:
            s = lookup_ksym(prog, task.tk_ops.value_())
        if task.tk_action:
            a = lookup_ksym(prog, task.tk_action.value_())
        rqst = task.tk_rqstp

        print(
            "---- <rpc_task: 0x%x>  tk_op: %s  tk_action: %s"
            % (task.value_(), s, a)
        )
        print(
            "     tk_client: 0x%x  tk_client.cl_xprt: 0x%x"
            % (task.tk_client.value_(), task.tk_client.cl_xprt.value_())
        )

        # fb43d17210baa: SUNRPC: Use the multipath iterator to assign
        #                       a transport to each task
        if has_member(task, "tk_xprt"):
            print("     tk_xprt: 0x%x" % task.tk_xprt.value_())
        print(
            "     tk_status: %d (%s)"
            % (
                task.tk_status.value_(),
                tk_status_to_str(task.tk_status.value_()),
            ),
            end="",
        )

        # 5ad64b36dda96: SUNRPC: Add tracking of RPC level errors
        if has_member(task, "tk_rpc_status"):
            print(
                " tk_rpc_status[%d] (%s)"
                % (
                    task.tk_rpc_status.value_(),
                    tk_status_to_str(task.tk_rpc_status.value_()),
                )
            )
        else:
            print()  # print end of line

        print(
            "     tk_runstate: 0x%x  (%s)"
            % (task.tk_runstate, decode_tk_runstate(prog, task))
        )
        print(
            "     tk_priority: %d  tk_timeout(ticks): %d  tk_timeouts(major): %d"
            % (task.tk_priority, task.tk_timeout, task.tk_timeouts)
        )
        if not skip_xprt:
            xprt = task.tk_xprt
            print(
                "     tk_xprt: 0x%x  proto: %d"
                % (xprt.value_(), xprt.prot.value_())
            )
            print(
                "         state: 0x%x  (%s)"
                % (
                    xprt.state.value_(),
                    RpcXprtState.decode(xprt.state.value_()),
                )
            )

        if rqst.value_() == 0:
            print("     tk_rqstp: 0")
        else:
            print(
                "     <tk_rqstp: 0x%x>  rq_xid: 0x%x  rq_retries: %d"
                % (
                    rqst.value_(),
                    rqst.rq_xid.value_(),
                    rqst.rq_retries.value_(),
                )
            )
        print("")


def show_rpc_clnts(prog: drgn.Program) -> None:
    """
    Display info of all rpc_clnt in the system.

    :param prog: drgn program
    :returns: None
    """

    total_clnts = 0
    total_tasks = 0
    clnt_list = for_each_rpc_clnt(prog)

    print(
        "=============================== RPC_CLNT ================================="
    )
    for c in clnt_list:
        xprt = c.cl_xprt
        servername = xprt.servername.string_().decode()
        tasks = list_count_nodes(c.cl_tasks.address_of_())
        total_clnts += 1
        total_tasks += tasks

        print("---- <rpc_clnt: 0x%x>  rpc_task: %d" % (c.value_(), tasks))

        RpcAuthFlavors = enum_type_to_class(
            prog.type("enum rpc_auth_flavors"), "RpcAuthFlavors"
        )
        if c.cl_auth:
            enum_name = enum_name_get(
                RpcAuthFlavors, c.cl_auth.au_flavor, "UNKNOWN"
            )
            print(
                "     cl_auth.au_flavor: %d (%s)"
                % (c.cl_auth.au_flavor, enum_name)
            )
        else:
            print("     cl_auth: NULL")
        print(
            "     cl_prog: %d (%s)  cl_vers: %d  cl_procinfo: %s"
            % (
                c.cl_prog,
                escape_ascii_string(c.cl_program.name.string_()),
                c.cl_vers,
                lookup_ksym(prog, c.cl_procinfo.value_()),
            )
        )
        print(
            "     <rpc_xprt: 0x%x>  servername: %s  ops: %s"
            % (xprt.value_(), servername, lookup_ksym(prog, xprt.ops.value_()))
        )
        print("     Server IPaddress: %s" % get_ipaddr_str(xprt.addr))
        print(
            "     state: 0x%x  (%s)"
            % (xprt.state.value_(), RpcXprtState.decode(xprt.state.value_()))
        )
        print()

    print("---- %d RPC Clients ----" % total_clnts)
    print("---- %d RPC Tasks ----" % total_tasks)
    print("")


def show_rpc_xprts(prog: drgn.Program) -> None:
    """
    Display the content of all struct rpc_xprt.

    :param prog: drgn program
    :returns: None
    """

    xprts = rpc_xprt_list(prog)

    print(
        "=============================== RPC_XPRT ================================="
    )
    for xprt in xprts:
        bindq_cnt = xprt.binding.qlen.value_()
        sendq_cnt = xprt.sending.qlen.value_()
        pendq_cnt = xprt.pending.qlen.value_()
        backlogq_cnt = xprt.backlog.qlen.value_()
        servername = xprt.servername.string_().decode()

        print(
            "---- <rpc_xprt: 0x%x>  servername: %s  ops: %s"
            % (xprt.value_(), servername, lookup_ksym(prog, xprt.ops.value_()))
        )
        print("     Server IPaddress: %s" % get_ipaddr_str(xprt.addr))
        print(
            "     state: 0x%x  (%s)"
            % (xprt.state.value_(), RpcXprtState.decode(xprt.state.value_()))
        )
        print(
            "     cong: %d  cwnd: %d"
            % (xprt.cong.value_(), xprt.cwnd.value_())
        )

        print(
            "     rpc_wait_queue:  binding[%d]  sending[%d]  pending[%d]  backlog[%d]"
            % (bindq_cnt, sendq_cnt, pendq_cnt, backlogq_cnt)
        )

        if bindq_cnt:
            display_rpc_wait_queue(prog, xprt.binding, "Binding")
        if sendq_cnt:
            display_rpc_wait_queue(prog, xprt.sending, "Sending")
        if pendq_cnt:
            display_rpc_wait_queue(prog, xprt.pending, "Pending")
        if backlogq_cnt:
            display_rpc_wait_queue(prog, xprt.backlog, "Backlog")
        print()


def show_rpc_tasks(prog: drgn.Program, max_tasks: int = 10) -> None:
    """
    Display the content of all struct rpc_task.

    :param prog: drgn program
    :param max_tasks: Maximum no of rpc_tasks to print for each rpc_clnt.
            default to first 10.
    :returns: None

    Example:
        show_rpc_tasks(prog, 20)    Print 1st 20 rpc_tasks
        show_rpc_tasks(prog -1)    Print all rpc_tasks
    """

    clnts = for_each_rpc_clnt(prog)
    print(
        "=============================== RPC_TASK ================================="
    )
    for clnt in clnts:
        tasks = list_count_nodes(clnt.cl_tasks.address_of_())
        if tasks > max_tasks:
            print(
                "\n    -- Printing first %d out of total %s RPC Tasks of rpc_clnt<0x%x> --"
                % (max_tasks, tasks, clnt.value_())
            )
            print("       See help(show_rpc_tasks)")
        display_rpc_tasks(prog, clnt, True, max_tasks)


def nfs_client_list(prog: drgn.Program) -> t.Iterator[Object]:
    """
    Return a list of struct nfs_client

    :param prog: drgn program
    :returns: a list of all nfs_client objects in the system.
    """

    nfs_clnts: t.Iterator[Object] = iter([])
    nfs_id = prog["nfs_net_id"]

    for net in namespaces(prog, nfs_id):
        # 6af2d5fff2fdc: netns: fix net_generic() "id - 1" bloat
        if not has_member(net.gen, "s"):
            nfs_id -= 1
        nfs_net = Object(
            prog, "struct nfs_net *", value=net.gen.ptr[nfs_id].value_()
        )
        nn = list_for_each_entry(
            "struct nfs_client",
            nfs_net.nfs_client_list.address_of_(),
            "cl_share_link",
        )
        nfs_clnts = chain(nfs_clnts, nn)
    return nfs_clnts


def nfs_server_list(nfs_client: Object) -> t.Iterator[Object]:
    """
    Given a nfs_client struct return a list of all associated struct nfs_server

    :param nfs_client: struct nfs_client
    :returns: list of associated struct nfs_server
    """

    return list_for_each_entry(
        "struct nfs_server",
        nfs_client.cl_superblocks.address_of_(),
        "client_link",
    )


def show_nfs_client(prog: drgn.Program, clnt: t.Union[Object, int]) -> None:
    """
    Given a nfs_client object or an kernel address, display the
    summary info of the nfs_client struct such as the remote hostname
    and IP address, the NFSv4 minor version, the nfs_server structs
    and the corresponding exports under this nfs_client.

    Example:
        clients = nfs_client_list(prog)
        show_nfs_client(prog, clients[0])

    :param prog: drgn program
    :param clnt: A nfs_client struct or a nfs_client address
    :returns: None
    """

    if isinstance(clnt, int):
        nfs_client = Object(prog, "struct nfs_client *", value=clnt)
    else:
        nfs_client = clnt
    server_name = nfs_client.cl_hostname.string_().decode()
    local_ip = nfs_client.cl_ipaddr.string_().decode()
    remote_ip = nfs_client.cl_addr.__data.value_()[2:6]

    print(
        "---- <nfs_client: 0x%x>  cl_minorversion: %d  cl_ipaddr: %s"
        % (nfs_client.value_(), nfs_client.cl_minorversion, local_ip)
    )
    print(
        "     cl_hostname: %s  cl_addr: %d.%d.%d.%d [remote]"
        % (
            server_name,
            remote_ip[0] & 0xFF,
            remote_ip[1] & 0xFF,
            remote_ip[2] & 0xFF,
            remote_ip[3] & 0xFF,
        )
    )

    print(
        "     cl_flags: 0x%x (%s)"
        % (
            nfs_client.cl_flags,
            NfsClientFlag.decode(nfs_client.cl_flags.value_()),
        )
    )

    # 212bf41d88c06: fs, nfs: convert nfs_client.cl_count from atomic_t to refcount_t
    if has_member(nfs_client.cl_count, "refs"):
        print("     cl_count: %d" % (nfs_client.cl_count.refs.counter))
    else:
        print("     cl_count: %d" % (nfs_client.cl_count.counter))

    if nfs_client.cl_rpcclient.cl_auth:
        RpcAuthFlavors = enum_type_to_class(
            prog.type("enum rpc_auth_flavors"), "RpcAuthFlavors"
        )
        enum_name = enum_name_get(
            RpcAuthFlavors,
            nfs_client.cl_rpcclient.cl_auth.au_flavor,
            "UNKNOWN",
        )
    else:
        enum_name = "NULL"
    print(
        "     cl_rpcclient: 0x%x  cl_auth.au_flavor: %d (%s)"
        % (
            nfs_client.cl_rpcclient.value_(),
            nfs_client.cl_rpcclient.cl_auth.au_flavor,
            enum_name,
        )
    )

    nfs_servers = nfs_server_list(nfs_client)
    for ns in nfs_servers:
        mount_src = ""
        mount_dst = ""
        mntp = get_mount(prog, ns.super)
        if mntp is not None:
            mount_src = escape_ascii_string(mntp.mnt_devname.string_())
            mount_dst = escape_ascii_string(
                d_path(mntp.mnt.address_of_(), mntp.mnt.mnt_root)
            )

        print(
            "          <nfs_server: 0x%x>  %s %s"
            % (ns.value_(), mount_src, mount_dst)
        )
        print(
            "          flags: 0x%x (%s)"
            % (ns.flags, NfsServerFlag.decode(ns.flags.value_()))
        )
        print(
            "          super: 0x%x  s_count: %d  s_active: %d"
            % (ns.super.value_(), ns.super.s_count, ns.super.s_active.counter)
        )
        print(
            "          client: 0x%x  nfs_client: 0x%x"
            % (ns.client.value_(), ns.nfs_client.value_())
        )
        display_nfs_delegations(ns, 10)
        print("")


def show_nfs_clients(prog) -> None:
    """
    Display summary information of the NFS layer on the NFS client side.
    The information includes major data structures such as nfs_client,
    nfs_server and corresponding RPC transport.

    :param prog: drgn pogram
    :returns: None
    """

    clients = nfs_client_list(prog)
    print(
        "============================== NFS_CLIENT ================================"
    )
    for clnt in clients:
        show_nfs_client(prog, clnt)


def _nfsshow(prog: drgn.Program, max_tasks: int = 10):
    show_nfs_clients(prog)
    show_rpc_clnts(prog)
    show_rpc_xprts(prog)
    show_rpc_tasks(prog, max_tasks)


def nfsshow(
    prog: drgn.Program, max_tasks: int = 10, filename: t.Optional[str] = None
) -> None:
    """
    Display summary information on NFS client side. The information includes
    major structures such as nfs_client, nfs_server, rpc_clnt, rpc_xprt and
    rpc_task.

    :param prog: drgn program
    :param max_tasks: the number of rpc_task to display, default to first 10 rpc_task.
    :param filename: filename to write nfsshow's output to. Default is None.
    :returns: None
    """

    if filename:
        with redirect_stdout(filename):
            _nfsshow(prog, max_tasks)
    else:
        _nfsshow(prog, max_tasks)


def get_mount(prog: drgn.Program, super_block: Object) -> Object:
    """
    Return the struct mount associated with the specified super_block

    :param prog: drgn program
    :param super_block: struct super_block
    :returns: struct mount associated with the specified super_block
    """

    prog = super_block.prog_
    ns = prog["init_task"].nsproxy.mnt_ns
    for mnt in for_each_mount(ns):
        if mnt.mnt.mnt_sb == super_block:
            return mnt
    return None


def get_ipaddr_str(sockaddr: Object) -> str:
    """
    Convert struct sockaddr_storage to IP address string.
    Only support IPv4 and IPv6 address family.

    :param addr: struct sockaddr_storage
    :returns: IP address string
    """

    prog = sockaddr.prog_
    if sockaddr.ss_family == 2:
        """AF_INET IPv4"""
        si = Object(
            prog, "struct sockaddr_in *", value=sockaddr.address_of_().value_()
        )
        ip = str(
            ipaddress.IPv4Address(socket.htonl(si.sin_addr.s_addr.value_()))
        )
        port = str(socket.htons(si.sin_port.value_()))
        return ip + ":" + port
    elif sockaddr.ss_family == 10:
        si = Object(
            prog, "struct in6_addr *", value=sockaddr.address_of_().value_()
        )
        ip = rds_inet_ntoa(si)
        """ AF_INET6 IPv6 """
        return ip
    elif sockaddr.ss_family == 1:
        """AF_UNIX Unix domain socket"""
        return "Unix domain socket"
    else:
        return (
            "Address Family["
            + str(sockaddr.ss_family.value_())
            + "] NOT_SUPPORTED"
        )


def lookup_ksym(prog: drgn.Program, addr: int) -> str:
    """
    Look up the symbol associated with the given kernel address.

    :param prog: drgn program
    :param addr: kernel address
    :returns: the symbol associated with the kernel address.
             If the symbol is not available, return the address
             as a string in hex.
    """

    if addr == 0:
        return "NULL"
    try:
        proc_sym = prog.symbol(addr).name
    except LookupError:
        proc_sym = str(hex(addr))
    return proc_sym


class NfsShow(CorelensModule):
    """Print summary information on NFS client side"""

    name = "nfsshow"

    # there's no point in running unless the nfs module is loaded
    skip_unless_have_kmod = "nfs"

    # we need sunrpc, and all nfs related debuginfo loaded
    debuginfo_kmods = ["sunrpc", "nfs", "nfs*"]

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--max_tasks",
            type=int,
            default=10,
            help="list at most <number> rpc_tasks",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        nfsshow(prog, max_tasks=args.max_tasks)
