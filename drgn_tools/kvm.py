# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import argparse
import enum
from typing import Iterable
from typing import Iterator

from drgn import cast
from drgn import Object
from drgn import Program
from drgn.helpers.common.type import enum_type_to_class
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.sched import task_state_to_char
from drgn.helpers.linux.xarray import xa_for_each

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_table
from drgn_tools.util import enum_name_get
from drgn_tools.util import has_member


class KvmVcpuState(enum.Enum):
    """
    Defined in include/uapi/linux/kvm.h, with prefix KVM_MP_STATE_
    """

    RUNNABLE = 0
    UNINITIALIZED = 1
    INIT_RECEIVED = 2
    HALTED = 3
    SIPI_RECEIVED = 4
    STOPPED = 5
    CHECK_STOP = 6
    OPERATING = 7
    LOAD = 8


class MemSlotFlag(enum.Enum):
    """
    kvm_memory_region::flags
    """

    KVM_MEM_LOG_DIRTY_PAGES = 1
    KVM_MEM_READONLY = 2


def for_each_vm(prog: Program) -> Iterable[Object]:
    """
    Iterates over all ``struct kvm *
    """
    try:
        yield from list_for_each_entry(
            "struct kvm", prog["vm_list"].address_of_(), "vm_list"
        )
    except KeyError:
        print("No VMs running")


def for_each_vcpu(vm: Object) -> Iterator[Object]:
    if has_member(vm, "vcpus"):
        vcpu_iterator = iter(vm.vcpus)
    else:
        vcpu_iterator = (
            cast("struct kvm_vcpu *", e)
            for _, e in xa_for_each(vm.vcpu_array.address_of_())
        )
    for struct_vcpu in vcpu_iterator:
        if struct_vcpu.value_() == 0:
            break
        yield struct_vcpu


def print_vm_list(prog: Program) -> None:
    """
    Print information for all the VMs
    """
    vm_list = for_each_vm(prog)

    print(" =============<< VM LIST >>=================")
    print("\n")
    rows = [
        [
            "KVM",
            "ONL",
            "CRT",
            "MEMSLOT_0",
            "MEMSLOT_1",
            "VCPUS",
            "KVM_ARCH",
            "KVM_STAT",
            "PID",
            "TASK",
            "CPU",
            "ST",
        ]
    ]

    for vm in vm_list:
        kvm_addr = hex(vm.value_())
        pid = vm.userspace_pid.value_()
        task = find_task(prog, pid)
        if has_member(task, "cpu"):
            cpu = task.cpu.value_()
        else:
            cpu = task.recent_used_cpu.value_()

        if has_member(vm, "vcpus"):
            vcpu = hex(vm.vcpus.address_of_())
        else:
            vcpu = hex(vm.vcpu_array.address_of_())

        rows.append(
            [
                kvm_addr,
                vm.online_vcpus.counter.value_(),
                vm.created_vcpus.value_(),
                hex(vm.memslots[0].value_()),
                hex(vm.memslots[1].value_()),
                vcpu,
                hex(vm.arch.address_of_()),
                hex(vm.stat.address_of_()),
                pid,
                hex(task.value_()),
                cpu,
                task_state_to_char(task),
            ]
        )
    print_table(rows)


def print_vcpu_list(prog: Program) -> None:
    """
    Print information for all the vcpus of each VM
    """
    vm_list = for_each_vm(prog)

    print(" =============<< VCPU LIST >>=================")
    print("\n")
    rows = [
        [
            "KVM",
            "VCPU",
            "ID",
            "IDX",
            "ARCH",
            "STAT",
            "STAT_ID",
            "STATE",
            "CPU",
            "TASK",
        ]
    ]

    for vm in vm_list:
        for vcpu in for_each_vcpu(vm):
            id = vcpu.vcpu_id.value_()

            if has_member(vcpu, "vcpu_idx"):
                idx = vcpu.vcpu_idx.value_()
            else:
                # The UEK5 does not have kvm_vcpu.vcpu_idx structure member. Print None instead.
                idx = None
            arch = hex(vcpu.arch.address_of_())
            stat = hex(vcpu.stat.address_of_())
            if has_member(vcpu, "stats_id"):
                stat_id = vcpu.stats_id.string_().decode("utf-8")
            else:
                # The UEK5 does not have kvm_vcpu.stats_id structure member. Print None instead.
                stat_id = None
            state = vcpu.arch.mp_state.value_()
            cpu = vcpu.cpu.value_()
            if has_member(vcpu, "wait"):
                task = hex(vcpu.wait.task.value_())
            else:
                # The UEK5 does not have kvm_vcpu.wait structure member. Print None instead.
                task = None
            rows.append(
                [
                    hex(vm.value_()),
                    hex(vcpu.value_()),
                    id,
                    idx,
                    arch,
                    stat,
                    stat_id,
                    KvmVcpuState(state).name,
                    cpu,
                    str(task),
                ]
            )

    print_table(rows)


def print_memslot_info(prog: Program) -> None:
    """
    Print memslots info of VM
    """
    vm_list = for_each_vm(prog)

    print(" =============<< MEMSLOT INFO >>=================\n")

    for vm in vm_list:
        rows = [
            [
                "KVM",
                "KVM_MEMSLOTS",
                "KVM_MEMORY_SLOT",
                "BASE_GFN",
                "PAGES",
                "ARCH",
                "USER_ADDR",
                "FLAGS",
            ]
        ]
        nr_pages = 0
        for memslot in vm.memslots:
            # for UEK5 to UEK7-U2
            if has_member(memslot, "memslots"):
                for j in range(memslot.used_slots.value_()):
                    mm = memslot.memslots[j]
                    gfn = mm.base_gfn.value_()
                    pages = mm.npages.value_()
                    arch = hex(mm.arch.address_of_())
                    usr_addr = hex(mm.userspace_addr.value_())
                    if mm.flags.value_() == 0:
                        flags = mm.flags.value_()
                    else:
                        flags = MemSlotFlag(mm.flags.value_()).name
                    nr_pages = nr_pages + pages
                    rows.append(
                        [
                            hex(vm.value_()),
                            hex(memslot.address_of_()),
                            hex(mm.address_of_()),
                            gfn,
                            pages,
                            arch,
                            usr_addr,
                            flags,
                        ]
                    )
            else:
                # Starting from UEK7-U3
                for vcpu in for_each_vcpu(vm):
                    mmslot = vcpu.last_used_slot
                    gfn = mmslot.base_gfn.value_()
                    pages = mmslot.npages.value_()
                    arch = hex(mmslot.arch.address_of_())
                    usr_addr = hex(mmslot.userspace_addr.value_())
                    if mmslot.flags.value_() == 0:
                        flags = mmslot.flags.value_()
                    else:
                        flags = MemSlotFlag(mmslot.flags.value_()).name
                    nr_pages = nr_pages + pages
                    rows.append(
                        [
                            hex(vm.value_()),
                            hex(memslot.value_()),
                            hex(mmslot.address_of_()),
                            gfn,
                            pages,
                            arch,
                            usr_addr,
                            flags,
                        ]
                    )
        print_table(rows)
        print("\n## Total Pages: %d ##" % (nr_pages))


def print_ioeventfd_info(prog: Program) -> None:
    """
    Print VM's ioeventfd information
    """
    vm_list = for_each_vm(prog)

    rows = [["KVM", "IOEVENTFD", "ADDR", "EVENTFD_CTX", "KVM_IO_DEV"]]
    nr_ioeventfds = 0

    for vm in vm_list:
        iofd = list_for_each_entry(
            "struct _ioeventfd", vm.ioeventfds.address_of_(), "list"
        )
        for fd in iofd:
            addr = hex(fd.addr.value_())
            ioeventfd = hex(fd.eventfd.value_())
            dev = fd.dev.address_of_()
            nr_ioeventfds = nr_ioeventfds + 1
            rows.append(
                [hex(vm.value_()), hex(fd.value_()), addr, ioeventfd, hex(dev)]
            )
    print("=============<< IOEVENTFDS >>=============")
    print_table(rows)
    print("\n## Total ioeventfds: ##", nr_ioeventfds)


def print_iobus_info(prog: Program) -> None:
    """
    Print iobus information of VM
    """
    rows = [
        ["KVM", "IOBUS", "BUS", "DEV_COUNT", "EVTFD_COUNT", "KVM_IO_RANGE"]
    ]

    vm_list = for_each_vm(prog)
    kvm_bus_type = enum_type_to_class(
        prog.type("enum kvm_bus"), "kvm_bus_type"
    )

    for vm in vm_list:
        iobus_iterator = iter(vm.buses)
        for i, bus in enumerate(iobus_iterator):
            iobus = hex(bus.value_())
            dev_count = bus.dev_count.value_()
            eventfd_count = bus.ioeventfd_count.value_()
            bus_name = enum_name_get(
                kvm_bus_type,
                i,
                "UNKNOWN",
            )
            range = hex(bus.range.address_of_())
            rows.append(
                [
                    hex(vm.value_()),
                    iobus,
                    str(bus_name),
                    dev_count,
                    eventfd_count,
                    range,
                ]
            )
    print("=============<< IOBUS >>=============")
    print_table(rows)


def print_kvmstat_info(prog: Program) -> None:
    """
    print vmstat and vcpustat information of a VM
    """
    vm_list = for_each_vm(prog)

    for vm in vm_list:
        stat = vm.stat
        if has_member(stat, "generic"):
            rtlab_flush = stat.generic.remote_tlb_flush.value_()
        else:
            rtlab_flush = stat.remote_tlb_flush.value_()
        if has_member(stat, "lpages"):
            lpages = stat.lpages.value_()
        else:
            lpages = "NA"
        if has_member(stat, "pages_1g"):
            pages_1g = stat.pages_1g.counter.value_()
        else:
            pages_1g = "NA"
        if has_member(stat, "pages_2m"):
            pages_2m = stat.pages_2m.counter.value_()
        else:
            pages_2m = "NA"
        if has_member(stat, "pages_4k"):
            pages_4k = stat.pages_4k.counter.value_()
        else:
            pages_4k = "NA"

        print("=============<< VMSTAT >>============= \n")
        rows_mm = [
            ["KVM", hex(vm.value_())],
            ["KVM_STAT", hex(vm.stat.address_of_())],
            ["Remote TLB Flush", rtlab_flush],
            ["MMU Shadow Zapped", stat.mmu_shadow_zapped.value_()],
            ["MMU PTE Write", stat.mmu_pte_write.value_()],
            ["MMU PDE Zapped", stat.mmu_pde_zapped.value_()],
            ["MMU Floaded", stat.mmu_flooded.value_()],
            ["MMU Recycled", stat.mmu_recycled.value_()],
            ["MMU Cache Miss", stat.mmu_cache_miss.value_()],
            ["MMU Unsync", stat.mmu_unsync.value_()],
            ["Lpages", lpages],
            ["NX Lpage Splits", stat.nx_lpage_splits.value_()],
            [
                "Max MMU Page Hash Collisions",
                stat.max_mmu_page_hash_collisions.value_(),
            ],
            ["Pages_1G", pages_1g],
            ["Pgaes_2M", pages_2m],
            ["Pages_4k", pages_4k],
        ]
        print_table(rows_mm)

        print("\n=============<< VCPU STAT >>============ \n")
        for vcpu in for_each_vcpu(vm):
            vcpu_stat = vcpu.stat
            rows_vcpu = [
                [
                    "VCPU:",
                    vcpu.vcpu_id.value_(),
                    "HALT_SUC:",
                    vcpu_stat.generic.halt_successful_poll.value_(),
                    "HALT_ATTMPT:",
                    vcpu_stat.generic.halt_attempted_poll.value_(),
                    "HALT_INV:",
                    vcpu_stat.generic.halt_poll_invalid.value_(),
                ],
                [
                    "PF_FIXED:",
                    vcpu_stat.pf_fixed.value_(),
                    "PF_GUEST:",
                    vcpu_stat.pf_guest.value_(),
                    "TLB_FLUSH:",
                    vcpu_stat.tlb_flush.value_(),
                    "INVLPG:",
                    vcpu_stat.invlpg.value_(),
                ],
                [
                    "EXITS:",
                    vcpu_stat.exits.value_(),
                    "IO_EXIT:",
                    vcpu_stat.io_exits.value_(),
                    "MMIO_EXIT:",
                    vcpu_stat.mmio_exits.value_(),
                    "SIG_EXIT:",
                    vcpu_stat.signal_exits.value_(),
                ],
                [
                    "IRQ_WIN_EXIT:",
                    vcpu_stat.irq_window_exits.value_(),
                    "NMI_WIN_EXIT:",
                    vcpu_stat.nmi_window_exits.value_(),
                    "L1D_FLUSH:",
                    vcpu_stat.l1d_flush.value_(),
                    "HALT_EXIT:",
                    vcpu_stat.halt_exits.value_(),
                ],
                [
                    "REQ_IRQ_EXIT:",
                    vcpu_stat.request_irq_exits.value_(),
                    "IRQ_EXITS:",
                    vcpu_stat.irq_exits.value_(),
                    "HOST_STATE_RL:",
                    vcpu_stat.host_state_reload.value_(),
                    "FPU_RL:",
                    vcpu_stat.fpu_reload.value_(),
                ],
                [
                    "INSN_EMUL:",
                    vcpu_stat.insn_emulation.value_(),
                    "INSN_EMUL_FAIL:",
                    vcpu_stat.insn_emulation_fail.value_(),
                    "HYPERCALLS:",
                    vcpu_stat.hypercalls.value_(),
                    "IRQ_INJ:",
                    vcpu_stat.irq_injections.value_(),
                ],
                [
                    "NMI_INJ:",
                    vcpu_stat.nmi_injections.value_(),
                    "REQ_EVENT:",
                    vcpu_stat.req_event.value_(),
                    "PREEMPT_RPT:",
                    vcpu_stat.preemption_reported.value_(),
                    "PREEMT_OTH:",
                    vcpu_stat.preemption_other.value_(),
                ],
            ]
            print()
            print_table(rows_vcpu)


class KvmUtil(CorelensModule):
    """
    Show all the VM related info from KVM host side
    """

    name = "kvm"
    skip_unless_have_kmods = ["kvm"]
    debuginfo_kmods = ["kvm-intel", "kvm-amd"]

    default_args = [
        [
            "--all",
        ]
    ]

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--vms",
            dest="list_vm",
            action="store_true",
            help="show all VM info",
        )
        parser.add_argument(
            "--vcpu",
            dest="vcpu_list",
            action="store_true",
            help="show all vcpu info",
        )
        parser.add_argument(
            "--mmslot",
            dest="memslot",
            action="store_true",
            help="show all memslot info",
        )
        parser.add_argument(
            "--ioeventfd",
            dest="ioeventfds",
            action="store_true",
            help="show all ioeventfds info",
        )
        parser.add_argument(
            "--iobus",
            dest="iobus",
            action="store_true",
            help="show all iobus info",
        )
        parser.add_argument(
            "--kvmstat",
            dest="kvmstat",
            action="store_true",
            help="show all iobus info",
        )
        parser.add_argument(
            "--all",
            action="store_true",
            help="show all of the above info",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        if args.list_vm or args.all:
            print_vm_list(prog)
        if args.vcpu_list or args.all:
            print_vcpu_list(prog)
        if args.memslot or args.all:
            print_memslot_info(prog)
        if args.ioeventfds or args.all:
            print_ioeventfd_info(prog)
        if args.iobus or args.all:
            print_iobus_info(prog)
        if args.kvmstat or args.all:
            print_kvmstat_info(prog)
        return
