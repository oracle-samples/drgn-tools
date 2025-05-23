#!/usr/bin/env drgn
from drgn import Object
from drgn import Program
from drgn import FaultError
from drgn import container_of
from drgn.helpers.common import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.list import list_for_each_entry
from drgn.helpers.linux.llist import llist_for_each_entry
from drgn.helpers.linux.llist import llist_empty
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry


def dump_hp_state(prog):
    for cpu in for_each_possible_cpu(prog):
        hpstate = per_cpu(prog["cpuhp_state"], cpu).state
        print(cpu, " : ", hpstate)

def dump_runq_wake_summary(runq: Object):
    cpu = runq.cpu.value_()
    if llist_empty(runq.wake_list):
        print(f"\ncpu: {cpu} has no tasks in its runq wake_list")
    else:
        print(f"\ncpu: {cpu} has following tasks in its runq wake_list")
        for task in llist_for_each_entry("struct task_struct", 
            per_cpu(runq.prog_["runqueues"], cpu).wake_list.first, "wake_entry"):
            print(f"task pid: {task.pid.value_()}, comm:  {task.comm.string_().decode()}")    
    return

def dump_runq_wait_summary(runq: Object):    
    cpu = runq.cpu.value_()
    if runq.curr.pid == 0:
        print(f"\ncpu: {cpu} is idle")
        return

    #rt_rq = runq.rt
    #if not rt_rq.rt_nr_running.value_():
    #    print("There are no runnable RT tasks on cpu: {cpu}")
    #else:
    #    print("The wait duration on RT runq of cpu: {cpu}:")
    #    rt_prio_array = rt_rq.active
    #    for prio in range(rt_prio_array.bitmap.nbits):
    #        if rt_prio_array.bitmap[prio]:
    #            print(f"\n Priority {prio} tasks: ")
    #            entry = head.next
    #            while entry != head.address_of_():
    #                task = container_of(entry, "struct task_struct", "se.run_list")
    #                qduration = runq.clock.value_() - task.sched_info.last_arrival.value_()
    #                print(f"pid: {task.pid.value_()} queued for {qduration} nsecs")
    cfs_rq = runq.cfs
    if not cfs_rq.nr_running.value_():
        print(f"\nThere are no runnable CFS tasks on cpu: {cpu}")
    else:
        print(f"\nThe wait duration on CFS runq of cpu: {cpu}:")
        rb_root = cfs_rq.tasks_timeline.rb_root
        for se in rbtree_inorder_for_each_entry("struct sched_entity", rb_root, "run_node"):
            task = container_of(se, "struct task_struct", "se")
            qduration = runq.clock.value_() - task.sched_info.last_arrival.value_()
            if not task.pid.value_():
                continue
            print(f"pid: {task.pid.value_()} queued for {qduration} nsecs")


    return

def dump_runq_summary(runq: Object):
    dump_runq_wait_summary(runq)
    dump_runq_wake_summary(runq)


#def check_runq_anomaly(runq): TODO
    # check if offlined runq has some tasks
    # check if tasks on the runq have been queued for long
    # check if critical tasks like migration/X , cpuhp/X etc are in the wake_list
    # check if idle CPU has tasks in its wake_list

def dump_all_runq_summary(prog: Program):
    for cpu in for_each_online_cpu(prog):
        runq = per_cpu(prog["runqueues"], cpu)
        dump_runq_summary(runq)
