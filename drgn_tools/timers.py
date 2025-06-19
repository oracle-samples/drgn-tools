# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Timers
--------------

The ``drgn.helpers.linux.timers`` module provides helpers for working with the
Linux hrtimers and timer wheel timers.
"""
import argparse

from drgn import FaultError
from drgn import Program
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.list import hlist_empty
from drgn.helpers.linux.list import hlist_for_each_entry
from drgn.helpers.linux.percpu import per_cpu

from drgn_tools.corelens import CorelensModule


__all__ = ("dump_timer_wheel_timers",)

_LVL_DEPTH = 9
_LVL_SIZE = 64
_WHEEL_SIZE = _LVL_DEPTH * _LVL_SIZE

#def ktime_to_ns(ktime):
#    return int(ktime)

#def ns_to_ms(ns):
#    return ns // 1_000_000

# Map known timer function names to descriptions
#KNOWN_TIMER_FUNCS = {
#    "tick_sched_timer": "Scheduler Tick",
#    "hrtimer_wakeup": "Userspace Wakeup (e.g., nanosleep)",
#    "posix_cpu_timer_schedule": "POSIX CPU Timer",
#    "it_real_fn": "ITIMER_REAL",
#    "hrtimer_nanosleep_restart": "Nanosleep Restart",
#}

print("Listing active hrtimers, remaining time, and owner task (if any):")

#for cpu in for_each_possible_cpu(prog: Program):
#    print(f"\n=== CPU {cpu} ===")
#    cpu_bases = prog["hrtimer_bases"][cpu].clock_base

#    for base_idx in range(8):
#        base = cpu_bases[base_idx]
#        print(f"  Clock base {base_idx}:")

#        for timer in list_for_each_entry("struct hrtimer", base.active, "node"):
#            expires_ns = ktime_to_ns(timer._softexpires.tv64)
#            now_ns = ktime_to_ns(ktime_get())

#            remaining_ns = max(0, expires_ns - now_ns)
#            fn_addr = timer.function
#            fn_name = address_to_symbol_name(fn_addr)
#            decoded = KNOWN_TIMER_FUNCS.get(fn_name, "Unknown")

#            print(f"    hrtimer @ {timer.address_}")
#            print(f"      Expires in: {ns_to_ms(remaining_ns)} ms")
#            print(f"      Function: {fn_name} ({decoded})")

#            # Special handling: if it's a hrtimer_wakeup, extract task
#            if fn_name == "hrtimer_wakeup":
#                # The hrtimer is embedded in struct hrtimer_sleeper
#                # So we cast back to container_of struct hrtimer_sleeper
#                # struct hrtimer_sleeper {
#                #     struct hrtimer timer;
#                #     struct task_struct *task;
#                # };
#                hrtimer_sleeper_type = prog.type("struct hrtimer_sleeper")
#                sleeper = timer.cast(hrtimer_sleeper_type)
#                task = sleeper.task

#                if task:
#                    print(f"      Task PID: {task.pid}, comm: {task.comm.string_().decode()}, state: {task_state_to_str(task.state)}")


def dump_timer_wheel_timers(prog: Program) -> None:
    online_cpus = list(for_each_online_cpu(prog))

    for cpu in for_each_possible_cpu(prog):
        cpu_state = "online" if cpu in online_cpus else "offline"
        print(f"### CPU: {cpu} state: {cpu_state} ###")

        try:
            for timer_base in per_cpu(prog["timer_bases"], cpu):
                if (
                    timer_base.value_()
                    == per_cpu(prog["timer_bases"][0], cpu).value_()
                ):
                    base_type = "BASE_STD"
                elif (
                    timer_base.value_()
                    == per_cpu(prog["timer_bases"][1], cpu).value_()
                ):
                    base_type = "BASE_DEF"
                else:
                    base_type = "BASE_UNKNOWN"
                for idx in range(_WHEEL_SIZE):
                    if hlist_empty(timer_base.vectors[idx]):
                        continue
                    for timer in hlist_for_each_entry(
                        "struct timer_list",
                        timer_base.vectors[idx].address_of_(),
                        "entry",
                    ):
                        jiffies = prog["jiffies"].value_()
                        tte = timer.expires.value_() - jiffies
                        try:
                            func = prog.symbol(timer.function.value_()).name
                        except LookupError:
                            func = f"UNKNOWN: 0x{timer.function.value_():x}"
                        print(
                            f"timer_base: {timer_base.address_:x} base_type: {base_type} idx: {idx} timer: {timer.value_():x} tte(jiffies): {tte} func: {func}"
                        )
        except FaultError:
            continue


class TimerModule(CorelensModule):
    """Show details about timers"""

    name = "timers"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        dump_timer_wheel_timers(prog)
