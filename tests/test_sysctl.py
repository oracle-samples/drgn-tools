# Copyright (c) 2023, 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import fnmatch
import os

from drgn.helpers.linux.pid import find_task

import drgn_tools.sysctl as sysctl
from tests import DrgnToolsTestCase
from tests import skip_unless_live


LIVE_SKIP = {
    # Dynamically generated values which we have not implemented:
    "dev.cdrom.info",
    "fs.binfmt_misc.status",
    "fs.quota.allocated_dquots",
    "fs.quota.cache_hits",
    "fs.quota.drops",
    "fs.quota.free_dquots",
    "fs.quota.lookups",
    "fs.quota.reads",
    "fs.quota.syncs",
    "fs.quota.writes",
    "kernel.auto_msgmni",  # returns dummy value of 0
    "kernel.cad_pid",  # not yet investigated
    "kernel.kexec_load_limit_panic",
    "kernel.kexec_load_limit_reboot",
    "kernel.numa_balancing",
    "kernel.rh_flags",
    "kernel.sched_energy_aware",  # int, but '' when disabled
    "kernel.sched_schedstats",
    "kernel.seccomp.actions_logged",
    "kernel.sysrq",
    "kernel.tainted",
    "kernel.task_delayacct",
    "kernel.threads-max",
    "kernel.usermodehelper.bset",
    "kernel.usermodehelper.inheritable",
    "net.core.default_qdisc",
    "net.core.flow_limit_cpu_bitmap",
    "net.core.rps_default_mask",
    "net.core.rps_sock_flow_entries",
    "net.ipv4.fib_multipath_hash_seed",
    "net.ipv4.ip_local_port_range",
    "net.ipv4.ping_group_range",
    "net.ipv4.tcp_allowed_congestion_control",
    "net.ipv4.tcp_available_congestion_control",
    "net.ipv4.tcp_available_ulp",
    "net.ipv4.tcp_congestion_control",
    "net.ipv4.tcp_ehash_entries",
    "net.ipv4.udp_hash_entries",
    "net.mptcp.available_path_managers",
    "net.mptcp.available_schedulers",
    "net.netfilter.nf_hooks_lwtunnel",
    "sunrpc.transports",
    "vm.nr_hugepages",
    "vm.nr_hugepages_mempolicy",
    "vm.nr_overcommit_hugepages",
    # Changes too frequently to reliably test:
    "fs.dentry-state",
    "fs.inode-nr",
    "fs.inode-state",
    "kernel.ns_last_pid",
    "kernel.random.entropy_avail",
    "kernel.random.fips_random",
    "kernel.random.uuid",
    # Write-only sysctls:
    "fs.xfs.stats_clear",
    "net.ipv4.route.flush",
    "net.ipv6.route.flush",
    "vm.compact_memory",
    "vm.drop_caches",
    "vm.stat_refresh",
    # Avoid displaying "secrets":
    "net.core.netdev_rss_key",
    "net.ipv4.tcp_fastopen_key",
    # Ksplice sysctls
    "kernel.known_exploit_detection",
    "kernel.known_exploit_detection_tripwires",
}

LIVE_SKIP_PATTERNS = (
    # Dynamically generated values which we have not implemented:
    "net.ipv6.conf.*.addr_gen_mode",
    "net.netfilter.nf_log.*",
    # Changes too frequently to reliably test:
    "kernel.sched_domain.*.max_newidle_lb_cost",
    # Avoid displaying "secrets":
    "net.ipv6.conf.*.stable_secret",
)


def should_skip(s):
    return s in LIVE_SKIP or any(
        fnmatch.fnmatch(s, pat) for pat in LIVE_SKIP_PATTERNS
    )


def get_sysctl_from_fs():
    expected = {}
    for root, _, filenames in os.walk("/proc/sys"):
        for filename in filenames:
            path = os.path.join(root, filename)
            key = os.path.relpath(path, "/proc/sys").replace(os.sep, ".")
            if should_skip(key):
                continue
            try:
                with open(path, encoding="utf-8") as f:
                    # Sysctls conventionally end in a newline, which is
                    # not part of the value reported by drgn-tools.
                    expected[key] = f.read().rstrip("\n")
            except OSError:
                # Some sysctls cannot be read, just as `sysctl -a` omits
                # them from its output.
                continue
    return expected


class TestSysctl(DrgnToolsTestCase):
    def test_smoke(self):
        # smoke test
        sysctl.print_sysctl_table(self.prog)

    def assertDictEqualPretty(self, d1, d2):
        differences = []
        common_keys = d1.keys() & d2.keys()
        for key in common_keys:
            if d1[key] != d2[key]:
                differences.append(f"key {key!r}: {d1[key]!r} != {d2[key]!r}")

        only_in_d1 = d1.keys() - d2.keys()
        if only_in_d1:
            differences.append(
                "Keys only in first dict: " + ", ".join(only_in_d1)
            )
        only_in_d2 = d2.keys() - d1.keys()
        if only_in_d2:
            differences.append(
                "Keys only in second dict: " + ", ".join(only_in_d2)
            )
        if differences:
            msg = "\n".join(["Dicts are not identical"] + differences)
            self.fail(msg)

    @skip_unless_live
    def test_live(self):
        our_task = find_task(self.prog, os.getpid())
        # It is important to read the sysctls once before we use the sysctl
        # helpers. Some sysctl handlers initialize state on their first run.
        expected = get_sysctl_from_fs()
        values = sysctl.get_sysctl_table(self.prog, context=our_task)

        for key in list(values.keys()):
            if should_skip(key):
                del values[key]

        self.assertDictEqualPretty(values, expected)
