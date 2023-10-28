# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper to view cpuinfo data
"""
import argparse
from typing import Any
from typing import Dict

from drgn import Architecture
from drgn import Object
from drgn import Program
from drgn import sizeof
from drgn.helpers.linux.bitops import for_each_set_bit
from drgn.helpers.linux.bitops import test_bit
from drgn.helpers.linux.percpu import per_cpu

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import print_dictionary


# Constants
X86_FEATURE_PTI = 7 * 32 + 11
X86_FEATURE_IBPB = 7 * 32 + 26
X86_FEATURE_USE_IBRS_FW = 7 * 32 + 22
X86_FEATURE_RSB_CTXSW = 7 * 32 + 19
X86_FEATURE_HYPERVISOR = 4 * 32 + 31
X86_FEATURE_MSR_IA32_FEAT_CTL = 7 * 32 + 31
X86_FEATURE_VMX = 4 * 32 + 5

X86_BUG_MSBDS_ONLY = 20
X86_BUG_MMIO_UNKNOWN = 26

X86_CR4_VMXE = 1 << 13

X86_VENDOR_HYGON = 2
X86_VENDOR_AMD = 3

SPEC_CTRL_IBRS_FIRMWARE = 1 << 3
SPEC_CTRL_IBPB_INUSE = 1 << 0

TAINT_NO_RETPOLINE = 16

AARCH64_MIDR_REVISION_MASK = 0xF
AARCH64_MIDR_PARTNUM_SHIFT = 4
AARCH64_MIDR_PARTNUM_MASK = 0xFFF << AARCH64_MIDR_PARTNUM_SHIFT
AARCH64_MIDR_VARIANT_SHIFT = 20
AARCH64_MIDR_VARIANT_MASK = 0xF << AARCH64_MIDR_VARIANT_SHIFT
AARCH64_MIDR_IMPLEMENTOR_SHIFT = 24
AARCH64_MIDR_IMPLEMENTOR_MASK = 0xFF << AARCH64_MIDR_IMPLEMENTOR_SHIFT


def x86_get_cpu_info(prog: Program) -> Dict[str, Any]:
    """
    Helper to get cpuinfo data for x86

    :returns: a dictionary of the cpuinfo data
    """
    cpus = int(prog["nr_cpu_ids"])

    if "cpu_data" in prog:
        cpuinfo_struct = prog["cpu_data"].read_()
    elif "boot_cpu_data" in prog:
        cpuinfo_struct = prog["boot_cpu_data"].read_()
    else:
        raise Exception(
            "Failed to load CPU info: no cpuinfo struct found (tried 'cpu_data' and 'boot_cpu_data')"
        )

    cpu_vendor = cpuinfo_struct.x86_vendor_id.string_().decode("utf-8")
    model_name = cpuinfo_struct.x86_model_id.string_().decode("utf-8")
    cpu_family = int(cpuinfo_struct.x86)
    cpus_numa0 = "0-" + str(cpus - 1)
    microcode = hex(cpuinfo_struct.microcode)
    cstates = int(prog["max_cstate"])

    cap = cpuinfo_struct.x86_capability
    cap_flags = prog["x86_cap_flags"].read_()
    bug_flags = prog["x86_bug_flags"].read_()

    cpu_flags_list = []
    bug_flags_list = []

    for nr in for_each_set_bit(cap, 8 * sizeof(cap)):
        if nr < len(cap_flags) and cap_flags[nr]:
            cpu_flags_list.append(cap_flags[nr].string_().decode("utf-8"))
        elif nr >= len(cap_flags) and bug_flags[nr - len(cap_flags)]:
            bug_flags_list.append(
                bug_flags[nr - len(cap_flags)].string_().decode("utf-8")
            )

    return {
        "CPU VENDOR": cpu_vendor,
        "MODEL NAME": model_name,
        "CPU FAMILY": cpu_family,
        "CPUS": cpus,
        "CPUS NUMA0": cpus_numa0,
        "MICROCODE": microcode,
        "CSTATES": cstates,
        "CPU FLAGS": " ".join(cpu_flags_list),
        "BUG FLAGS": " ".join(bug_flags_list),
    }


def aarch64_get_cpu_info(prog: Program) -> Dict[str, Any]:
    """
    Helper to get cpuinfo data for aarch64

    :returns: a dictionary of the cpuinfo data
    """
    cpus = int(prog["nr_cpu_ids"])
    midr = prog["boot_cpu_data"].reg_midr
    cpu_caps_list = []

    hwcap_str = prog["hwcap_str"].read_()
    elf_hwcap = prog["elf_hwcap"].read_()
    num_caps = len(hwcap_str)

    for i in range(num_caps):
        if elf_hwcap & (1 << i):
            cpu_caps_list.append(hwcap_str[i].string_().decode("utf-8"))

    midr_implementor = hex(
        (midr & AARCH64_MIDR_IMPLEMENTOR_MASK)
        >> AARCH64_MIDR_IMPLEMENTOR_SHIFT
    )
    midr_architecture = 8
    midr_variant = hex(
        (midr & AARCH64_MIDR_VARIANT_MASK) >> AARCH64_MIDR_VARIANT_SHIFT
    )
    midr_partnum = hex(
        (midr & AARCH64_MIDR_PARTNUM_MASK) >> AARCH64_MIDR_PARTNUM_SHIFT
    )
    midr_revision = int(midr & AARCH64_MIDR_REVISION_MASK)

    return {
        "CPUs": cpus,
        "Features": " ".join(cpu_caps_list),
        "CPU Implementer": midr_implementor,
        "CPU Architecture": midr_architecture,
        "CPU Variant": midr_variant,
        "CPU Part": midr_partnum,
        "CPU Revision": midr_revision,
    }


def check_smt_enabled(prog: Program) -> bool:
    """
    Checks if SMT (Simultaneous Multithreading) is enabled
    """
    if "sched_smt_present" not in prog:
        return prog["cpu_smt_control"] == prog.constant("CPU_SMT_ENABLED")
    else:
        return prog["sched_smt_present"].key.enabled.counter > 0


def get_meltdown_mitigation(prog: Program, cpu_caps_bugs: Object) -> str:
    """
    Extracts Mitigation for Meltdown
    """
    mitigation = ""
    if test_bit(X86_FEATURE_PTI, cpu_caps_bugs):
        mitigation = "Mitigation: PTI"
    else:
        if "x86_hyper_type" not in prog:
            if prog["xen_domain_type"] != prog.constant("XEN_NATIVE") and prog[
                "xen_domain_type"
            ] == prog.constant(
                "XEN_PV_DOMAIN"
            ):  # This is how it is defined in the kernel
                mitigation = (
                    "Unknown (XEN PV detected, hypervisor mitigation required)"
                )
        elif prog["x86_hyper_type"] == prog.constant("X86_HYPER_XEN_PV"):
            mitigation = (
                "Unknown (XEN PV detected, hypervisor mitigation required)"
            )

    return mitigation


def get_spectre_v1_mitigation(prog: Program, cpu_caps_bugs: Object) -> str:
    """
    Extracts Mitigation for Spectre_V1
    """
    return (
        prog["spectre_v1_strings"][prog["spectre_v1_mitigation"]]
        .string_()
        .decode("utf-8")
    )


def get_spectre_v2_mitigation(prog: Program, cpu_caps_bugs: Object) -> str:
    """
    Extracts Mitigation for Spectre_V2
    """
    if "SPECTRE_V2_LFENCE" not in prog:
        mitigation = (
            prog["spectre_v2_strings"][prog["spectre_v2_enabled"]]
            .string_()
            .decode("utf-8")
        )
        if test_bit(
            TAINT_NO_RETPOLINE,
            prog["tainted_mask"].address_of_()
            # TAINT_NO_RETPOLINE exists only for UEK4. It taints kernel for
            # missing retpoline in module
        ) and (
            prog["spectre_v2_enabled"]
            == prog.constant("SPECTRE_V2_RETPOLINE_GENERIC")
            or prog["spectre_v2_enabled"]
            == prog.constant("SPECTRE_V2_RETPOLINE_AMD")
        ):
            mitigation += " (non-retpoline module(s) has been loaded)"
        if prog["use_ibrs"] & SPEC_CTRL_IBRS_FIRMWARE:
            mitigation += ", IBRS_FW"
        if prog["use_ibpb"] & SPEC_CTRL_IBPB_INUSE:
            mitigation += ", IBPB"
    else:
        if prog["spectre_v2_enabled"] == prog.constant("SPECTRE_V2_LFENCE"):
            mitigation = "Vulnerable: LFENCE"
        elif (
            prog["spectre_v2_enabled"] == prog.constant("SPECTRE_V2_EIBRS")
            and not prog["sysctl_unprivileged_bpf_disabled"]
        ):
            mitigation = "Vulnerable: eIBRS with unprivileged eBPF"
        elif (
            check_smt_enabled(prog)
            and not prog["sysctl_unprivileged_bpf_disabled"]
            and prog["spectre_v2_enabled"]
            == prog.constant("SPECTRE_V2_EIBRS_LFENCE")
        ):
            mitigation = (
                "Vulnerable: eIBRS+LFENCE with unprivileged eBPF and SMT"
            )
        else:
            mitigation = (
                prog["spectre_v2_strings"][prog["spectre_v2_enabled"]]
                .string_()
                .decode("utf-8")
            )
            if test_bit(X86_FEATURE_IBPB, cpu_caps_bugs):
                if prog["switch_mm_always_ibpb"].key.enabled.counter > 0:
                    mitigation += ", IBPB: always-on"
                elif prog["switch_mm_cond_ibpb"].key.enabled.counter > 0:
                    mitigation += ", IBPB: conditional"
                else:
                    mitigation += ", IBPB: disabled"
            if (
                "ibrs_firmware_enabled_key" in prog
                and prog["ibrs_firmware_enabled_key"].key.enabled.counter > 0
            ):
                mitigation += ", IBRS_FW"
            elif test_bit(X86_FEATURE_USE_IBRS_FW, cpu_caps_bugs):
                mitigation += ", IBRS_FW"

            if (
                prog["spectre_v2_enabled"] != prog.constant("SPECTRE_V2_EIBRS")
                and prog["spectre_v2_enabled"]
                != prog.constant("SPECTRE_V2_EIBRS_RETPOLINE")
                and prog["spectre_v2_enabled"]
                != prog.constant("SPECTRE_V2_EIBRS_LFENCE")
            ):  # Not in EIBRS Mode
                if prog["spectre_v2_user_stibp"] == prog.constant(
                    "SPECTRE_V2_USER_NONE"
                ):
                    mitigation += ", STIBP: disabled"
                elif prog["spectre_v2_user_stibp"] == prog.constant(
                    "SPECTRE_V2_USER_STRICT"
                ):
                    mitigation += ", STIBP: forced"
                elif prog["spectre_v2_user_stibp"] == prog.constant(
                    "SPECTRE_V2_USER_STRICT_PREFERRED"
                ):
                    mitigation += ", STIBP: always-on"
                elif prog["spectre_v2_user_stibp"] == prog.constant(
                    "SPECTRE_V2_USER_PRCTL"
                ) or prog["spectre_v2_user_stibp"] == prog.constant(
                    "SPECTRE_V2_USER_SECCOMP"
                ):
                    if prog["switch_to_cond_stibp"].key.enabled.counter > 0:
                        mitigation += ", STIBP: conditional"

            if test_bit(X86_FEATURE_RSB_CTXSW, cpu_caps_bugs):
                mitigation += ", RSB filling"

            if prog["spectre_v2_bad_module"]:
                mitigation += " - vulnerable module loaded"

    return mitigation


def get_ssb_mitigation(prog: Program, cpu_caps_bugs: Object) -> str:
    """
    Extracts Mitigation for spec_store_bypass
    """
    return prog["ssb_strings"][prog["ssb_mode"]].string_().decode("utf-8")


def get_l1tf_mitigation(prog: Program, cpu_caps_bugs: Object) -> str:
    """
    Extracts Mitigation for L1TF
    """
    mitigation = "Mitigation: PTE Inversion"
    if "l1tf_vmx_states" in prog:
        if prog["l1tf_vmx_mitigation"] == prog.constant(
            "VMENTER_L1D_FLUSH_AUTO"
        ):
            pass
        elif (
            prog["l1tf_vmx_mitigation"]
            == prog.constant("VMENTER_L1D_FLUSH_EPT_DISABLED")
            or prog["l1tf_vmx_mitigation"]
            == prog.constant("VMENTER_L1D_FLUSH_NEVER")
        ) and (check_smt_enabled(prog)):
            mitigation += "; VMX: "
            mitigation += (
                prog["l1tf_vmx_states"][prog["l1tf_vmx_mitigation"]]
                .string_()
                .decode("utf-8")
            )
        else:
            mitigation += "; VMX: "
            mitigation += (
                prog["l1tf_vmx_states"][prog["l1tf_vmx_mitigation"]]
                .string_()
                .decode("utf-8")
            )
            mitigation += ", SMT "
            if check_smt_enabled(prog):
                mitigation += "vulnerable"
            else:
                mitigation += "disabled"

    return mitigation


def get_mds_mitigation(prog: Program, cpu_caps_bugs: Object) -> str:
    """
    Extracts Mitigation for MDS
    """
    mitigation = (
        prog["mds_strings"][prog["mds_mitigation"]].string_().decode("utf-8")
    )
    mitigation += "; SMT "
    num_caps = len(prog["x86_cap_flags"])
    if test_bit(X86_FEATURE_HYPERVISOR, cpu_caps_bugs):
        mitigation += "Host state unknown"
    elif test_bit(num_caps + X86_BUG_MSBDS_ONLY, cpu_caps_bugs):
        if prog["mds_mitigation"] == prog.constant("MDS_MITIGATION_OFF"):
            mitigation += "vulnerable"
        elif check_smt_enabled(prog):
            mitigation += "mitigated"
        else:
            mitigation += "disabled"
    else:
        if check_smt_enabled(prog):
            mitigation += "vulnerable"
        else:
            mitigation += "disabled"

    return mitigation


def get_taa_mitigation(prog: Program, cpu_caps_bugs: Object) -> str:
    """
    Extracts Mitigation for tsx_async_abort
    """
    mitigation = (
        prog["taa_strings"][prog["taa_mitigation"]].string_().decode("utf-8")
    )

    if prog["taa_mitigation"] == prog.constant(
        "TAA_MITIGATION_TSX_DISABLED"
    ) or prog["taa_mitigation"] == prog.constant("TAA_MITIGATION_OFF"):
        pass
    elif test_bit(X86_FEATURE_HYPERVISOR, cpu_caps_bugs):
        mitigation += "; SMT Host state unknown"
    else:
        mitigation += "; SMT "
        if check_smt_enabled(prog):
            mitigation += "vulnerable"
        else:
            mitigation += "disabled"

    return mitigation


def get_itlb_multihit_mitigation(prog: Program, cpu_caps_bugs: Object) -> str:
    """
    Extracts Mitigation for itlb_multihit
    """
    if "l1tf_vmx_states" not in prog:
        mitigation = "Processor vulnerable"
    elif "cr4_read_shadow" in prog:
        if (not test_bit(X86_FEATURE_MSR_IA32_FEAT_CTL, cpu_caps_bugs)) or (
            not test_bit(X86_FEATURE_VMX, cpu_caps_bugs)
        ):
            mitigation = "KVM: Mitigation: VMX unsupported"
        elif not per_cpu(prog["cpu_tlbstate"], 0).cr4 & X86_CR4_VMXE:
            mitigation = "KVM: Mitigation: VMX disabled"
    elif prog["itlb_multihit_kvm_mitigation"]:
        mitigation = "KVM: Mitigation: Split huge pages"
    else:
        mitigation = "KVM: Vulnerable"

    return mitigation


def get_srbds_mitigation(prog: Program, cpu_caps_bugs: Object) -> str:
    """
    Extracts Mitigation for SRBDS
    """
    return (
        prog["srbds_strings"][prog["srbds_mitigation"]]
        .string_()
        .decode("utf-8")
    )


def get_mmio_stale_data_mitigation(
    prog: Program, cpu_caps_bugs: Object
) -> str:
    """
    Extracts Mitigation for mmio_stale_data and mmio_unknown
    """
    num_caps = len(prog["x86_cap_flags"])
    if test_bit(num_caps + X86_BUG_MMIO_UNKNOWN, cpu_caps_bugs):
        mitigation = "Unknown: No mitigations"
    else:
        mitigation = (
            prog["mmio_strings"][prog["mmio_mitigation"]]
            .string_()
            .decode("utf-8")
        )
        if prog["mmio_mitigation"] == prog.constant("MMIO_MITIGATION_OFF"):
            pass
        elif test_bit(X86_FEATURE_HYPERVISOR, cpu_caps_bugs):
            mitigation += "; SMT Host state unknown"
        else:
            mitigation += "; SMT "
            if check_smt_enabled(prog):
                mitigation += "vulnerable"
            else:
                mitigation += "disabled"

    return mitigation


def get_retbleed_mitigation(prog: Program, cpu_caps_bugs: Object) -> str:
    """
    Extracts Mitigation for Retbleed
    """
    if "cpu_data" in prog:
        x86_vendor = prog["cpu_data"].x86_vendor
    elif "boot_cpu_data" in prog:
        x86_vendor = prog["boot_cpu_data"].x86_vendor
    else:
        raise Exception(
            "Failed to load CPU info: no cpuinfo struct found (tried 'cpu_data' and 'boot_cpu_data')"
        )

    if "retbleed_state" in prog:
        if prog["retbleed_state"] == prog.constant(
            "RETBLEED_MITIGATION_UNRET"
        ):
            if x86_vendor != X86_VENDOR_AMD and x86_vendor != X86_VENDOR_HYGON:
                mitigation = (
                    "Vulnerable: untrained return thunk on non-Zen uarch"
                )
            else:
                mitigation = (
                    prog["retbleed_strings"][prog["retbleed_state"]]
                    .string_()
                    .decode("utf-8")
                    + "; SMT "
                )
                if not check_smt_enabled(prog):
                    mitigation += "disabled"
                elif prog["spectre_v2_user_stibp"] == prog.constant(
                    "SPECTRE_V2_USER_STRICT"
                ) or prog["spectre_v2_user_stibp"] == prog.constant(
                    "SPECTRE_V2_USER_STRICT_PREFERRED"
                ):
                    mitigation += "enabled with STIBP protection"
                else:
                    mitigation += "vulnerable"
        else:
            mitigation = (
                prog["retbleed_strings"][prog["retbleed_state"]]
                .string_()
                .decode("utf-8")
            )
    else:
        if prog["retbleed_mitigation"] == prog.constant(
            "RETBLEED_MITIGATION_UNRET"
        ) or prog["retbleed_mitigation"] == prog.constant(
            "RETBLEED_MITIGATION_IBPB"
        ):
            if x86_vendor != X86_VENDOR_AMD and x86_vendor != X86_VENDOR_HYGON:
                mitigation = "Vulnerable: untrained return thunk / IBPB on non-AMD based uarch"
            else:
                mitigation = (
                    prog["retbleed_strings"][prog["retbleed_mitigation"]]
                    .string_()
                    .decode("utf-8")
                    + "; SMT "
                )
                if not check_smt_enabled(prog):
                    mitigation += "disabled"
                elif prog["spectre_v2_user_stibp"] == prog.constant(
                    "SPECTRE_V2_USER_STRICT"
                ) or prog["spectre_v2_user_stibp"] == prog.constant(
                    "SPECTRE_V2_USER_STRICT_PREFERRED"
                ):
                    mitigation += "enabled with STIBP protection"
                else:
                    mitigation += "vulnerable"
        else:
            mitigation = (
                prog["retbleed_strings"][prog["retbleed_mitigation"]]
                .string_()
                .decode("utf-8")
            )

    return mitigation


def get_gds_mitigation(prog: Program, cpu_caps_bugs: Object) -> str:
    """
    Extracts Mitigation for GDS
    """
    return (
        prog["gds_strings"][prog["gds_mitigation"]].string_().decode("utf-8")
    )


def get_srso_mitigation(prog: Program, cpu_caps_bugs: Object) -> str:
    """
    Extracts Mitigation for SRSO
    """
    return "Vulnerable (Status Unknown)"
    # Currently cannot handle this mitigation data because the kernel uses
    # assembly code to fetch it


def x86_get_cpu_mitigations(prog: Program) -> Dict[str, str]:
    """
    Helper to get mitigations for vulnerabilities for x86

    :returns: a dictionary of vulnerabilities with their mitigations
    """
    vuln_to_checker = {
        "Meltdown": get_meltdown_mitigation,
        "Spectre_V1": get_spectre_v1_mitigation,
        "Spectre_V2": get_spectre_v2_mitigation,
        "L1TF": get_l1tf_mitigation,
        "MDS": get_mds_mitigation,
        "tsx_async_abort": get_taa_mitigation,
        "itlb_multihit": get_itlb_multihit_mitigation,
        "SRDBS": get_srbds_mitigation,
        "mmio_stale_data": get_mmio_stale_data_mitigation,
        "mmio_unknown": get_mmio_stale_data_mitigation,
        "Retbleed": get_retbleed_mitigation,
        "spec_store_bypass": get_ssb_mitigation,
        "GDS": get_gds_mitigation,
        "SRSO": get_srso_mitigation,
    }
    bug_to_vuln_name = {
        "cpu_meltdown": "Meltdown",
        "spectre_v1": "Spectre_V1",
        "spectre_v2": "Spectre_V2",
        "l1tf": "L1TF",
        "mds": "MDS",
        "taa": "tsx_async_abort",
        "srbds": "SRBDS",
        "retbleed": "Retbleed",
        "gds": "GDS",
        "srso": "SRSO",
    }

    if "cpu_data" in prog:
        cpuinfo_struct = prog["cpu_data"].read_()
    elif "boot_cpu_data" in prog:
        cpuinfo_struct = prog["boot_cpu_data"].read_()
    else:
        raise Exception(
            "Failed to load CPU info: no cpuinfo struct found (tried 'cpu_data' and 'boot_cpu_data')"
        )

    cpu_caps_bugs = cpuinfo_struct.x86_capability

    cpuinfo_data = x86_get_cpu_info(prog)
    bugs = cpuinfo_data["BUG FLAGS"].split()
    mitigations = {vuln: "Not Affected" for vuln in vuln_to_checker}

    for bug in bugs:
        vuln_name = bug_to_vuln_name.get(bug, bug)
        mitigation_checker = vuln_to_checker.get(vuln_name)
        if mitigation_checker:
            mitigations[vuln_name] = mitigation_checker(prog, cpu_caps_bugs)
        else:
            mitigations[vuln_name] = "Vulnerable"

    return mitigations


def print_cpu_info(prog: Program) -> None:
    """
    Prints the cpuinfo data
    """
    if prog.platform.arch == Architecture.X86_64:
        cpuinfo_data = x86_get_cpu_info(prog)
        print_dictionary(cpuinfo_data)

        mitigation_data = x86_get_cpu_mitigations(prog)
        print("\nVULNERABILITIES:")
        print_dictionary(mitigation_data)

    elif prog.platform.arch == Architecture.AARCH64:
        cpuinfo_data = aarch64_get_cpu_info(prog)
        print_dictionary(cpuinfo_data)

    else:
        print(f"Not supported for {prog.platform.arch.name}")


class Cpu(CorelensModule):
    """
    Corelens Module for cpuinfo
    """

    name = "cpuinfo"

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_cpu_info(prog)
