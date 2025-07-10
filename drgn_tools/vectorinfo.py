# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Helper to print CPU vector information
"""
import argparse

import drgn
from drgn import Program
from drgn.helpers.linux.percpu import for_each_online_cpu
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.percpu import per_cpu_ptr

from drgn_tools.corelens import CorelensModule
from drgn_tools.table import Table
from drgn_tools.util import has_member

nr_vectors = 0x100
syscall_vector = 0x80
vector_start = 0x20
vector_end = 0xEC

# Reserved vectors = 53
# 0-31 for trap (32)
# 0x80/128 for syscall (1)
# 0xec to 0xff for internal use IPI and others (20)
# 32 + 1 + 20 = 53
res_vectors = 53


def dump_vectors(vectors: str) -> None:
    """
    Print the given string with a space after every 8 characters,
    and a newline after every 64 characters.
    """
    for i in range(0, len(vectors), 8):
        if i and i % 64 == 0:
            print()
        print(vectors[i : i + 8], end=" ")
    print()


def print_vector_matrix(prog: Program) -> None:
    """
    Print vector matrix information
    """
    try:
        vector_matrix = prog["vector_matrix"]
    except KeyError:
        print("\nvector_matrix not found; skipping vector info.\n")
        return
    per_cpu_vector_map = vector_matrix.maps
    print("System vector matrix:")
    print(f"\t{'Vector bits':25}: {vector_matrix.matrix_bits.value_()}")
    print(
        f"\t{'Vector allocation start':25}: {vector_matrix.alloc_start.value_()}"
    )
    print(
        f"\t{'Vector allocation end':25}: {vector_matrix.alloc_end.value_()}"
    )
    print(
        f"\t{'Vector allocation size':25}: {vector_matrix.alloc_size.value_()}"
    )
    print(
        f"\t{'Global available':25}: {vector_matrix.global_available.value_()}"
    )
    print(
        f"\t{'Global reserved':25}: {vector_matrix.global_reserved.value_()}"
    )
    print(
        f"\t{'Total allocated':25}: {vector_matrix.total_allocated.value_()}"
    )
    print(f"\t{'Online maps':25}: {vector_matrix.online_maps.value_()}")
    print()

    for cpu in for_each_online_cpu(prog):
        per_cpu_vector_matrix = per_cpu_ptr(per_cpu_vector_map, cpu)
        print(f"Per-CPU IRQ vector map (CPU {cpu}):")
        print(
            f"\t{'Available':25}: {per_cpu_vector_matrix.available.value_()}"
        )
        print(
            f"\t{'Allocated':25}: {per_cpu_vector_matrix.allocated.value_()}"
        )
        print(f"\t{'Managed':25}: {per_cpu_vector_matrix.managed.value_()}")
        print(
            f"\t{'Managed Allocated':25}: {per_cpu_vector_matrix.managed_allocated.value_()}"
        )
        print()


def print_vectors(prog: Program, verbose: bool) -> None:
    """
    Print vector information

    If -v flag specified, print per vector information
    """
    total_vectors_used = 0
    total_cpus = 0
    total_avl_vectors = 0
    system_vectors = []
    system_table = Table(
        [
            "CPU",
            "Total Vectors",
            "Used Vectors",
            "Reserved Vectors",
            "Available Vectors",
        ]
    )
    for cpu in for_each_online_cpu(prog):
        total_cpus += 1
        cpu_vector_list = ["0"] * 256
        cpu_vectors = per_cpu(prog["vector_irq"], cpu)
        per_cpu_vectors_used = 0
        per_cpu_avl_vectors = 0

        if verbose:
            print(f"\nCPU : {cpu}")
            per_cpu_table = Table(
                ["Vector", "IRQ", "Address", "Function", "Device", "Module"]
            )

        for vec in range(nr_vectors):
            if not cpu_vectors[vec]:
                if (
                    vec >= vector_start
                    and vec < vector_end
                    and vec != syscall_vector
                ):
                    per_cpu_avl_vectors += 1
                continue

            irqdesc = cpu_vectors[vec]
            per_cpu_vectors_used += 1
            cpu_vector_list[vec] = "1"

            if not verbose:
                continue

            irqdesc_addr = "NA"
            irqdesc_irq = "NA"
            irqdesc_fn = "NA"
            irqdesc_dev = "NA"
            irqdesc_mod = "NA"

            try:
                if irqdesc.action:
                    irqdesc_addr = hex(irqdesc.action.address_of_())
                    irqdesc_irq = irqdesc.action.irq.value_()

                    if irqdesc.action.name:
                        irqdesc_fn = irqdesc.action.name.string_().decode(
                            "utf-8"
                        )

                if has_member(irqdesc, "dev_name") and irqdesc.dev_name:
                    irqdesc_dev = irqdesc.dev_name.string_().decode("utf-8")

                if irqdesc.owner and irqdesc.owner.name:
                    irqdesc_mod = irqdesc.owner.name.string_().decode("utf-8")

            except drgn.FaultError:
                irqdesc_addr = "INV"
                irqdesc_irq = "INV"
                irqdesc_fn = "INV"
                irqdesc_dev = "INV"
                irqdesc_mod = "INV"

            per_cpu_table.row(
                vec,
                irqdesc_irq,
                irqdesc_addr,
                irqdesc_fn,
                irqdesc_dev,
                irqdesc_mod,
            )

        if verbose:
            per_cpu_table.write()
            print(
                f"Total: {nr_vectors}\tUsed: {per_cpu_vectors_used}\tReserved: {res_vectors}\tAvailable: {per_cpu_avl_vectors}"
            )

        system_vectors.append("".join(cpu_vector_list))

        total_vectors_used += per_cpu_vectors_used
        total_avl_vectors += per_cpu_avl_vectors
        system_table.row(
            cpu,
            nr_vectors,
            per_cpu_vectors_used,
            res_vectors,
            per_cpu_avl_vectors,
        )

    total_system_vectors = nr_vectors * total_cpus
    total_res_vectors = res_vectors * total_cpus
    for i in range(total_cpus):
        print(f"\nCPU : {i}")
        dump_vectors(system_vectors[i])
    print()
    system_table.row(
        "Total",
        total_system_vectors,
        total_vectors_used,
        total_res_vectors,
        total_avl_vectors,
    )
    system_table.write()


def print_vector_info(prog: Program, args: argparse.Namespace) -> None:
    """
    Helper to print CPU vector information
    """
    print_vector_matrix(prog)
    print_vectors(prog, args.verbose)


class VectorInfo(CorelensModule):
    """
    Corelens Module to print CPU vector information
    """

    name = "vectorinfo"

    def add_args(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            help="Print per vector information",
        )

    def run(self, prog: Program, args: argparse.Namespace) -> None:
        print_vector_info(prog, args)
