# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Contains definitions for kernel taint values
"""
from enum import IntEnum

from drgn.helpers.common.format import decode_flags


class Taint(IntEnum):
    """
    Kernel and module taint flags

    These flags are not recorded in any enum type, only preprocessor
    definitions, since they need to be used in assembly listings in the kernel.
    Record them here. They can be found at ``include/linux/panic.h`` or for
    older kernels, ``include/linux/kernel.h``.
    """

    PROPRIETARY_MODULE = 0
    FORCED_MODULE = 1
    CPU_OUT_OF_SPEC = 2
    FORCED_RMMOD = 3
    MACHINE_CHECK = 4
    BAD_PAGE = 5
    USER = 6
    DIE = 7
    OVERRIDDEN_ACPI_TABLE = 8
    WARN = 9
    CRAP = 10
    FIRMWARE_WORKAROUND = 11
    OOT_MODULE = 12
    UNSIGNED_MODULE = 13
    SOFTLOCKUP = 14
    LIVEPATCH = 15
    AUX = 16
    RANDSTRUCT = 17
    FLAGS_COUNT = 18

    @classmethod
    def decode(cls, value: int) -> str:
        fields = [(v.name, v) for v in cls]
        return decode_flags(value, fields, bit_numbers=True)
