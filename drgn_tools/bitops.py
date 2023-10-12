# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from typing import Iterable


def for_each_bit_set(val: int, depth: int = 64) -> Iterable[int]:
    """
        List offset of each set bit in one word

    :param val: value of the world
    :param depth: maximum bit to be checked
    :returns: each set bit as one iterator
    """
    for index in range(depth):
        if val & 0x1:
            yield index
        val >>= 1
