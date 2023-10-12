# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from typing import Any
from typing import Generator
from typing import Iterable
from typing import TypeVar

T = TypeVar("T")


def count(it: Iterable[Any]) -> int:
    return sum(1 for _ in it)


def take(n: int, it: Iterable[T]) -> Generator[T, None, None]:
    for i, e in enumerate(it):
        if i == n:
            break
        yield e
