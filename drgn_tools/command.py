# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Convenience wrappers for drgn's command mode."""
from typing import Any
from typing import Callable


def _dummy_register(
    *args: Any, **kwargs: Any
) -> Callable[[Callable], Callable]:
    def decorator(f: Callable) -> Callable:
        return f

    return decorator


try:
    from drgn.commands import parse_shell_command
    from drgn.commands.linux import linux_kernel_custom_command

    HAVE_DRGN_COMMANDS = True
except (ImportError, ModuleNotFoundError):
    HAVE_DRGN_COMMANDS = False
    linux_kernel_custom_command = _dummy_register
    parse_shell_command = None

# The _crash module is private, and we should not be surprised or bothered if it
# changes from under us. Keep it in a separate try/except block so that even if
# future changes happen to the _crash module, we can still register our linux
# command.
try:
    from drgn.commands._crash import crash_custom_command
except (ImportError, ModuleNotFoundError):
    crash_custom_command = _dummy_register
