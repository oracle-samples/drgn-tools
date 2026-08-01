# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""Report limits and structure paths for the mlx5 Corelens report."""
import re


_PCI_BDF_RE = re.compile(
    r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$"
)

MAX_DEFAULT_DESCRIPTOR_ENTRIES = 32
MAX_DESCRIPTOR_ENTRIES = 4096
MAX_REPORT_ROWS = 1048576
MAX_CHANNELS = 128
MAX_QOS_SQS = 256
MAX_TC = 16
DEFAULT_DESCRIPTOR_ENTRY_BYTES = 64
