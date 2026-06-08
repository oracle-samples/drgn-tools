# Copyright (c) 2023, 2026 Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from pathlib import Path
from unittest import mock

from drgn.helpers.linux import for_each_partition

from drgn_tools import partition
from tests import DrgnToolsTestCase
from tests import skip_unless_live


class TestPartition(DrgnToolsTestCase):
    def test_partitioninfo(self):
        partition.print_partition_info(self.prog)

    @skip_unless_live
    def test_block_helpers(self):
        partitions_sysfs = []
        partitions_drgn = []

        def sysfs_int(p: Path, s: str, default: int = 0) -> int:
            n = p / s
            if not n.exists():
                return default
            return int(n.open().read().strip())

        path = Path("/sys/class/block")
        for block_dev_dir in path.iterdir():
            size = sysfs_int(block_dev_dir, "size")
            ro = bool(sysfs_int(block_dev_dir, "ro"))
            start = sysfs_int(block_dev_dir, "start")
            dev_path = block_dev_dir / "dev"
            # Hidden gendisks, such as NVMe multipath component namespaces,
            # have class directories but do not publish a sysfs dev number.
            if dev_path.exists():
                dev = dev_path.open().read().strip()
                maj, minor = map(int, dev.split(":"))
            else:
                maj = mock.ANY
                minor = mock.ANY
            name = block_dev_dir.name
            partitions_sysfs.append((name, size, ro, start, maj, minor))

        for part in for_each_partition(self.prog):
            info = partition.get_partition_info(part)
            partitions_drgn.append(
                (
                    info.name,
                    info.nr_sects,
                    info.ro,
                    info.start_sect,
                    info.major,
                    info.minor,
                )
            )

        self.assertCountEqual(partitions_sysfs, partitions_drgn)
