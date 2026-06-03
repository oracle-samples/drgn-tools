# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
from pathlib import Path

from drgn.helpers.linux import for_each_partition

from drgn_tools import partition
from tests import DrgnToolsTestCase
from tests import skip_unless_live


class TestPartition(DrgnToolsTestCase):
    def test_partitioninfo(self):
        partition.print_partition_info(self.prog)

    @skip_unless_live
    def test_block_helpers(self):
        partitions_sysfs = set()
        partitions_drgn = set()

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
            dev = (block_dev_dir / "dev").open().read().strip()
            maj, min = map(int, dev.split(":"))
            name = block_dev_dir.name
            partitions_sysfs.add((name, size, ro, start, maj, min))

        for part in for_each_partition(self.prog):
            info = partition.get_partition_info(part)
            partitions_drgn.add(
                (
                    info.name,
                    info.nr_sects,
                    info.ro,
                    info.start_sect,
                    info.major,
                    info.minor,
                )
            )

        assert partitions_sysfs == partitions_drgn
