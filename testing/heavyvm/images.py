# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Describes the "heavy" images used for running tests
"""
import dataclasses
from typing import List


@dataclasses.dataclass
class ImageInfo:
    ol: int
    ol_update: int
    uek: int
    arch: str
    iso_url: str
    rpms: List[str]

    @property
    def iso_name(self) -> str:
        return f"ol{self.ol}-u{self.ol_update}-{self.arch}-boot-uek.iso"

    @property
    def name(self) -> str:
        return f"ol{self.ol}-u{self.ol_update}-uek{self.uek}-{self.arch}"

    @property
    def image_name(self) -> str:
        return f"{self.name}.qcow"

    @property
    def ks_name(self) -> str:
        return f"{self.name}-ks.cfg"


CONFIGURATIONS = [
    # OL9: UEK 7
    ImageInfo(
        9,
        5,
        7,
        "x86_64",
        "https://yum.oracle.com/ISOS/OracleLinux/OL9/u5/x86_64/OracleLinux-R9-U5-x86_64-boot-uek.iso",  # noqa
        ["drgn-0.0.29-1.0.1.el9.x86_64.rpm"],
    ),
    # OL8: UEK 6-7
    ImageInfo(
        8,
        10,
        7,
        "x86_64",
        "https://yum.oracle.com/ISOS/OracleLinux/OL8/u10/x86_64/OracleLinux-R8-U10-x86_64-boot-uek.iso",  # noqa
        ["drgn-0.0.29-1.0.1.el8.x86_64.rpm"],
    ),
    ImageInfo(
        8,
        10,
        6,
        "x86_64",
        "https://yum.oracle.com/ISOS/OracleLinux/OL8/u10/x86_64/OracleLinux-R8-U10-x86_64-boot-uek.iso",  # noqa
        ["drgn-0.0.29-1.0.1.el8.x86_64.rpm"],
    ),
    # OL7: UEK 4-6
    ImageInfo(
        7,
        9,
        6,
        "x86_64",
        "https://yum.oracle.com/ISOS/OracleLinux/OL7/u9/x86_64/x86_64-boot-uek.iso",  # noqa
        ["drgn-0.0.29-1.0.1.el7.x86_64.rpm"],
    ),
    ImageInfo(
        7,
        9,
        5,
        "x86_64",
        "https://yum.oracle.com/ISOS/OracleLinux/OL7/u9/x86_64/x86_64-boot-uek.iso",  # noqa
        ["drgn-0.0.29-1.0.1.el7.x86_64.rpm"],
    ),
    ImageInfo(
        7,
        9,
        4,
        "x86_64",
        "https://yum.oracle.com/ISOS/OracleLinux/OL7/u9/x86_64/x86_64-boot-uek.iso",  # noqa
        ["drgn-0.0.29-1.0.1.el7.x86_64.rpm"],
    ),
]
NAME_TO_CONFIGURATION = {i.name: i for i in CONFIGURATIONS}
