# Copyright (c) 2024-2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Describes the "heavy" images used for running tests
"""
import dataclasses
from typing import List


DEFAULT_UEK = {
    10: 8,
    9: 8,
    8: 7,
    7: 6,
}


@dataclasses.dataclass
class ImageInfo:
    ol: int
    uek: int
    arch: str
    image_url: str
    rpms: List[str]

    @property
    def name(self) -> str:
        return f"ol{self.ol}-uek{self.uek}-{self.arch}"

    def is_default_uek(self) -> bool:
        return self.uek == DEFAULT_UEK[self.ol]

    def default_uek(self) -> int:
        return DEFAULT_UEK[self.ol]

    @property
    def disk_name(self) -> str:
        return f"{self.name}.qcow2"

    @property
    def base_image_name(self) -> str:
        return self.image_url.split("/")[-1]


IMAGES = {
    "ol10": "https://yum.oracle.com/templates/OracleLinux/OL10/u1/x86_64/OL10U1_x86_64-kvm-b270.qcow2",
    "ol9": "https://yum.oracle.com/templates/OracleLinux/OL9/u7/x86_64/OL9U7_x86_64-kvm-b269.qcow2",
    "ol8": "https://yum.oracle.com/templates/OracleLinux/OL8/u10/x86_64/OL8U10_x86_64-kvm-b271.qcow2",
    "ol7": "https://yum.oracle.com/templates/OracleLinux/OL7/u9/x86_64/OL7U9_x86_64-kvm-b257.qcow2",
}

CONFIGURATIONS = [
    ImageInfo(10, 8, "x86_64", IMAGES["ol10"], []),
    ImageInfo(9, 8, "x86_64", IMAGES["ol9"], []),
    ImageInfo(9, 7, "x86_64", IMAGES["ol9"], []),
    ImageInfo(8, 7, "x86_64", IMAGES["ol8"], []),
    ImageInfo(8, 6, "x86_64", IMAGES["ol8"], []),
    ImageInfo(
        7, 6, "x86_64", IMAGES["ol7"], ["drgn-0.0.32-1.0.1.el7.x86_64.rpm"]
    ),
    ImageInfo(
        7, 5, "x86_64", IMAGES["ol7"], ["drgn-0.0.32-1.0.1.el7.x86_64.rpm"]
    ),
    ImageInfo(
        7, 4, "x86_64", IMAGES["ol7"], ["drgn-0.0.32-1.0.1.el7.x86_64.rpm"]
    ),
]
NAME_TO_CONFIGURATION = {i.name: i for i in CONFIGURATIONS}
