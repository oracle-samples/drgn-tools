# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Describes the "heavy" images used for running tests
"""
import dataclasses


@dataclasses.dataclass
class ImageInfo:
    ol: int
    ol_update: int
    uek: int
    arch: str
    iso_url: str

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
        2,
        7,
        "x86_64",
        "https://yum.oracle.com/ISOS/OracleLinux/OL9/u1/x86_64/OracleLinux-R9-U1-x86_64-boot-uek.iso",  # noqa
    ),
    # OL8: UEK 6-7
    ImageInfo(
        8,
        8,
        7,
        "x86_64",
        "https://yum.oracle.com/ISOS/OracleLinux/OL8/u7/x86_64/x86_64-boot-uek.iso",  # noqa
    ),
    ImageInfo(
        8,
        8,
        6,
        "x86_64",
        "https://yum.oracle.com/ISOS/OracleLinux/OL8/u7/x86_64/x86_64-boot-uek.iso",  # noqa
    ),
    # OL7: UEK 4-6
    ImageInfo(
        7,
        9,
        6,
        "x86_64",
        "https://yum.oracle.com/ISOS/OracleLinux/OL7/u9/x86_64/x86_64-boot-uek.iso",  # noqa
    ),
    ImageInfo(
        7,
        9,
        5,
        "x86_64",
        "https://yum.oracle.com/ISOS/OracleLinux/OL7/u9/x86_64/x86_64-boot-uek.iso",  # noqa
    ),
    ImageInfo(
        7,
        9,
        4,
        "x86_64",
        "https://yum.oracle.com/ISOS/OracleLinux/OL7/u9/x86_64/x86_64-boot-uek.iso",  # noqa
    ),
]
NAME_TO_CONFIGURATION = {i.name: i for i in CONFIGURATIONS}
