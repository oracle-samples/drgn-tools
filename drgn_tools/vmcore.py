# Copyright (c) 2026, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Introspection of kdump-compressed vmcore files
"""
import enum
import struct
from pathlib import Path
from typing import BinaryIO
from typing import Iterator
from typing import NamedTuple
from typing import Tuple


KDUMP_SIGNATURE = b"KDUMP   "
DISKDUMP_HEADER_BLOCKS = 1


class DUMP_DH_COMPRESSED(enum.Flag):
    ZLIB = enum.auto()
    LZO = enum.auto()
    SNAPPY = enum.auto()
    INCOMPLETE = enum.auto()
    EXCLUDED_VMEMMAP = enum.auto()
    ZSTD = enum.auto()


class DumpLevel(enum.Flag):
    EXCLUDE_ZERO = enum.auto()
    EXCLUDE_CACHE = enum.auto()
    EXCLUDE_PRIVATE_CACHE = enum.auto()
    EXCLUDE_USER = enum.auto()
    EXCLUDE_FREE = enum.auto()


class Layout(NamedTuple):
    name: str
    disk_dump_header: struct.Struct
    kdump_sub_header: struct.Struct
    page_desc: struct.Struct


class DiskDumpHeader(NamedTuple):
    signature: bytes
    header_version: int
    status: int
    block_size: int
    sub_hdr_size: int
    bitmap_blocks: int
    max_mapnr: int
    total_ram_blocks: int
    device_blocks: int
    written_blocks: int
    current_cpu: int
    nr_cpus: int


class KdumpSubHeader(NamedTuple):
    phys_base: int
    dump_level: int
    split: int
    start_pfn: int
    end_pfn: int
    offset_vmcoreinfo: int
    size_vmcoreinfo: int
    offset_note: int
    size_note: int
    offset_eraseinfo: int
    size_eraseinfo: int
    start_pfn_64: int
    end_pfn_64: int
    max_mapnr_64: int


class PageDesc(NamedTuple):
    offset: int
    size: int
    flags: int
    page_flags: int


LAYOUTS = (
    Layout(
        "64-bit little-endian",
        struct.Struct("<8si390s6xqqIiiIIIIIIi"),
        struct.Struct("<QiiQQqQqQqQQQQ"),
        struct.Struct("<qIIQ"),
    ),
    Layout(
        "64-bit big-endian",
        struct.Struct(">8si390s6xqqIiiIIIIIIi"),
        struct.Struct(">QiiQQqQqQqQQQQ"),
        struct.Struct(">qIIQ"),
    ),
    Layout(
        "32-bit little-endian",
        struct.Struct("<8si390s2xllIiiIIIIIIi"),
        struct.Struct("<IiiIIqIqIqIQQQ"),
        struct.Struct("<qIIQ"),
    ),
    Layout(
        "32-bit big-endian",
        struct.Struct(">8si390s2xllIiiIIIIIIi"),
        struct.Struct(">IiiIIqIqIqIQQQ"),
        struct.Struct(">qIIQ"),
    ),
)


def read_at(f: BinaryIO, offset: int, size: int) -> bytes:
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise ValueError(
            f"short read at offset 0x{offset:x}: wanted {size}, got {len(data)}"
        )
    return data


def parse_disk_dump_header(layout: Layout, data: bytes) -> DiskDumpHeader:
    fields = layout.disk_dump_header.unpack(data)
    (
        signature,
        header_version,
        _utsname,
        _tv_sec,
        _tv_usec,
        status,
        block_size,
        sub_hdr_size,
        bitmap_blocks,
        max_mapnr,
        total_ram_blocks,
        device_blocks,
        written_blocks,
        current_cpu,
        nr_cpus,
    ) = fields
    return DiskDumpHeader(
        signature=signature,
        header_version=header_version,
        status=status,
        block_size=block_size,
        sub_hdr_size=sub_hdr_size,
        bitmap_blocks=bitmap_blocks,
        max_mapnr=max_mapnr,
        total_ram_blocks=total_ram_blocks,
        device_blocks=device_blocks,
        written_blocks=written_blocks,
        current_cpu=current_cpu,
        nr_cpus=nr_cpus,
    )


def parse_kdump_sub_header(layout: Layout, data: bytes) -> KdumpSubHeader:
    return KdumpSubHeader(*layout.kdump_sub_header.unpack(data))


def is_power_of_two(value: int) -> bool:
    return value > 0 and (value & (value - 1)) == 0


def is_plausible_header(
    header: DiskDumpHeader, file_size: int, sub_header_size: int
) -> bool:
    if header.signature != KDUMP_SIGNATURE:
        return False
    if not (1 <= header.header_version <= 64):
        return False
    if not (512 <= header.block_size <= 1024 * 1024 * 1024):
        return False
    if not is_power_of_two(header.block_size):
        return False
    if header.block_size > file_size:
        return False
    if not (1 <= header.sub_hdr_size <= 1024 * 1024):
        return False
    if header.sub_hdr_size * header.block_size < sub_header_size:
        return False
    if header.bitmap_blocks < 0:
        return False
    page_desc_offset = (
        DISKDUMP_HEADER_BLOCKS + header.sub_hdr_size + header.bitmap_blocks
    ) * header.block_size
    return page_desc_offset <= file_size


def detect_layout(
    f: BinaryIO, file_size: int
) -> Tuple[Layout, DiskDumpHeader, KdumpSubHeader]:
    first_read = max(layout.disk_dump_header.size for layout in LAYOUTS)
    data = read_at(f, 0, first_read)

    for layout in LAYOUTS:
        header = parse_disk_dump_header(
            layout, data[: layout.disk_dump_header.size]
        )
        if is_plausible_header(
            header, file_size, layout.kdump_sub_header.size
        ):
            sub_data = read_at(
                f, header.block_size, layout.kdump_sub_header.size
            )
            sub_header = parse_kdump_sub_header(layout, sub_data)
            return layout, header, sub_header

    signature = data[: len(KDUMP_SIGNATURE)]
    if signature != KDUMP_SIGNATURE:
        raise ValueError(
            f"not a kdump-compressed dump: signature is {signature!r}"
        )
    raise ValueError(
        "KDUMP signature found, but no supported header layout matched"
    )


class Dump:
    path: Path
    file: BinaryIO
    layout: Layout
    header: DiskDumpHeader
    subheader: KdumpSubHeader

    # max_mapnr has a 32 and 64-bit version. Prefer the newer 64-bit one.
    _max_mapnr: int

    # File offsets determined from the header
    _offset_bitmap1: int
    _offset_bitmap2: int
    _offset_page_desc: int

    def __init__(self, path: Path) -> None:
        self.path = path
        self.file = self.path.open("rb")
        self.layout, self.header, self.subheader = detect_layout(
            self.file,
            self.path.stat().st_size,
        )
        self._max_mapnr = self.subheader.max_mapnr_64 or self.header.max_mapnr
        self._offset_bitmap1 = self.header.block_size * (
            DISKDUMP_HEADER_BLOCKS + self.header.sub_hdr_size
        )
        self._offset_bitmap2 = (
            self._offset_bitmap1
            + (self.header.bitmap_blocks * self.header.block_size) // 2
        )
        self._offset_page_desc = (
            self._offset_bitmap1
            + self.header.bitmap_blocks * self.header.block_size
        )

    def iter_included_pfns(self) -> Iterator[int]:
        """
        Iterate over bitmap 2, yielding PFNs of included pages.
        """
        index = 0
        offset = self._offset_bitmap2
        size = (self.header.bitmap_blocks * self.header.block_size) // 2
        while index < size:
            chunk = read_at(
                self.file, offset + index, min(65536, size - index)
            )
            for i, value in enumerate(chunk):
                if value:
                    for bit in range(8):
                        if value & (1 << bit):
                            pfn = (index + i) * 8 + bit
                            yield pfn
            index += len(chunk)

    def iter_pages(self) -> Iterator[Tuple[int, PageDesc]]:
        """
        Yield PFNs of included pages and their corresponding page descs.
        """
        # Page descriptors are not indexed by PFN, but by their logical index
        # based on their presence in the file. Suppose the following PFNs are
        # included in the file: [0, 3, 5, 7]. Then the page descriptor of PFN 3
        # could be found at index 1 in the second array, because it is the
        # second included page.
        #
        # We read chunks at a time. pd_start is the beginning index of the
        # chunk, and pd_cache is the size (in descriptors) of each chunk.
        pd_start = 0
        pd_cache = 4096
        pd_chunk = None
        pd_offset = self._offset_page_desc
        for index, pfn in enumerate(self.iter_included_pfns()):
            if not (pd_start <= index < pd_start + pd_cache) or not pd_chunk:
                pd_start = (index // pd_cache) * pd_cache
                pd_chunk = read_at(
                    self.file,
                    pd_offset + pd_start * self.layout.page_desc.size,
                    pd_cache * self.layout.page_desc.size,
                )
            byte_offset = (index - pd_start) * self.layout.page_desc.size
            data = pd_chunk[
                byte_offset : byte_offset + self.layout.page_desc.size
            ]
            desc = PageDesc(*self.layout.page_desc.unpack(data))
            yield pfn, desc

    def get_compression(self) -> DUMP_DH_COMPRESSED:
        """
        Return the first compression flags observed on dumped page

        The kdump-compressed format does not enumerate the compression methods
        used anywhere in its header. Instead, you're left to discover it on each
        page descriptor. This means that it's possible for any page to be
        compressed in any way. In practice, makedumpfile will only use one
        compression flag, but you still need to iterate over a small sample of
        pages: some pages are not compressed (because compression did not save
        space).
        """
        for i, (pfn, desc) in enumerate(self.iter_pages()):
            if desc.flags:
                return DUMP_DH_COMPRESSED(desc.flags)
            if i >= 5000:
                break
        return DUMP_DH_COMPRESSED(0)
