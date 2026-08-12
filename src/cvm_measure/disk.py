# Copyright 2026 Cohere, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Extract measured data from pod VM disk images.

Locates the EFI System Partition via GPT parsing and copies out the UKI
with mtools (mcopy). Supports raw disk images and .tar.gz archives.

Requires: mtools (``apt install mtools`` / ``brew install mtools``).
"""

from __future__ import annotations

import hashlib
import struct
import subprocess
import tarfile
import tempfile
from pathlib import Path

# EFI System Partition GUID in mixed-endian binary form.
ESP_GUID = bytes.fromhex("28732AC11FF8D211BA4B00A0C93EC93B")
ZERO_GUID = bytes(16)

# UEFI §5.3.2 — primary GPT header (first 92 bytes through PartitionEntryArrayCRC32).
_GPT_HEADER_LBA = 1
_SECTOR_SIZE = 512
_GPT_SIGNATURE = b"EFI PART"
_GPT_HEADER_PREFIX_LEN = 92
_GPT_OFF_HEADER_SIZE = 12
_GPT_OFF_PARTITION_ENTRY_LBA = 72
_GPT_OFF_NUM_PARTITION_ENTRIES = 80
_GPT_OFF_PARTITION_ENTRY_SIZE = 84

# UEFI §5.3.3 — partition entry layout.
_PART_OFF_TYPE_GUID = 0
_PART_OFF_STARTING_LBA = 32
_PART_MIN_LEN = _PART_OFF_STARTING_LBA + 8


def find_esp_offset(path: str | Path) -> int:
    """Return the byte offset of the ESP in a GPT disk image."""
    with open(path, "rb") as f:
        f.seek(_GPT_HEADER_LBA * _SECTOR_SIZE)
        hdr = f.read(_GPT_HEADER_PREFIX_LEN)
        if len(hdr) < _GPT_HEADER_PREFIX_LEN or hdr[: len(_GPT_SIGNATURE)] != _GPT_SIGNATURE:
            raise ValueError("Not a GPT disk")

        partition_entry_lba = struct.unpack_from("<Q", hdr, _GPT_OFF_PARTITION_ENTRY_LBA)[0]
        number_of_partition_entries = struct.unpack_from("<I", hdr, _GPT_OFF_NUM_PARTITION_ENTRIES)[0]
        size_of_partition_entry = struct.unpack_from("<I", hdr, _GPT_OFF_PARTITION_ENTRY_SIZE)[0]

        f.seek(partition_entry_lba * _SECTOR_SIZE)
        for _ in range(number_of_partition_entries):
            entry = f.read(size_of_partition_entry)
            if len(entry) < _PART_MIN_LEN:
                break
            if entry[_PART_OFF_TYPE_GUID : _PART_OFF_TYPE_GUID + 16] == ESP_GUID:
                starting_lba: int = struct.unpack_from("<Q", entry, _PART_OFF_STARTING_LBA)[0]
                return starting_lba * _SECTOR_SIZE

    raise ValueError("No EFI System Partition found")


def _read_gpt_header_and_entries(path: str | Path) -> tuple[bytes, list[bytes]]:
    """Return the GPT header and non-empty partition entries from a disk image."""
    with open(path, "rb") as f:
        f.seek(_GPT_HEADER_LBA * _SECTOR_SIZE)
        hdr_prefix = f.read(_GPT_HEADER_PREFIX_LEN)
        if len(hdr_prefix) < _GPT_HEADER_PREFIX_LEN or hdr_prefix[: len(_GPT_SIGNATURE)] != _GPT_SIGNATURE:
            raise ValueError("Not a GPT disk")

        header_size = struct.unpack_from("<I", hdr_prefix, _GPT_OFF_HEADER_SIZE)[0]
        if header_size < _GPT_HEADER_PREFIX_LEN:
            raise ValueError(f"Invalid GPT header size: {header_size}")

        # EDK2 copies sizeof(EFI_PARTITION_TABLE_HEADER) bytes, so only the first
        # 92 bytes are measured even when HeaderSize is larger.
        header = hdr_prefix

        partition_entry_lba = struct.unpack_from("<Q", hdr_prefix, _GPT_OFF_PARTITION_ENTRY_LBA)[0]
        number_of_partition_entries = struct.unpack_from("<I", hdr_prefix, _GPT_OFF_NUM_PARTITION_ENTRIES)[0]
        size_of_partition_entry = struct.unpack_from("<I", hdr_prefix, _GPT_OFF_PARTITION_ENTRY_SIZE)[0]

        f.seek(partition_entry_lba * _SECTOR_SIZE)
        entries = []
        for _ in range(number_of_partition_entries):
            entry = f.read(size_of_partition_entry)
            if len(entry) < size_of_partition_entry:
                break
            if entry[_PART_OFF_TYPE_GUID : _PART_OFF_TYPE_GUID + 16] != ZERO_GUID:
                entries.append(entry)

    return header, entries


def compute_gpt_digest(disk: str | Path) -> bytes:
    """Compute the SHA-384 digest for the UEFI EV_EFI_GPT_EVENT data.

    Mirrors Tcg2MeasureGptTable() in EDK2 DxeTpm2MeasureBootLib, which hashes
    an EFI_GPT_DATA laid out as the 92-byte EFI_PARTITION_TABLE_HEADER copied
    verbatim from LBA 1, a UINT64 count of non-empty partition entries, then
    those entries. The header's own NumberOfPartitionEntries and HeaderCRC32
    fields are measured as they appear on disk.
    """
    raw_path, cleanup = _resolve_raw_disk(Path(disk))
    try:
        header, entries = _read_gpt_header_and_entries(raw_path)
    finally:
        if cleanup is not None:
            cleanup.cleanup()

    event_data = header + struct.pack("<Q", len(entries)) + b"".join(entries)
    return hashlib.sha384(event_data).digest()


# PEP 706 added tarfile extraction filters in 3.12 and backported them to
# 3.10.12 / 3.11.4. Older 3.10 patch releases raise TypeError on filter=.
_HAS_TAR_DATA_FILTER = hasattr(tarfile, "data_filter")


def _reject_unsafe_member(member: tarfile.TarInfo) -> None:
    """Approximate the 'data' filter for interpreters that predate PEP 706."""
    if not member.isfile():
        raise ValueError(f"Refusing to extract {member.name!r}: not a regular file")
    if member.mode is not None and member.mode & 0o7000:
        raise ValueError(f"Refusing to extract {member.name!r}: setuid/setgid/sticky bit set")


def _resolve_raw_disk(disk_path: Path) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    """If disk_path is a .tar.gz, extract the raw image; otherwise return as-is."""
    suffixes = "".join(disk_path.suffixes).lower()
    if not suffixes.endswith((".tar.gz", ".tgz")):
        return disk_path, None

    tmpdir = tempfile.TemporaryDirectory()
    dest = Path(tmpdir.name)
    with tarfile.open(disk_path) as tar:
        for member in tar:
            if member.name.endswith(".raw") or member.name == "disk.raw":
                resolved = (dest / member.name).resolve()
                if not resolved.is_relative_to(dest.resolve()):
                    tmpdir.cleanup()
                    raise ValueError(f"Refusing to extract {member.name!r}: path traversal detected")
                if _HAS_TAR_DATA_FILTER:
                    tar.extract(member, path=dest, filter="data")
                else:
                    _reject_unsafe_member(member)
                    tar.extract(member, path=dest)  # nosec B202 - member vetted above
                return resolved, tmpdir

    tmpdir.cleanup()
    raise ValueError(f"No member ending in '.raw' found in {disk_path}")


def extract_uki(disk: str | Path, output: str | Path) -> bytes:
    """Extract BOOTX64.EFI from a pod VM disk image. Returns its SHA-384 digest."""
    raw_path, cleanup = _resolve_raw_disk(Path(disk))
    try:
        offset = find_esp_offset(raw_path)
        subprocess.run(
            ["mcopy", "-i", f"{raw_path}@@{offset}", "::/EFI/BOOT/BOOTX64.EFI", str(output)],
            check=True,
        )
    finally:
        if cleanup is not None:
            cleanup.cleanup()

    return hashlib.sha384(Path(output).read_bytes()).digest()
