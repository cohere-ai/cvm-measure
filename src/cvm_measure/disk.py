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
import zlib
from pathlib import Path
from typing import IO

# EFI System Partition GUID in mixed-endian binary form.
ESP_GUID = bytes.fromhex("28732AC11FF8D211BA4B00A0C93EC93B")
ZERO_GUID = bytes(16)

# Upper bound on what we will unpack from a .tar.gz, so a small archive cannot
# fill the temporary filesystem. Pod VM images are a few GiB.
DEFAULT_MAX_EXTRACT_BYTES = 32 * 1024**3
_COPY_CHUNK_BYTES = 1024 * 1024

# UEFI §5.3.2 — primary GPT header (first 92 bytes through PartitionEntryArrayCRC32).
_GPT_HEADER_LBA = 1
_SECTOR_SIZE = 512
_GPT_SIGNATURE = b"EFI PART"
_GPT_HEADER_PREFIX_LEN = 92
_GPT_OFF_HEADER_SIZE = 12
_GPT_OFF_HEADER_CRC32 = 16
_GPT_OFF_PARTITION_ENTRY_LBA = 72
_GPT_OFF_NUM_PARTITION_ENTRIES = 80
_GPT_OFF_PARTITION_ENTRY_SIZE = 84
_GPT_OFF_ENTRY_ARRAY_CRC32 = 88

# UEFI §5.3.3 — SizeOfPartitionEntry must be 128 * 2**n.
_GPT_MIN_ENTRY_SIZE = 128
# The spec reserves 16 KiB for the entry array; allow generous headroom but
# refuse a header that would have us read an unbounded amount of the image.
_GPT_MAX_ENTRY_ARRAY_BYTES = 1 << 20

_PART_OFF_TYPE_GUID = 0
_PART_OFF_STARTING_LBA = 32


def _validate_gpt_header(header: bytes) -> tuple[int, int, int]:
    """Validate a primary GPT header, returning (entry_lba, count, entry_size).

    EDK2 measures the table it actually parsed, and PartitionValidGptTable()
    checks both CRCs before doing so (see CVE-2024-13745). We apply the same
    checks and fail closed rather than measuring a table firmware would have
    rejected.
    """
    if len(header) < _GPT_HEADER_PREFIX_LEN or header[: len(_GPT_SIGNATURE)] != _GPT_SIGNATURE:
        raise ValueError("Not a GPT disk")

    header_size: int = struct.unpack_from("<I", header, _GPT_OFF_HEADER_SIZE)[0]
    if not _GPT_HEADER_PREFIX_LEN <= header_size <= len(header):
        raise ValueError(f"Invalid GPT header size: {header_size}")

    stored_crc: int = struct.unpack_from("<I", header, _GPT_OFF_HEADER_CRC32)[0]
    zeroed = bytearray(header[:header_size])
    struct.pack_into("<I", zeroed, _GPT_OFF_HEADER_CRC32, 0)
    actual_crc = zlib.crc32(zeroed)
    if actual_crc != stored_crc:
        raise ValueError(
            f"GPT header CRC32 mismatch: header records 0x{stored_crc:08x}, "
            f"computed 0x{actual_crc:08x}"
        )

    entry_lba: int = struct.unpack_from("<Q", header, _GPT_OFF_PARTITION_ENTRY_LBA)[0]
    count: int = struct.unpack_from("<I", header, _GPT_OFF_NUM_PARTITION_ENTRIES)[0]
    entry_size: int = struct.unpack_from("<I", header, _GPT_OFF_PARTITION_ENTRY_SIZE)[0]

    if entry_size < _GPT_MIN_ENTRY_SIZE or entry_size % _GPT_MIN_ENTRY_SIZE != 0:
        raise ValueError(f"Invalid GPT partition entry size: {entry_size}")
    multiple = entry_size // _GPT_MIN_ENTRY_SIZE
    if multiple & (multiple - 1):
        raise ValueError(
            f"GPT partition entry size must be 128 * 2**n, got {entry_size}"
        )
    if count == 0:
        raise ValueError("GPT header declares zero partition entries")
    if count * entry_size > _GPT_MAX_ENTRY_ARRAY_BYTES:
        raise ValueError(
            f"GPT partition entry array is implausibly large: {count} entries of "
            f"{entry_size} bytes exceeds {_GPT_MAX_ENTRY_ARRAY_BYTES} bytes"
        )
    if entry_lba == 0:
        raise ValueError("GPT header points its partition entry array at LBA 0")

    return entry_lba, count, entry_size


def _read_gpt(path: str | Path) -> tuple[bytes, list[bytes]]:
    """Return the measured GPT header and the non-empty partition entries.

    The header is the fixed 92-byte EFI_PARTITION_TABLE_HEADER that EDK2
    copies into EFI_GPT_DATA, regardless of the on-disk HeaderSize.
    """
    with open(path, "rb") as f:
        f.seek(_GPT_HEADER_LBA * _SECTOR_SIZE)
        header = f.read(_SECTOR_SIZE)
        entry_lba, count, entry_size = _validate_gpt_header(header)

        array_len = count * entry_size
        f.seek(entry_lba * _SECTOR_SIZE)
        array = f.read(array_len)
        if len(array) != array_len:
            raise ValueError(
                f"Truncated GPT partition entry array: expected {array_len} bytes, "
                f"read {len(array)}"
            )

    stored_crc: int = struct.unpack_from("<I", header, _GPT_OFF_ENTRY_ARRAY_CRC32)[0]
    actual_crc = zlib.crc32(array)
    if actual_crc != stored_crc:
        raise ValueError(
            f"GPT partition entry array CRC32 mismatch: header records "
            f"0x{stored_crc:08x}, computed 0x{actual_crc:08x}"
        )

    entries = [
        entry
        for offset in range(0, array_len, entry_size)
        if (entry := array[offset : offset + entry_size])[
            _PART_OFF_TYPE_GUID : _PART_OFF_TYPE_GUID + 16
        ]
        != ZERO_GUID
    ]
    return header[:_GPT_HEADER_PREFIX_LEN], entries


def find_esp_offset(path: str | Path) -> int:
    """Return the byte offset of the ESP in a GPT disk image."""
    _, entries = _read_gpt(path)
    for entry in entries:
        if entry[_PART_OFF_TYPE_GUID : _PART_OFF_TYPE_GUID + 16] == ESP_GUID:
            starting_lba: int = struct.unpack_from("<Q", entry, _PART_OFF_STARTING_LBA)[0]
            return starting_lba * _SECTOR_SIZE

    raise ValueError("No EFI System Partition found")


def gpt_event_data(
    disk: str | Path,
    max_extract_bytes: int = DEFAULT_MAX_EXTRACT_BYTES,
) -> bytes:
    """Build the UEFI EV_EFI_GPT_EVENT data for a disk image.

    Mirrors Tcg2MeasureGptTable() in EDK2 DxeTpm2MeasureBootLib, which hashes
    an EFI_GPT_DATA laid out as the 92-byte EFI_PARTITION_TABLE_HEADER copied
    verbatim from LBA 1, a UINT64 count of non-empty partition entries, then
    those entries. The header's own NumberOfPartitionEntries and HeaderCRC32
    fields are measured as they appear on disk.

    Returned unhashed because platforms disagree only about the hash: TDX
    folds this into RTMR[1] with SHA-384, the vTPM into PCR 5 with SHA-256.
    """
    raw_path, cleanup = _resolve_raw_disk(Path(disk), max_extract_bytes)
    try:
        header, entries = _read_gpt(raw_path)
    finally:
        if cleanup is not None:
            cleanup.cleanup()

    return header + struct.pack("<Q", len(entries)) + b"".join(entries)


def compute_gpt_digest(
    disk: str | Path,
    max_extract_bytes: int = DEFAULT_MAX_EXTRACT_BYTES,
) -> bytes:
    """Compute the SHA-384 digest for the UEFI EV_EFI_GPT_EVENT data."""
    return hashlib.sha384(gpt_event_data(disk, max_extract_bytes)).digest()


def _copy_bounded(source: IO[bytes], dest: IO[bytes], limit: int, name: str) -> None:
    """Copy source to dest, refusing to write more than limit bytes.

    A tar header can understate a member's real size, so the running total is
    what stops us rather than the declared size.
    """
    remaining = limit
    while chunk := source.read(_COPY_CHUNK_BYTES):
        remaining -= len(chunk)
        if remaining < 0:
            raise ValueError(
                f"Refusing to extract {name!r}: exceeds the {limit} byte extraction "
                "limit (raise max_extract_bytes if this image is legitimately larger)"
            )
        dest.write(chunk)


def _resolve_raw_disk(
    disk_path: Path,
    max_extract_bytes: int = DEFAULT_MAX_EXTRACT_BYTES,
) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    """If disk_path is a .tar.gz, extract the raw image; otherwise return as-is.

    The member is copied out by hand rather than through TarFile.extract, so
    the only path ever written is the validated one. That keeps a hostile
    archive from escaping the temporary directory via traversal, symlinks or
    device nodes, and avoids TarFile.extract's filter= argument, which older
    3.10 interpreters predate.
    """
    suffixes = "".join(disk_path.suffixes).lower()
    if not suffixes.endswith((".tar.gz", ".tgz")):
        return disk_path, None

    tmpdir = tempfile.TemporaryDirectory()
    dest = Path(tmpdir.name).resolve()
    try:
        with tarfile.open(disk_path) as tar:
            candidates = [m for m in tar.getmembers() if m.name.endswith(".raw")]
            if not candidates:
                raise ValueError(f"No member ending in '.raw' found in {disk_path}")
            # Picking the first of several would make the result depend on
            # archive ordering, so require the choice to be unambiguous.
            if len(candidates) > 1:
                names = ", ".join(sorted(m.name for m in candidates))
                raise ValueError(
                    f"{disk_path} contains {len(candidates)} '.raw' members ({names}); "
                    "expected exactly one"
                )

            member = candidates[0]
            if not member.isfile():
                raise ValueError(
                    f"Refusing to extract {member.name!r}: not a regular file"
                )
            if member.size > max_extract_bytes:
                raise ValueError(
                    f"Refusing to extract {member.name!r}: declares {member.size} bytes, "
                    f"over the {max_extract_bytes} byte extraction limit"
                )

            resolved = (dest / member.name).resolve()
            if not resolved.is_relative_to(dest):
                raise ValueError(
                    f"Refusing to extract {member.name!r}: path traversal detected"
                )

            source = tar.extractfile(member)
            if source is None:
                raise ValueError(f"Cannot read {member.name!r} from {disk_path}")

            resolved.parent.mkdir(parents=True, exist_ok=True)
            with source, open(resolved, "wb") as out:
                _copy_bounded(source, out, max_extract_bytes, member.name)
            return resolved, tmpdir
    except Exception:
        tmpdir.cleanup()
        raise


def extract_uki(
    disk: str | Path,
    output: str | Path,
    max_extract_bytes: int = DEFAULT_MAX_EXTRACT_BYTES,
) -> bytes:
    """Extract BOOTX64.EFI from a pod VM disk image. Returns its SHA-384 digest."""
    raw_path, cleanup = _resolve_raw_disk(Path(disk), max_extract_bytes)
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
