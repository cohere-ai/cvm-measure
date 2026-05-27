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


def find_esp_offset(path: str | Path) -> int:
    """Return the byte offset of the ESP in a GPT disk image."""
    with open(path, "rb") as f:
        f.seek(512)
        hdr = f.read(92)
        if len(hdr) < 92 or hdr[:8] != b"EFI PART":
            raise ValueError("Not a GPT disk")

        f.seek(struct.unpack_from("<Q", hdr, 72)[0] * 512)
        for _ in range(struct.unpack_from("<I", hdr, 80)[0]):
            entry = f.read(struct.unpack_from("<I", hdr, 84)[0])
            if len(entry) < 48:
                break
            if entry[:16] == ESP_GUID:
                return struct.unpack_from("<Q", entry, 32)[0] * 512

    raise ValueError("No EFI System Partition found")


def _read_gpt_header_and_entries(path: str | Path) -> tuple[bytes, list[bytes]]:
    """Return the GPT header and non-empty partition entries from a disk image."""
    with open(path, "rb") as f:
        f.seek(512)
        hdr_prefix = f.read(92)
        if len(hdr_prefix) < 92 or hdr_prefix[:8] != b"EFI PART":
            raise ValueError("Not a GPT disk")

        header_size = struct.unpack_from("<I", hdr_prefix, 12)[0]
        if header_size < 92:
            raise ValueError(f"Invalid GPT header size: {header_size}")

        f.seek(512)
        header = f.read(header_size)
        if len(header) != header_size:
            raise ValueError("Truncated GPT header")

        partition_entry_lba = struct.unpack_from("<Q", hdr_prefix, 72)[0]
        number_of_partition_entries = struct.unpack_from("<I", hdr_prefix, 80)[0]
        size_of_partition_entry = struct.unpack_from("<I", hdr_prefix, 84)[0]

        f.seek(partition_entry_lba * 512)
        entries = []
        for _ in range(number_of_partition_entries):
            entry = f.read(size_of_partition_entry)
            if len(entry) < size_of_partition_entry:
                break
            if entry[:16] != ZERO_GUID:
                entries.append(entry)

    return header, entries


def compute_gpt_digest(disk: str | Path) -> bytes:
    """Compute the SHA-384 digest for the UEFI EV_EFI_GPT_EVENT data.

    EDK2 measures EFI_GPT_DATA, which is the GPT header, a UINTN count of
    non-empty partition entries, and then those partition entries.
    """
    raw_path, cleanup = _resolve_raw_disk(Path(disk))
    try:
        header, entries = _read_gpt_header_and_entries(raw_path)
    finally:
        if cleanup is not None:
            cleanup.cleanup()

    event_data = header + struct.pack("<Q", len(entries)) + b"".join(entries)
    return hashlib.sha384(event_data).digest()


def _resolve_raw_disk(disk_path: Path) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    """If disk_path is a .tar.gz, extract the raw image; otherwise return as-is."""
    suffixes = "".join(disk_path.suffixes).lower()
    if not (suffixes.endswith(".tar.gz") or suffixes.endswith(".tgz")):
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
                tar.extract(member, path=dest, filter="data")
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
