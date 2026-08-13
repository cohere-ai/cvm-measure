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

from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
import tarfile
import tempfile
import zlib
from pathlib import Path

import pytest

from cvm_measure.disk import (
    ESP_GUID,
    compute_gpt_digest,
    extract_uki,
    find_esp_offset,
)

HAS_MTOOLS = shutil.which("mcopy") is not None and shutil.which("mkfs.fat") is not None


SECTOR = 512
ENTRY_LBA = 2


def _build_measurable_gpt_disk(
    *,
    esp_data: bytes = b"",
    esp_lba: int = 2048,
    header_size: int = 92,
    tail: bytes = b"",
    num_entries: int = 4,
    non_empty: int = 2,
    entry_size: int = 128,
    entry_array_len: int | None = None,
) -> tuple[bytes, bytes, list[bytes]]:
    """Build a spec-valid GPT disk plus the header and entries EDK2 measures.

    Both CRCs are computed for real, since the parser verifies them the way
    EDK2's PartitionValidGptTable() does.
    """
    array_len = num_entries * entry_size
    esp_sectors = max(1, -(-len(esp_data) // SECTOR))
    total_sectors = esp_lba + esp_sectors + 1

    array = bytearray(array_len)
    measured_entries = []
    for i in range(non_empty):
        entry = bytearray(entry_size)
        if i == 0:
            entry[:16] = ESP_GUID
            struct.pack_into("<Q", entry, 32, esp_lba)
            struct.pack_into("<Q", entry, 40, esp_lba + esp_sectors - 1)
        else:
            entry[:16] = bytes([i + 1] * 16)
            struct.pack_into("<Q", entry, 32, esp_lba + esp_sectors + i)
        array[i * entry_size : (i + 1) * entry_size] = entry
        measured_entries.append(bytes(entry))

    hdr = bytearray(SECTOR)
    hdr[:8] = b"EFI PART"
    struct.pack_into("<I", hdr, 8, 0x00010000)          # Revision
    struct.pack_into("<I", hdr, 12, header_size)
    struct.pack_into("<Q", hdr, 24, 1)                  # MyLBA
    struct.pack_into("<Q", hdr, 32, total_sectors - 1)  # AlternateLBA
    struct.pack_into("<Q", hdr, 72, ENTRY_LBA)
    struct.pack_into("<I", hdr, 80, num_entries)
    struct.pack_into("<I", hdr, 84, entry_size)
    struct.pack_into("<I", hdr, 88, zlib.crc32(bytes(array)))
    hdr[92 : 92 + len(tail)] = tail
    # HeaderCRC32 covers HeaderSize bytes with the field itself zeroed, so it
    # has to be written last.
    struct.pack_into("<I", hdr, 16, zlib.crc32(bytes(hdr[:header_size])))

    disk = bytearray(total_sectors * SECTOR)
    disk[SECTOR : 2 * SECTOR] = hdr
    written = array_len if entry_array_len is None else entry_array_len
    disk[ENTRY_LBA * SECTOR : ENTRY_LBA * SECTOR + written] = array[:written]
    disk[esp_lba * SECTOR : esp_lba * SECTOR + len(esp_data)] = esp_data

    return bytes(disk), bytes(hdr[:92]), measured_entries


def _build_gpt_disk(esp_data: bytes, esp_lba: int = 2048) -> bytes:
    """A spec-valid GPT disk whose first partition is the ESP."""
    disk, _, _ = _build_measurable_gpt_disk(
        esp_data=esp_data, esp_lba=esp_lba, num_entries=4, non_empty=1
    )
    return disk


def _patch(disk: bytes, offset: int, value: bytes) -> bytes:
    patched = bytearray(disk)
    patched[offset : offset + len(value)] = value
    return bytes(patched)


def _patch_header_field(disk: bytes, offset: int, value: bytes) -> bytes:
    """Patch a GPT header field and refresh HeaderCRC32.

    Without refreshing, the CRC check fires first and hides whatever field
    validation the test is actually about.
    """
    patched = bytearray(_patch(disk, SECTOR + offset, value))
    header_size = struct.unpack_from("<I", patched, SECTOR + 12)[0]
    struct.pack_into("<I", patched, SECTOR + 16, 0)
    crc = zlib.crc32(bytes(patched[SECTOR : SECTOR + header_size]))
    struct.pack_into("<I", patched, SECTOR + 16, crc)
    return bytes(patched)


class TestComputeGptDigest:
    def _digest(self, disk: bytes) -> bytes:
        with tempfile.NamedTemporaryFile(suffix=".raw") as f:
            f.write(disk)
            f.flush()
            return compute_gpt_digest(f.name)

    def _expected(self, header: bytes, entries: list[bytes]) -> bytes:
        return hashlib.sha384(
            header + struct.pack("<Q", len(entries)) + b"".join(entries)
        ).digest()

    def test_matches_edk2_gpt_data_layout(self):
        disk, header, entries = _build_measurable_gpt_disk()
        assert self._digest(disk) == self._expected(header, entries)

    def test_measures_only_92_header_bytes(self):
        """EDK2 copies a fixed-size struct, so a larger HeaderSize adds nothing."""
        disk, header, entries = _build_measurable_gpt_disk(
            header_size=96, tail=b"\xa5" * 4
        )
        assert len(header) == 92
        assert self._digest(disk) == self._expected(header, entries)

    def test_skips_empty_partition_entries(self):
        disk, header, entries = _build_measurable_gpt_disk(num_entries=8, non_empty=3)
        assert len(entries) == 3
        assert self._digest(disk) == self._expected(header, entries)

    def test_larger_entry_size_is_accepted(self):
        disk, header, entries = _build_measurable_gpt_disk(entry_size=256)
        assert self._digest(disk) == self._expected(header, entries)

    def test_tar_gz_disk(self):
        disk, header, entries = _build_measurable_gpt_disk()
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            raw = tmp / "disk.raw"
            raw.write_bytes(disk)
            archive = tmp / "disk.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(raw, arcname="disk.raw")

            assert compute_gpt_digest(archive) == self._expected(header, entries)


class TestGptValidation:
    """A pod VM image is untrusted, so the table is validated before use."""

    def _digest(self, disk: bytes):
        with tempfile.NamedTemporaryFile(suffix=".raw") as f:
            f.write(disk)
            f.flush()
            return compute_gpt_digest(f.name)

    def test_rejects_zero_entry_size(self):
        """A zero entry size with a huge count would otherwise loop forever."""
        disk, _, _ = _build_measurable_gpt_disk()
        disk = _patch_header_field(disk, 84, struct.pack("<I", 0))
        disk = _patch_header_field(disk, 80, struct.pack("<I", 0xFFFFFFFF))
        with pytest.raises(ValueError, match="entry size"):
            self._digest(disk)

    def test_rejects_non_power_of_two_entry_size(self):
        disk, _, _ = _build_measurable_gpt_disk()
        disk = _patch_header_field(disk, 84, struct.pack("<I", 384))
        with pytest.raises(ValueError, match=r"128 \* 2"):
            self._digest(disk)

    def test_rejects_implausible_entry_count(self):
        disk, _, _ = _build_measurable_gpt_disk()
        disk = _patch_header_field(disk, 80, struct.pack("<I", 0xFFFFFF))
        with pytest.raises(ValueError, match="implausibly large"):
            self._digest(disk)

    def test_rejects_zero_entry_count(self):
        disk, _, _ = _build_measurable_gpt_disk()
        disk = _patch_header_field(disk, 80, struct.pack("<I", 0))
        with pytest.raises(ValueError, match="zero partition entries"):
            self._digest(disk)

    def test_rejects_entry_array_at_lba_zero(self):
        disk, _, _ = _build_measurable_gpt_disk()
        disk = _patch_header_field(disk, 72, struct.pack("<Q", 0))
        with pytest.raises(ValueError, match="LBA 0"):
            self._digest(disk)

    def test_rejects_bad_header_crc(self):
        disk, _, _ = _build_measurable_gpt_disk()
        disk = _patch(disk, SECTOR + 16, struct.pack("<I", 0xDEADBEEF))
        with pytest.raises(ValueError, match="header CRC32 mismatch"):
            self._digest(disk)

    def test_rejects_bad_entry_array_crc(self):
        disk, _, _ = _build_measurable_gpt_disk()
        # Flip a byte in the first partition entry, leaving the stored CRC stale.
        disk = _patch(disk, ENTRY_LBA * SECTOR + 60, b"\xff")
        with pytest.raises(ValueError, match="entry array CRC32 mismatch"):
            self._digest(disk)

    def test_rejects_truncated_entry_array(self):
        disk, _, _ = _build_measurable_gpt_disk()
        with pytest.raises(ValueError, match="Truncated GPT partition entry array"):
            self._digest(disk[: ENTRY_LBA * SECTOR + 64])


class TestTarExtraction:
    """A pod VM archive is untrusted input; it must not write outside tmpdir."""

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            payload = tmp / "payload"
            payload.write_bytes(b"pwned")

            archive = tmp / "evil.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(payload, arcname="../escaped.raw")

            with pytest.raises(ValueError, match="path traversal"):
                compute_gpt_digest(archive)

    def test_rejects_symlink_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            archive = tmp / "evil.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                link = tarfile.TarInfo("disk.raw")
                link.type = tarfile.SYMTYPE
                link.linkname = "/etc/passwd"
                tar.addfile(link)

            with pytest.raises(ValueError, match="not a regular file"):
                compute_gpt_digest(archive)

    def test_rejects_archive_without_raw_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            dummy = tmp / "readme.txt"
            dummy.write_text("not a disk")

            archive = tmp / "archive.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(dummy, arcname="readme.txt")

            with pytest.raises(ValueError, match="No member ending in '.raw'"):
                compute_gpt_digest(archive)

    def test_rejects_multiple_raw_members(self):
        """Picking the first would make the digest depend on archive ordering."""
        disk, _, _ = _build_measurable_gpt_disk()
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            raw = tmp / "disk.raw"
            raw.write_bytes(disk)

            archive = tmp / "disk.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(raw, arcname="disk.raw")
                tar.add(raw, arcname="other.raw")

            with pytest.raises(ValueError, match="expected exactly one"):
                compute_gpt_digest(archive)

    def test_enforces_extraction_limit(self):
        disk, _, _ = _build_measurable_gpt_disk()
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            raw = tmp / "disk.raw"
            raw.write_bytes(disk)

            archive = tmp / "disk.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(raw, arcname="disk.raw")

            with pytest.raises(ValueError, match="extraction limit"):
                compute_gpt_digest(archive, max_extract_bytes=len(disk) - 1)

    def test_extraction_limit_allows_exact_size(self):
        disk, header, entries = _build_measurable_gpt_disk()
        expected = hashlib.sha384(
            header + struct.pack("<Q", len(entries)) + b"".join(entries)
        ).digest()
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            raw = tmp / "disk.raw"
            raw.write_bytes(disk)

            archive = tmp / "disk.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(raw, arcname="disk.raw")

            assert compute_gpt_digest(archive, max_extract_bytes=len(disk)) == expected


class TestFindEspOffset:
    def test_standard_lba(self):
        disk = _build_gpt_disk(bytes(4096 * 512), esp_lba=2048)
        with tempfile.NamedTemporaryFile(suffix=".raw") as f:
            f.write(disk)
            f.flush()
            assert find_esp_offset(f.name) == 2048 * 512

    def test_non_standard_lba(self):
        disk = _build_gpt_disk(bytes(1024 * 512), esp_lba=4096)
        with tempfile.NamedTemporaryFile(suffix=".raw") as f:
            f.write(disk)
            f.flush()
            assert find_esp_offset(f.name) == 4096 * 512

    def test_rejects_non_gpt(self):
        with tempfile.NamedTemporaryFile(suffix=".raw") as f:
            f.write(bytes(8192))
            f.flush()
            with pytest.raises(ValueError, match="Not a GPT disk"):
                find_esp_offset(f.name)

    def test_rejects_truncated(self):
        with tempfile.NamedTemporaryFile(suffix=".raw") as f:
            f.write(bytes(256))
            f.flush()
            with pytest.raises(ValueError, match="Not a GPT disk"):
                find_esp_offset(f.name)

    def test_accepts_path_object(self):
        disk = _build_gpt_disk(bytes(1024 * 512), esp_lba=2048)
        with tempfile.NamedTemporaryFile(suffix=".raw") as f:
            f.write(disk)
            f.flush()
            assert find_esp_offset(Path(f.name)) == 2048 * 512


@pytest.mark.skipif(not HAS_MTOOLS, reason="mtools not installed")
class TestExtractUki:
    def _make_esp_with_uki(self, tmp: Path, payload: bytes) -> bytes:
        """Create a FAT32 ESP image with a UKI at /EFI/BOOT/BOOTX64.EFI."""
        fat = tmp / "esp.img"
        uki = tmp / "uki.efi"
        uki.write_bytes(payload)

        subprocess.run(["truncate", "-s", "1M", str(fat)], check=True)
        subprocess.run(
            ["mkfs.fat", "-F", "32", str(fat)],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["mmd", "-i", str(fat), "::/EFI", "::/EFI/BOOT"],
            check=True,
        )
        subprocess.run(
            ["mcopy", "-i", str(fat), str(uki), "::/EFI/BOOT/BOOTX64.EFI"],
            check=True,
        )
        return fat.read_bytes()

    def test_raw_disk(self):
        payload = b"FAKE-UKI-" + bytes(range(256)) * 40
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            esp_data = self._make_esp_with_uki(tmp, payload)
            disk_path = tmp / "disk.raw"
            disk_path.write_bytes(_build_gpt_disk(esp_data))

            out = tmp / "BOOTX64.EFI"
            digest = extract_uki(disk_path, out)

            assert out.read_bytes() == payload
            assert digest == hashlib.sha384(payload).digest()

    def test_tar_gz(self):
        payload = b"FAKE-UKI-TAR-" + bytes(range(256)) * 20
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            esp_data = self._make_esp_with_uki(tmp, payload)
            disk_path = tmp / "disk.raw"
            disk_path.write_bytes(_build_gpt_disk(esp_data))

            archive = tmp / "disk.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(disk_path, arcname="disk.raw")

            out = tmp / "BOOTX64.EFI"
            digest = extract_uki(archive, out)

            assert out.read_bytes() == payload
            assert digest == hashlib.sha384(payload).digest()

    def test_tar_gz_no_raw_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            dummy = tmp / "readme.txt"
            dummy.write_text("not a disk")

            archive = tmp / "archive.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(dummy, arcname="readme.txt")

            with pytest.raises(ValueError, match="No member ending in '.raw'"):
                extract_uki(archive, tmp / "out.efi")
