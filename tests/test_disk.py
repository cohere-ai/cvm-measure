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
from pathlib import Path

import pytest

from cvm_measure.disk import (
    ESP_GUID,
    compute_gpt_digest,
    extract_uki,
    find_esp_offset,
)

HAS_MTOOLS = shutil.which("mcopy") is not None and shutil.which("mkfs.fat") is not None


def _build_gpt_disk(esp_data: bytes, esp_lba: int = 2048) -> bytes:
    """Build a minimal GPT disk image with an ESP partition."""
    esp_sectors = len(esp_data) // 512
    disk = bytearray((esp_lba + esp_sectors + 1) * 512)

    # GPT header at LBA 1
    hdr = bytearray(92)
    hdr[:8] = b"EFI PART"
    struct.pack_into("<Q", hdr, 72, 2)   # partition entry start LBA
    struct.pack_into("<I", hdr, 80, 1)   # number of entries
    struct.pack_into("<I", hdr, 84, 128) # entry size
    disk[512:512 + 92] = hdr

    # Single partition entry at LBA 2
    entry = bytearray(128)
    entry[:16] = ESP_GUID
    struct.pack_into("<Q", entry, 32, esp_lba)
    struct.pack_into("<Q", entry, 40, esp_lba + esp_sectors - 1)
    disk[1024:1024 + 128] = entry

    # Embed ESP data
    off = esp_lba * 512
    disk[off:off + len(esp_data)] = esp_data
    return bytes(disk)


def _build_measurable_gpt_disk(
    *,
    header_size: int = 92,
    tail: bytes = b"",
    num_entries: int = 4,
    non_empty: int = 2,
    entry_size: int = 128,
) -> tuple[bytes, bytes, list[bytes]]:
    """Build a GPT disk plus the header and entries EDK2 would measure."""
    entry_lba = 2
    entry_sectors = (num_entries * entry_size + 511) // 512
    disk = bytearray((entry_lba + entry_sectors + 1) * 512)

    hdr = bytearray(512)
    hdr[:8] = b"EFI PART"
    struct.pack_into("<I", hdr, 12, header_size)
    struct.pack_into("<I", hdr, 16, 0xDEADBEEF)  # HeaderCRC32, measured verbatim
    struct.pack_into("<Q", hdr, 72, entry_lba)
    struct.pack_into("<I", hdr, 80, num_entries)
    struct.pack_into("<I", hdr, 84, entry_size)
    hdr[92 : 92 + len(tail)] = tail
    disk[512:1024] = hdr

    measured_entries = []
    off = entry_lba * 512
    for i in range(num_entries):
        entry = bytearray(entry_size)
        if i < non_empty:
            entry[:16] = ESP_GUID if i == 0 else bytes([i + 1] * 16)
            struct.pack_into("<Q", entry, 32, 2048 + i)
            measured_entries.append(bytes(entry))
        disk[off : off + entry_size] = entry
        off += entry_size

    return bytes(disk), bytes(hdr[:92]), measured_entries


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

    def test_bytes_past_92_are_not_measured(self):
        """EDK2 copies a fixed-size struct, so a larger HeaderSize adds nothing."""
        a, header, entries = _build_measurable_gpt_disk(header_size=96, tail=b"\xa5" * 4)
        b, _, _ = _build_measurable_gpt_disk(header_size=96, tail=b"\x5a" * 4)
        assert self._digest(a) == self._digest(b) == self._expected(header, entries)

    def test_skips_empty_partition_entries(self):
        disk, header, entries = _build_measurable_gpt_disk(num_entries=8, non_empty=3)
        assert len(entries) == 3
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
