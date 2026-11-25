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

"""Firmware volume walking, for values OVMF derives from its own image."""

from __future__ import annotations

import lzma
import struct
import uuid
from collections.abc import Iterator

_FVH = b"_FVH"
_LZMA_GUID = uuid.UUID("ee4e5898-3914-4259-9d6e-dc7bd79403cf").bytes_le
# MdeModulePkg.dec PcdBootManagerMenuFile default: BootManagerMenuApp's FILE_GUID.
BOOT_MANAGER_MENU_FILE = uuid.UUID("eec25bdc-67f2-4d95-b1d5-f81b2039d11d").bytes_le

_SECTION_GUID_DEFINED = 0x02
_SECTION_PE32 = 0x10
_SECTION_USER_INTERFACE = 0x15
_SECTION_FIRMWARE_VOLUME_IMAGE = 0x17
_FFS_ATTRIB_LARGE_FILE = 0x01
_FV_FILETYPE_FFS_PAD = 0xF0


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _sections(data: bytes) -> Iterator[tuple[int, bytes]]:
    """Leaf sections, with GUID-defined LZMA and nested volume images expanded."""
    off = 0
    while off + 4 <= len(data):
        size = int.from_bytes(data[off : off + 3], "little")
        stype, hdr = data[off + 3], 4
        if size == 0xFFFFFF:
            size, hdr = struct.unpack_from("<I", data, off + 4)[0], 8
        if size < hdr:
            break
        body = data[off + hdr : off + size]
        if stype == _SECTION_GUID_DEFINED and body[:16] == _LZMA_GUID:
            data_offset = struct.unpack_from("<H", body, 16)[0] - hdr
            yield from _sections(
                lzma.decompress(body[data_offset:], format=lzma.FORMAT_ALONE)
            )
        else:
            yield stype, body
        off = _align(off + size, 4)


def volumes(
    image: bytes,
) -> Iterator[tuple[bytes, list[tuple[bytes, list[tuple[int, bytes]]]]]]:
    """Yield (FvNameGuid, [(file GUID, sections)]) for every volume, nested ones included."""
    off = 0
    while (sig := image.find(_FVH, off)) >= 0:
        start = sig - 40
        off = sig + 4
        if start < 0:
            continue
        length, _, _, hdr_len, _, ext_off = struct.unpack_from(
            "<Q4sIHHH", image, start + 32
        )
        if not hdr_len or start + length > len(image):
            continue
        fv = image[start : start + length]
        name = fv[ext_off : ext_off + 16] if ext_off else b""
        files, nested = [], []
        pos = (
            _align(ext_off + struct.unpack_from("<I", fv, ext_off + 16)[0], 8)
            if ext_off
            else hdr_len
        )
        while pos + 24 <= len(fv):
            fguid, _, ftype, attrs = struct.unpack_from("<16sHBB", fv, pos)
            fsize, fhdr = int.from_bytes(fv[pos + 20 : pos + 23], "little"), 24
            if attrs & _FFS_ATTRIB_LARGE_FILE:
                fsize, fhdr = struct.unpack_from("<Q", fv, pos + 24)[0], 32
            if fguid == b"\xff" * 16 or fsize < fhdr:
                break
            if ftype != _FV_FILETYPE_FFS_PAD:
                secs = list(_sections(fv[pos + fhdr : pos + fsize]))
                files.append((fguid, secs))
                nested += [b for t, b in secs if t == _SECTION_FIRMWARE_VOLUME_IMAGE]
            pos = _align(pos + fsize, 8)
        yield name, files
        for inner in nested:
            yield from volumes(inner)
        off = start + length


def boot_manager_menu_option(firmware: bytes) -> bytes:
    """The Boot0000 load option BdsDxe registers for the boot manager menu.

    BmRegisterBootManagerMenu: LOAD_OPTION_ACTIVE | LOAD_OPTION_HIDDEN |
    LOAD_OPTION_CATEGORY_APP, the file's UI name, and an FV + FvFile device path.
    """
    for fv_name, files in volumes(firmware):
        for fguid, secs in files:
            if fguid != BOOT_MANAGER_MENU_FILE or not any(
                t == _SECTION_PE32 for t, _ in secs
            ):
                continue
            ui = next((b for t, b in secs if t == _SECTION_USER_INTERFACE), None)
            if ui is None or not fv_name:
                raise NotImplementedError(
                    "boot manager menu file without a UI section or FV name"
                )
            path = (
                struct.pack("<BBH", 0x04, 0x07, 20)
                + fv_name
                + struct.pack("<BBH", 0x04, 0x06, 20)
                + fguid
                + struct.pack("<BBH", 0x7F, 0xFF, 4)
            )
            description = ui.decode("utf-16-le").rstrip("\0") + "\0"
            return (
                struct.pack("<IH", 0x0109, len(path))
                + description.encode("utf-16-le")
                + path
            )
    raise ValueError("firmware has no boot manager menu application")
