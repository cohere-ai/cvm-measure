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

"""Host facts that a Kata TDX measurement depends on and no artifact records.

QEMU copies the TD's CPUID leaf 1 into the guest's SMBIOS processor record,
and OVMF sizes its 64-bit PCI window from the TD's CPUID address width and
places the GPUs' BARs in it. The same Kata release therefore measures
differently on a different CPU or GPU, so these values live in a small JSON
file per host type rather than in code.

Example:
    {
      "name": "oci-bm-gpu-b200-emr",
      "cpuid_1_eax": "0x000c06f2",
      "cpuid_1_edx": "0x1fa9fbff",
      "phys_bits": 52,
      "guest_phys_bits": 0,
      "gpu_bars": ["256GiB", "64MiB", "32MiB"]
    }
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

_SIZE_UNITS = {"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}


@dataclass(frozen=True)
class Platform:
    name: str
    # CPUID.01H:EAX and EDX as QEMU sees them for the TD (SMBIOS type 4 ProcessorId).
    cpuid_1_eax: int
    cpuid_1_edx: int
    # CPUID.80000008H:EAX[7:0] and [23:16] inside the TD.
    phys_bits: int
    guest_phys_bits: int
    # Sizes of each 64-bit prefetchable BAR of one passed-through GPU.
    gpu_bars: tuple[int, ...]


def _int(value: object, what: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{what} must be an integer, got {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(f"{what} must be an integer or a 0x-prefixed string, got {value!r}")


def _size(value: object, what: str) -> int:
    m = (
        re.fullmatch(r"(\d+)\s*(KiB|MiB|GiB|TiB)", value.strip())
        if isinstance(value, str)
        else None
    )
    size = int(m.group(1)) * _SIZE_UNITS[m.group(2)] if m else _int(value, what)
    if size <= 0 or size & (size - 1):
        raise ValueError(f"{what} must be a power of two, got {value!r}")
    return size


def load_platform(path: str | Path) -> Platform:
    data = json.loads(Path(path).read_text())
    bars = data.get("gpu_bars")
    if not isinstance(bars, list) or not bars:
        raise ValueError(f"{path}: gpu_bars must be a non-empty list")
    return Platform(
        name=str(data["name"]),
        cpuid_1_eax=_int(data["cpuid_1_eax"], "cpuid_1_eax"),
        cpuid_1_edx=_int(data["cpuid_1_edx"], "cpuid_1_edx"),
        phys_bits=_int(data["phys_bits"], "phys_bits"),
        guest_phys_bits=_int(data.get("guest_phys_bits", 0), "guest_phys_bits"),
        gpu_bars=tuple(_size(b, "gpu_bars entry") for b in bars),
    )
