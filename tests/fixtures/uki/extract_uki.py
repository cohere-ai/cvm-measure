#!/usr/bin/env python3
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

"""Extract BOOTX64.EFI (UKI) from a disk.tar.gz image.

Requires mtools (brew install mtools / apt install mtools).

Usage:
    python3 extract_uki.py /tmp/disk.tar.gz tests/fixtures/uki/bootx64-a3-highgpu-1g.efi
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def extract_uki(archive: Path, output: Path) -> None:
    with tarfile.open(archive) as tar:
        member = next(
            m for m in tar if m.name.endswith(".raw") or m.name == "disk.raw"
        )
        tar.extract(member, path=tempfile.gettempdir())
        raw = Path(tempfile.gettempdir()) / member.name

    try:
        subprocess.run(
            ["mcopy", "-i", f"{raw}@@1048576", "::/EFI/BOOT/BOOTX64.EFI", str(output)],
            check=True,
        )
    finally:
        raw.unlink(missing_ok=True)

    data = output.read_bytes()
    print(f"Size: {len(data)} bytes", file=sys.stderr)
    print(f"SHA-384: {hashlib.sha384(data).hexdigest()}", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <disk.tar.gz> <output.efi>", file=sys.stderr)
        sys.exit(1)
    extract_uki(Path(sys.argv[1]), Path(sys.argv[2]))
