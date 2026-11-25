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

"""Facts read from the QEMU binary Kata launches."""

from __future__ import annotations

import re

# Machine versions whose SMBIOS and ACPI compat properties this package models.
SUPPORTED_Q35_MACHINES = ("pc-q35-11.0",)


def q35_machine(qemu: bytes) -> str:
    """The versioned machine that ``-machine q35`` resolves to: the newest pc-q35 QOM type."""
    versions = {
        (int(major), int(minor))
        for major, minor in re.findall(
            rb"(?<=\0)pc-q35-(\d+)\.(\d+)-machine(?=\0)", qemu
        )
    }
    if not versions:
        raise ValueError("QEMU binary defines no pc-q35 machine types")
    major, minor = max(versions)
    machine = f"pc-q35-{major}.{minor}"
    if machine not in SUPPORTED_Q35_MACHINES:
        raise NotImplementedError(
            f"QEMU machine {machine} is not modelled; supported: {SUPPORTED_Q35_MACHINES}"
        )
    return machine
