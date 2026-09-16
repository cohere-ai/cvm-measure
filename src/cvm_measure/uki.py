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

"""Unified Kernel Image sections, as systemd-stub measures them.

Shared because the section list is correctness-relevant rather than
convenient: it encodes systemd's UnifiedSection enum, and every platform's
OS-identity register is built from it. Two copies would drift apart the next
time systemd adds a section, and the symptom would be a register that is
wrong rather than one that is missing.

The measurement itself differs between platforms only in the hash: TDX folds
it into RTMR[2] with SHA-384, the vTPM into PCR 11 with SHA-256.
"""

from __future__ import annotations

from .tdx.pe import pe_extract_section, pe_section_names

# systemd's canonical measurement order for UKI sections, from the
# UnifiedSection enum in src/fundamental/uki.h ("PLEASE DO NOT REORDER").
# systemd-stub walks the enum and measures every section it finds, so the list
# has to be complete: a section missing from here would be skipped silently and
# the register would come out wrong rather than absent.
UKI_MEASURED_SECTIONS = [
    ".linux",
    ".osrel",
    ".cmdline",
    ".initrd",
    ".ucode",
    ".splash",
    ".dtb",
    ".uname",
    ".sbat",
    # .pcrsig sits here in the enum. It signs the expected result of the
    # measurement, so systemd is careful not to feed it back in.
    ".pcrpkey",
    ".profile",
    ".dtbauto",
    ".hwids",
    ".efifw",
]

UKI_UNMEASURED_SECTION = ".pcrsig"

# .profile keeps its place in the canonical order above, but a UKI that carries
# one is refused rather than measured: profiles repeat section names, one group
# per profile, and systemd-stub measures the group the profile selected at boot
# resolves to. Which group that is cannot be decided from the image alone.
UKI_PROFILE_SECTION = ".profile"


def measured_sections(uki: bytes, *, register: str) -> list[tuple[str, bytes]]:
    """The sections systemd-stub measures, in order, with their contents.

    Sections are read at VirtualSize, which is what the loader maps and what
    systemd-stub hashes. The refusal check runs here rather than in the
    caller so that no platform can measure a UKI this tool does not model.

    Args:
        uki: Raw UKI (BOOTX64.EFI) bytes.
        register: Register name for error messages, e.g. "PCR 11".
    """
    reject_unmodelled_uki(uki, register)

    sections = []
    for name in UKI_MEASURED_SECTIONS:
        content = pe_extract_section(uki, name, use_virtual_size=True)
        if content is not None:
            sections.append((name, content))
    return sections


def reject_unmodelled_uki(uki: bytes, register: str) -> None:
    """Refuse a UKI whose measured section sequence is not the canonical one."""
    names = pe_section_names(uki)
    if UKI_PROFILE_SECTION in names:
        raise ValueError(
            f"UKI carries a {UKI_PROFILE_SECTION} section, so what gets measured "
            f"into {register} depends on which profile is selected at boot. This "
            "tool measures a single section sequence, so refusing rather than "
            "modelling one arbitrary profile."
        )

    repeated = sorted(
        {
            name
            for name in names
            if name in UKI_MEASURED_SECTIONS and names.count(name) > 1
        }
    )
    if repeated:
        raise ValueError(
            f"UKI repeats measured section(s) {', '.join(repeated)}. systemd-stub "
            "measures one of each, and which one is not decidable from the image "
            f"alone, so refusing to compute {register}."
        )
