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

"""Orchestrate offline computation of MRTD + RTMR[0-3].

Combines firmware analysis, baseline data, UKI PE parsing, and initdata
to compute all TDX register values without requiring a live VM.

The baseline stores events whose digests cannot be computed offline:
  - VMM-generated events (TdxTable, ACPI tables, boot variables)
  - SecureBoot variables (injected by hypervisor, may change)
  - GPT partition hash (depends on disk layout)

This module computes the rest from firmware, UKI, and constants.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from .baseline import Baseline
from .mrtd import compute_mrtd
from .pe import pe_authenticode_digest, pe_extract_section
from .rtmr import SHA384_SIZE, replay_digests
from .uefi import compute_secureboot_digest

UKI_MEASURED_SECTIONS = [
    ".linux",
    ".osrel",
    ".cmdline",
    ".initrd",
    ".ucode",
    ".uname",
    ".sbat",
    ".pcrpkey",
]

SEPARATOR_DIGEST = hashlib.sha384(struct.pack("<I", 0)).digest()

# RTMR[0] events that occupy a fixed slot in the replay, addressed by label.
_RTMR0_FIXED_LABELS = ("TdxTable", "PK", "KEK", "db", "dbx")

# Labels a baseline may use for the EV_EFI_GPT_EVENT digest. Baselines
# extracted by this tool omit it, since it is computed from --disk instead.
_GPT_LABELS = ("GPT", "EV_EFI_GPT_EVENT")

EFI_ACTION_DIGESTS = {
    name: hashlib.sha384(name.encode("ascii")).digest()
    for name in [
        "Calling EFI Application from Boot Option",
        "Exit Boot Services Invocation",
        "Exit Boot Services Returned with Success",
    ]
}


@dataclass
class ComputedRegisters:
    """All five TDX measurement registers as hex strings."""

    mrtd: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str

    def as_dict(self) -> dict[str, str]:
        return {
            "mrtd": self.mrtd,
            "rtmr0": self.rtmr0,
            "rtmr1": self.rtmr1,
            "rtmr2": self.rtmr2,
            "rtmr3": self.rtmr3,
        }


def compute_all(
    firmware: bytes,
    uki: bytes,
    baseline: Baseline,
    ram_gib: int,
    numa_nodes: int = 1,
    max_per_node_gib: int | None = None,
    rtmr3_hex: str | None = None,
    gpt_digest_hex: str | None = None,
) -> ComputedRegisters:
    """Compute MRTD + RTMR[0-3] entirely offline.

    Args:
        firmware: Raw OVMF firmware binary bytes.
        uki: Raw UKI (BOOTX64.EFI) bytes.
        baseline: Baseline with non-computable event digests.
        ram_gib: Total guest RAM in GiB.
        numa_nodes: Number of NUMA nodes (default 1).
        max_per_node_gib: Max GiB per NUMA node (defaults to ram_gib).
        rtmr3_hex: Pre-computed RTMR[3] hex string (96 chars). If None,
            defaults to all zeros (no initdata).
        gpt_digest_hex: Pre-computed EV_EFI_GPT_EVENT SHA-384 hex string. If
            None, falls back to the GPT event captured in the baseline.
    """
    if rtmr3_hex is None:
        rtmr3_hex = bytes(SHA384_SIZE).hex()

    return ComputedRegisters(
        mrtd=_compute_mrtd(firmware, ram_gib, numa_nodes, max_per_node_gib),
        rtmr0=_compute_rtmr0(firmware, baseline),
        rtmr1=_compute_rtmr1(uki, baseline, gpt_digest_hex),
        rtmr2=_compute_rtmr2(uki),
        rtmr3=rtmr3_hex,
    )


def _compute_mrtd(
    firmware: bytes,
    ram_gib: int,
    numa_nodes: int = 1,
    max_per_node_gib: int | None = None,
) -> str:
    return compute_mrtd(firmware, ram_gib, numa_nodes, max_per_node_gib).hex()


def _compute_rtmr0(firmware: bytes, baseline: Baseline) -> str:
    """Compute RTMR[0] from firmware + baseline events.

    Event order (16 total):
      1.  TdxTable                    (baseline event)
      2.  CFV = SHA-384(fw[0:0x20000]) (computed from firmware)
      3.  SecureBoot                  (computed from secureboot_enabled flag)
      4.  PK                         (baseline event)
      5.  KEK                        (baseline event)
      6.  db                         (baseline event)
      7.  dbx                        (baseline event)
      8.  Separator = SHA-384(0u32)   (computed constant)
      9.  ACPI_DATA                  (baseline event)
      10. ACPI_DATA                  (baseline event)
      11. ACPI_DATA                  (baseline event)
      12. BootOrder                  (baseline event)
      13. Boot0001                   (baseline event)
      14. Boot0002                   (baseline event)
      15. Boot0003                   (baseline event)
      16. Boot0000                   (baseline event)

    The five fixed events are looked up by label so that a baseline whose
    events are ordered differently fails loudly instead of replaying the
    wrong digest in the wrong slot. The trailing ACPI and Boot events keep
    their baseline order, which is the order firmware measured them in.
    """
    baseline_events = baseline.rtmr_events(0)
    by_label: dict[str, str] = {}
    for event in baseline_events:
        by_label.setdefault(event.label, event.digest)

    missing = [label for label in _RTMR0_FIXED_LABELS if label not in by_label]
    if missing:
        raise ValueError(
            f"RTMR[0] baseline is missing required event(s): {', '.join(missing)}"
        )

    cfv_digest = hashlib.sha384(firmware[0:0x20000]).digest()
    sb_flag_data = b"\x01" if baseline.secureboot_enabled else b"\x00"
    sb_flag_digest = compute_secureboot_digest("SecureBoot", sb_flag_data)

    fixed = set(_RTMR0_FIXED_LABELS)
    digests = [
        bytes.fromhex(by_label["TdxTable"]),
        cfv_digest,
        sb_flag_digest,
        bytes.fromhex(by_label["PK"]),
        bytes.fromhex(by_label["KEK"]),
        bytes.fromhex(by_label["db"]),
        bytes.fromhex(by_label["dbx"]),
        SEPARATOR_DIGEST,
        *(
            bytes.fromhex(event.digest)
            for event in baseline_events
            if event.label not in fixed
        ),
    ]

    return replay_digests(digests).hex()


def _compute_rtmr1(
    uki: bytes, baseline: Baseline, gpt_digest_hex: str | None = None
) -> str:
    """Compute RTMR[1] from UKI + baseline.

    Event order (7 total):
      1. "Calling EFI Application from Boot Option"  (computed constant)
      2. Separator                                     (computed constant)
      3. GPT hash                                      (disk image, or baseline fallback)
      4. UKI PE Authenticode hash                      (computed from UKI)
      5. Kernel PE Authenticode hash                   (computed from UKI .linux)
      6. "Exit Boot Services Invocation"               (computed constant)
      7. "Exit Boot Services Returned with Success"    (computed constant)

    A UKI without a .linux section is measured as its own kernel, since the
    whole image is then the kernel that firmware hands off to.
    """
    if gpt_digest_hex is not None:
        gpt_digest = bytes.fromhex(gpt_digest_hex)
    else:
        gpt_event = next(
            (e for e in baseline.rtmr_events(1) if e.label in _GPT_LABELS), None
        )
        if gpt_event is None:
            raise ValueError(
                "RTMR[1] requires the EV_EFI_GPT_EVENT digest, which depends on the "
                "disk layout. Pass --disk to compute it from the pod VM image, or "
                "use a legacy baseline that still carries a GPT event."
            )
        gpt_digest = bytes.fromhex(gpt_event.digest)

    uki_auth = pe_authenticode_digest(uki, "sha384")
    kernel_data = pe_extract_section(uki, ".linux", use_virtual_size=True)
    kernel_auth = (
        pe_authenticode_digest(kernel_data, "sha384")
        if kernel_data is not None
        else uki_auth
    )

    digests = [
        EFI_ACTION_DIGESTS["Calling EFI Application from Boot Option"],
        SEPARATOR_DIGEST,
        gpt_digest,
        uki_auth,
        kernel_auth,
        EFI_ACTION_DIGESTS["Exit Boot Services Invocation"],
        EFI_ACTION_DIGESTS["Exit Boot Services Returned with Success"],
    ]

    return replay_digests(digests).hex()


def _compute_rtmr2(uki: bytes) -> str:
    """Compute RTMR[2] entirely from UKI PE sections. No baseline needed.

    systemd-stub measures each section as two events:
      1. SHA-384(section_name + '\\0')
      2. SHA-384(section_content)
    """
    digests = []
    for section_name in UKI_MEASURED_SECTIONS:
        content = pe_extract_section(uki, section_name, use_virtual_size=True)
        if content is None:
            continue
        digests.append(hashlib.sha384((section_name + "\0").encode("ascii")).digest())
        digests.append(hashlib.sha384(content).digest())

    return replay_digests(digests).hex()
