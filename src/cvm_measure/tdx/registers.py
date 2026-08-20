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

from ..uki import (
    UKI_MEASURED_SECTIONS,
    UKI_PROFILE_SECTION,
    UKI_UNMEASURED_SECTION,
    measured_sections,
)
from .baseline import Baseline
from .mrtd import cfv_image, compute_mrtd
from .pe import pe_authenticode_digest, pe_extract_section
from .rtmr import SHA384_SIZE, replay_digests
from .uefi import compute_secureboot_digest

__all__ = [
    "UKI_MEASURED_SECTIONS",
    "UKI_PROFILE_SECTION",
    "UKI_UNMEASURED_SECTION",
    "ComputedRegisters",
    "compute_all",
]

SEPARATOR_DIGEST = hashlib.sha384(struct.pack("<I", 0)).digest()

# RTMR[0] events that occupy a fixed slot in the replay, addressed by label.
_RTMR0_FIXED_LABELS = ("TdxTable", "PK", "KEK", "db", "dbx")

# The remaining RTMR[0] events are replayed positionally, because three
# consecutive ACPI_DATA events are indistinguishable by label. That only works
# for firmware measuring this exact sequence, which is the GCP A3 OVMF build.
# TODO(CC-167): keep an ordered CCEL template with placeholders for the
# computable events, so other firmware can be reconstructed by substitution
# instead of relying on a hard-coded sequence.
_RTMR0_TRAILING_LABELS = (
    "ACPI_DATA",
    "ACPI_DATA",
    "ACPI_DATA",
    "BootOrder",
    "Boot0001",
    "Boot0002",
    "Boot0003",
    "Boot0000",
)
_RTMR0_EXPECTED_LABELS = _RTMR0_FIXED_LABELS + _RTMR0_TRAILING_LABELS

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


def _digest_from_hex(value: str, what: str) -> bytes:
    """Decode a caller-supplied SHA-384 hex string, rejecting anything else."""
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{what} is not valid hex: {value!r}") from exc
    if len(raw) != SHA384_SIZE:
        raise ValueError(
            f"{what} must be a {SHA384_SIZE}-byte SHA-384 digest "
            f"({SHA384_SIZE * 2} hex chars), got {len(raw)} bytes"
        )
    return raw


def _verify_firmware(firmware: bytes, baseline: Baseline) -> None:
    """Refuse to mix a baseline with firmware it was not captured from.

    Baseline events and the digests computed here describe one boot of one
    firmware image. Combining halves from different images yields a register
    tuple that looks plausible but no machine will ever report.
    """
    if not baseline.firmware_sha384:
        return
    actual = hashlib.sha384(firmware).hexdigest()
    if actual != baseline.firmware_sha384.lower():
        raise ValueError(
            f"Baseline {baseline.machine_type!r} was captured from different "
            f"firmware: baseline records {baseline.firmware_sha384}, the given "
            f"firmware hashes to {actual}"
        )


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
    _verify_firmware(firmware, baseline)

    if rtmr3_hex is None:
        rtmr3_hex = bytes(SHA384_SIZE).hex()
    else:
        rtmr3_hex = _digest_from_hex(rtmr3_hex, "rtmr3").hex()

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
      2.  CFV = SHA-384(CFV region)    (located via firmware TDX metadata)
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

    labels = [event.label for event in baseline_events]
    if sorted(labels) != sorted(_RTMR0_EXPECTED_LABELS):
        raise ValueError(
            f"RTMR[0] baseline for {baseline.machine_type!r} does not match the only "
            f"supported event set. Expected {list(_RTMR0_EXPECTED_LABELS)}, got {labels}. "
            "Reconstructing other firmware needs an ordered CCEL template."
        )

    fixed = set(_RTMR0_FIXED_LABELS)
    trailing = [event for event in baseline_events if event.label not in fixed]
    if tuple(e.label for e in trailing) != _RTMR0_TRAILING_LABELS:
        raise ValueError(
            "RTMR[0] baseline events are in an unsupported order: expected "
            f"{list(_RTMR0_TRAILING_LABELS)} after the Secure Boot variables, got "
            f"{[e.label for e in trailing]}. These are replayed positionally, so the "
            "order has to match the firmware that produced them."
        )

    cfv_digest = hashlib.sha384(cfv_image(firmware)).digest()
    sb_flag_data = b"\x01" if baseline.secureboot_enabled else b"\x00"
    sb_flag_digest = compute_secureboot_digest("SecureBoot", sb_flag_data)

    digests = [
        _digest_from_hex(by_label["TdxTable"], "baseline TdxTable digest"),
        cfv_digest,
        sb_flag_digest,
        _digest_from_hex(by_label["PK"], "baseline PK digest"),
        _digest_from_hex(by_label["KEK"], "baseline KEK digest"),
        _digest_from_hex(by_label["db"], "baseline db digest"),
        _digest_from_hex(by_label["dbx"], "baseline dbx digest"),
        SEPARATOR_DIGEST,
        *(
            _digest_from_hex(event.digest, f"baseline {event.label} digest")
            for event in trailing
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

    Event 5 is the kernel systemd-stub loads out of the UKI's .linux section,
    which firmware measures as a second boot application. A UKI without that
    section boots some other way and produces a different event sequence, so
    it is rejected rather than measured as if it were its own kernel.
    """
    if gpt_digest_hex is not None:
        gpt_digest = _digest_from_hex(gpt_digest_hex, "GPT digest")
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
        gpt_digest = _digest_from_hex(gpt_event.digest, "baseline GPT digest")

    uki_auth = pe_authenticode_digest(uki, "sha384")
    kernel_data = pe_extract_section(uki, ".linux", use_virtual_size=True)
    if kernel_data is None:
        raise ValueError(
            "UKI has no .linux section, so there is no embedded kernel for "
            "firmware to measure as the second boot application. RTMR[1] for a "
            "boot chain like that is not something this tool can reconstruct."
        )
    kernel_auth = pe_authenticode_digest(kernel_data, "sha384")

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

    systemd-stub measures each section it recognises as two events, in the
    canonical order of UKI_MEASURED_SECTIONS:
      1. SHA-384(section_name + '\\0')
      2. SHA-384(section_content)
    """
    digests = []
    for section_name, content in measured_sections(uki, register="RTMR[2]"):
        digests.append(hashlib.sha384((section_name + "\0").encode("ascii")).digest())
        digests.append(hashlib.sha384(content).digest())

    return replay_digests(digests).hex()
