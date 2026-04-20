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

"""Baseline management for non-computable event digests.

Stores event data that cannot be computed from firmware, UKI, or
constants alone. Extracted once from a known-good CCEL and reused
for measurement computation.

The baseline has:

  secureboot_enabled: Whether Secure Boot is on or off. Stored as a
    simple boolean so it can be toggled without a new CCEL; the
    UEFI_VARIABLE_DATA digest is recomputed on the fly.

  events: Pre-hashed SHA-384(UEFI_VARIABLE_DATA) digests for
    PK/KEK/db/dbx certificate databases, plus VMM-generated
    machine-type-dependent digests (TdxTable, ACPI tables, boot
    variables, GPT hash) that cannot be derived from any input we have.
"""

from __future__ import annotations

import json
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .ccel import (
    EV_EFI_ACTION,
    EV_EFI_BOOT_SERVICES_APPLICATION,
    EV_EFI_GPT_EVENT,
    EV_EFI_HANDOFF_TABLES2,
    EV_EFI_PLATFORM_FIRMWARE_BLOB2,
    EV_EFI_VARIABLE_BOOT,
    EV_EFI_VARIABLE_DRIVER_CONFIG,
    EV_IPL,
    EV_PLATFORM_CONFIG_FLAGS,
    EV_SEPARATOR,
    TPM_ALG_SHA384,
    EventLogEntry,
    ParsedEventLog,
    parse_event_log,
)


@dataclass
class BaselineEvent:
    """A single non-computable event digest extracted from a reference CCEL."""

    rtmr: int
    event_type: str
    label: str  # human-readable label (e.g. "TdxTable", "PK", "GPT")
    digest: str  # SHA-384 hex


def _infer_provider(machine_type: str) -> str:
    """Infer cloud provider from machine type naming conventions."""
    mt = machine_type.lower()
    if mt.startswith("standard_") or mt.startswith("standard "):
        return "azure"
    if "." in mt and any(mt.endswith(s) for s in (".metal", ".xlarge", ".large", ".medium", ".small", ".micro", ".nano")):
        return "aws"
    return "gcp"


@dataclass
class Baseline:
    """Non-computable event digests for a specific machine type.

    These are VMM-generated values (ACPI tables, GPT, boot variables, etc.)
    that cannot be derived offline from firmware or UKI alone.
    """

    machine_type: str
    firmware_sha384: str = ""
    secureboot_enabled: bool = False
    provider: str = ""
    platform: str = ""
    events: list[BaselineEvent] = field(default_factory=list)

    def rtmr_events(self, rtmr: int) -> list[BaselineEvent]:
        return [e for e in self.events if e.rtmr == rtmr]


def load(path: Path) -> Baseline:
    """Load a baseline from a JSON file."""
    data = json.loads(path.read_text())
    events = [BaselineEvent(**e) for e in data.get("events", [])]
    return Baseline(
        machine_type=data["machine_type"],
        firmware_sha384=data.get("firmware_sha384", ""),
        secureboot_enabled=data.get("secureboot_enabled", False),
        provider=data.get("provider", ""),
        platform=data.get("platform", ""),
        events=events,
    )


def save(baseline: Baseline, path: Path) -> None:
    """Save a baseline to a JSON file."""
    data: dict = {}
    if baseline.provider:
        data["provider"] = baseline.provider
    if baseline.platform:
        data["platform"] = baseline.platform
    data["machine_type"] = baseline.machine_type
    data["firmware_sha384"] = baseline.firmware_sha384
    data["secureboot_enabled"] = baseline.secureboot_enabled
    data["events"] = [asdict(e) for e in baseline.events]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _is_computable(rtmr: int, event: EventLogEntry) -> bool:
    """Return True if this event's digest can be computed from inputs."""
    et = event.event_type

    if rtmr == 0:
        if et == EV_EFI_PLATFORM_FIRMWARE_BLOB2:
            return True
        if et == EV_SEPARATOR:
            return True
        if et == EV_EFI_VARIABLE_DRIVER_CONFIG:
            raw = event.event_data
            if len(raw) >= 32:
                name_len = struct.unpack_from("<Q", raw, 16)[0]
                name = raw[32 : 32 + name_len * 2].decode("utf-16-le", errors="replace")
                return name == "SecureBoot"
            return False
        return False

    if rtmr == 1:
        if et == EV_EFI_ACTION:
            return True
        if et == EV_SEPARATOR:
            return True
        if et == EV_EFI_BOOT_SERVICES_APPLICATION:
            return True
        return False

    if rtmr == 2:
        return True

    return False


def _label_for_event(rtmr: int, event: EventLogEntry) -> str:
    et = event.event_type
    raw = event.event_data

    if rtmr == 0:
        if et == EV_EFI_HANDOFF_TABLES2:
            return "TdxTable"
        if et == EV_PLATFORM_CONFIG_FLAGS:
            return "ACPI_DATA"
        if et == EV_EFI_VARIABLE_DRIVER_CONFIG and len(raw) >= 32:
            name_len = struct.unpack_from("<Q", raw, 16)[0]
            return raw[32 : 32 + name_len * 2].decode("utf-16-le", errors="replace")
        if et == EV_EFI_VARIABLE_BOOT and len(raw) >= 32:
            name_len = struct.unpack_from("<Q", raw, 16)[0]
            return raw[32 : 32 + name_len * 2].decode("utf-16-le", errors="replace")

    if rtmr == 1:
        if et == EV_EFI_GPT_EVENT:
            return "GPT"

    return event.event_type_name


def extract_from_ccel(
    ccel_data: bytes,
    machine_type: str,
) -> Baseline:
    """Extract a baseline from a CCEL binary.

    The SecureBoot flag is stored as a boolean (computable from it).
    PK/KEK/db/dbx and other VMM-generated events are stored as
    pre-hashed digests.
    """
    log = parse_event_log(ccel_data)
    baseline = Baseline(
        machine_type=machine_type,
        provider=_infer_provider(machine_type),
        platform="tdx",
    )

    for event in log.measurable_events:
        if event.imr_index != 0 or event.event_type != EV_EFI_VARIABLE_DRIVER_CONFIG:
            continue
        raw = event.event_data
        if len(raw) < 32:
            continue
        name_len = struct.unpack_from("<Q", raw, 16)[0]
        data_len = struct.unpack_from("<Q", raw, 24)[0]
        name = raw[32 : 32 + name_len * 2].decode("utf-16-le", errors="replace")
        if name == "SecureBoot":
            var_data = raw[32 + name_len * 2 : 32 + name_len * 2 + data_len]
            baseline.secureboot_enabled = (var_data != b"\x00")
            break

    for event in log.measurable_events:
        d = event.get_digest(TPM_ALG_SHA384)
        if d is None:
            continue

        rtmr = event.imr_index
        if _is_computable(rtmr, event):
            continue

        label = _label_for_event(rtmr, event)
        baseline.events.append(BaselineEvent(
            rtmr=rtmr,
            event_type=event.event_type_name,
            label=label,
            digest=d.hex,
        ))

    return baseline
