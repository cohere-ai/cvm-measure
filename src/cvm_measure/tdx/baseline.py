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

Stores VMM-generated digests (ACPI tables, boot variables, etc.) extracted
once from a known-good CCEL and reused for measurement computation.
Image-specific events such as GPT are computed from the disk image instead.
SecureBoot is stored as a boolean so it can be toggled without a new CCEL.
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
    EV_PLATFORM_CONFIG_FLAGS,
    EV_SEPARATOR,
    TPM_ALG_SHA384,
    EventLogEntry,
    parse_event_log,
)


@dataclass
class BaselineEvent:
    """A single non-computable event digest extracted from a reference CCEL."""

    rtmr: int
    event_type: str
    label: str
    digest: str  # SHA-384 hex


def _infer_provider(machine_type: str) -> str:
    """Infer cloud provider from machine type naming conventions."""
    mt = machine_type.lower()
    if mt.startswith("standard_") or mt.startswith("standard "):
        return "azure"
    if "." in mt:
        return "aws"
    return "gcp"


@dataclass
class Baseline:
    """Non-computable event digests for a specific machine type."""

    machine_type: str
    firmware_sha384: str = ""
    secureboot_enabled: bool = False
    provider: str = ""
    platform: str = ""
    events: list[BaselineEvent] = field(default_factory=list)

    def rtmr_events(self, rtmr: int) -> list[BaselineEvent]:
        return [e for e in self.events if e.rtmr == rtmr]

    def to_dict(self) -> dict[str, object]:
        """Serialize to a dict suitable for JSON output."""
        data: dict[str, object] = {}
        if self.provider:
            data["provider"] = self.provider
        if self.platform:
            data["platform"] = self.platform
        data["machine_type"] = self.machine_type
        data["firmware_sha384"] = self.firmware_sha384
        data["secureboot_enabled"] = self.secureboot_enabled
        data["events"] = [asdict(e) for e in self.events]
        return data


def load(path: Path) -> Baseline:
    """Load a baseline from a JSON file."""
    data = json.loads(path.read_text())
    known_keys = {"rtmr", "event_type", "label", "digest"}
    events = [
        BaselineEvent(**{k: v for k, v in e.items() if k in known_keys})
        for e in data.get("events", [])
    ]
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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline.to_dict(), indent=2) + "\n")


# -- CCEL extraction -----------------------------------------------------------

_COMPUTABLE = {
    (0, EV_EFI_PLATFORM_FIRMWARE_BLOB2),
    (0, EV_SEPARATOR),
    (1, EV_EFI_ACTION),
    (1, EV_EFI_GPT_EVENT),
    (1, EV_SEPARATOR),
    (1, EV_EFI_BOOT_SERVICES_APPLICATION),
}

_LABEL_OVERRIDES = {
    (0, EV_EFI_HANDOFF_TABLES2): "TdxTable",
    (0, EV_PLATFORM_CONFIG_FLAGS): "ACPI_DATA",
    (1, EV_EFI_GPT_EVENT): "GPT",
}


def _uefi_var_name(event_data: bytes) -> str | None:
    """Extract the UEFI variable name from a VARIABLE event's raw data."""
    if len(event_data) < 32:
        return None
    name_len = struct.unpack_from("<Q", event_data, 16)[0]
    return event_data[32 : 32 + name_len * 2].decode("utf-16-le", errors="replace")


def _is_computable(rtmr: int, event: EventLogEntry) -> bool:
    """Return True if this event's digest can be computed from inputs."""
    if rtmr == 2:
        return True
    if (rtmr, event.event_type) in _COMPUTABLE:
        return True
    if rtmr == 0 and event.event_type == EV_EFI_VARIABLE_DRIVER_CONFIG:
        return _uefi_var_name(event.event_data) == "SecureBoot"
    return False


def _label_for_event(rtmr: int, event: EventLogEntry) -> str:
    override = _LABEL_OVERRIDES.get((rtmr, event.event_type))
    if override:
        return override
    if event.event_type in (EV_EFI_VARIABLE_DRIVER_CONFIG, EV_EFI_VARIABLE_BOOT):
        name = _uefi_var_name(event.event_data)
        if name:
            return name
    return event.event_type_name


def extract_from_ccel(ccel_data: bytes, machine_type: str) -> Baseline:
    """Extract a baseline from a CCEL binary.

    SecureBoot is stored as a boolean; all other non-computable events
    are stored as pre-hashed SHA-384 digests.
    """
    log = parse_event_log(ccel_data)
    baseline = Baseline(
        machine_type=machine_type,
        provider=_infer_provider(machine_type),
        platform="tdx",
    )

    for event in log.measurable_events:
        rtmr = event.imr_index

        if (
            rtmr == 0
            and event.event_type == EV_EFI_VARIABLE_DRIVER_CONFIG
            and _uefi_var_name(event.event_data) == "SecureBoot"
        ):
            raw = event.event_data
            name_len = struct.unpack_from("<Q", raw, 16)[0]
            data_len = struct.unpack_from("<Q", raw, 24)[0]
            offset = 32 + name_len * 2
            baseline.secureboot_enabled = raw[offset : offset + data_len] != b"\x00"

        d = event.digests.get(TPM_ALG_SHA384)
        if d is None or _is_computable(rtmr, event):
            continue

        baseline.events.append(BaselineEvent(
            rtmr=rtmr,
            event_type=event.event_type_name,
            label=_label_for_event(rtmr, event),
            digest=d.hex(),
        ))

    return baseline
