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

"""Azure SEV-SNP vTPM PCR computation.

Computes the PCRs an Azure confidential VM should report, from the pod VM
disk image and, for PCR 8, the deployment's initdata. No firmware input and
no baseline: Azure publishes no firmware blob, and every event in these five
registers is either a TCG-defined constant or a function of image bytes.

Each register extend is PCR := SHA-256(PCR || digest), from 32 zero bytes.

What is deliberately not computed, because none of it is a property of the
image:

  - **PCR 0** measures Azure's own firmware blob and its S-CRTM version.
  - **PCR 1, 2, 3** hold a separator and nothing else on this platform,
    because Azure's firmware measures no boot variables on the
    removable-media path. That absence is Azure's boot configuration, not
    ours to predict.
  - **PCR 6** measures the per-VM vmUniqueId, assigned at deployment.
  - **PCR 7** measures Azure's Secure Boot variables. Secure Boot is off on
    this image, so it records SecureBoot = 0 plus Azure's certificate
    databases, which move with Azure's firmware.
  - **PCR 10** is IMA, which extends with ima-ng template hashes and keeps
    growing as files are measured, so it has no final value to predict.

Pinning PCR 0, 6 or 7 would break attestation the moment Microsoft updates
firmware. The firmware is pinned in policy by the SNP report's ID key digest
instead, which identifies Microsoft as the signer and survives updates.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

from ..initdata import compute_digest
from ..tdx.pe import pe_authenticode_digest, pe_extract_section
from ..uki import measured_sections

SHA256_SIZE = 32

SEPARATOR_DIGEST = hashlib.sha256(struct.pack("<I", 0)).digest()

# TCG-defined EV_EFI_ACTION strings, hashed as ASCII with no NUL terminator.
EFI_ACTION_DIGESTS = {
    name: hashlib.sha256(name.encode("ascii")).digest()
    for name in [
        "Calling EFI Application from Boot Option",
        "Exit Boot Services Invocation",
        "Exit Boot Services Returned with Success",
    ]
}


def extend(current: bytes, digest: bytes) -> bytes:
    """Single PCR extend: SHA-256(current || digest)."""
    return hashlib.sha256(current + digest).digest()


def replay_digests(digests: list[bytes]) -> bytes:
    """Replay a sequence of raw SHA-256 digests from an initial zero state."""
    pcr = bytes(SHA256_SIZE)
    for digest in digests:
        pcr = extend(pcr, digest)
    return pcr


@dataclass
class ComputedPcrs:
    """The Azure SEV-SNP vTPM PCRs this tool computes, as hex strings."""

    pcr4: str
    pcr5: str
    pcr8: str
    pcr9: str
    pcr11: str

    def as_dict(self) -> dict[str, str]:
        return {
            "pcr4": self.pcr4,
            "pcr5": self.pcr5,
            "pcr8": self.pcr8,
            "pcr9": self.pcr9,
            "pcr11": self.pcr11,
        }


def compute_all(
    uki: bytes,
    gpt_event_data: bytes,
    *,
    initdata: Path | bytes | None = None,
    pcr8_hex: str | None = None,
) -> ComputedPcrs:
    """Compute PCR 4, 5, 8, 9 and 11 offline.

    Args:
        uki: Raw UKI (BOOTX64.EFI) bytes.
        gpt_event_data: EV_EFI_GPT_EVENT data, from disk.gpt_event_data().
        initdata: The deployment's CoCo initdata, as a Path or as the TOML
            bytes. PCR 8 is derived from it.
        pcr8_hex: PCR 8 as a pre-computed hex string, for a caller who has the
            register value but not the initdata behind it.

    With neither initdata nor pcr8_hex, PCR 8 is reported as zeros, which is
    what the register holds when no initdata was supplied to the deployment.
    """
    return ComputedPcrs(
        pcr4=_compute_pcr4(uki),
        pcr5=_compute_pcr5(gpt_event_data),
        pcr8=_resolve_pcr8(initdata, pcr8_hex),
        pcr9=_compute_pcr9(uki),
        pcr11=_compute_pcr11(uki),
    )


def _resolve_pcr8(initdata: Path | bytes | None, pcr8_hex: str | None) -> str:
    """Settle PCR 8 from whichever form of it the caller supplied."""
    if initdata is not None and pcr8_hex is not None:
        raise ValueError(
            "Pass either initdata or pcr8_hex, not both. They are two ways to "
            "state the same register, and nothing here can tell you which one "
            "to believe if they disagree."
        )
    if initdata is not None:
        return compute_pcr8(compute_digest(initdata))
    if pcr8_hex is not None:
        return digest_from_hex(pcr8_hex, "pcr8").hex()
    return bytes(SHA256_SIZE).hex()


def digest_from_hex(value: str, what: str) -> bytes:
    """Decode a caller-supplied SHA-256 hex string, rejecting anything else."""
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{what} is not valid hex: {value!r}") from exc
    if len(raw) != SHA256_SIZE:
        raise ValueError(
            f"{what} must be a {SHA256_SIZE}-byte SHA-256 digest "
            f"({SHA256_SIZE * 2} hex chars), got {len(raw)} bytes"
        )
    return raw


def _compute_pcr4(uki: bytes) -> str:
    """Compute PCR 4, the boot chain, from the UKI.

    Event order (4 total):
      1. EV_EFI_ACTION   "Calling EFI Application from Boot Option"
      2. EV_SEPARATOR    SHA-256(0u32)
      3. EV_EFI_BOOT_SERVICES_APPLICATION  Authenticode over the whole UKI
      4. EV_EFI_BOOT_SERVICES_APPLICATION  Authenticode over its .linux
                                           section, loaded as its own PE

    Event 3 is the only measurement of the systemd-stub code itself. PCR 11
    covers the payload sections systemd-stub recognises, but not .text,
    .rodata, .data or the PE headers, so a swapped stub with identical
    payloads moves PCR 4 and nothing else.

    Event 4 is the kernel systemd-stub loads out of .linux, which firmware
    measures as a second boot application. A UKI without that section boots
    some other way and produces a different event sequence, so it is
    rejected rather than measured as if it were its own kernel.
    """
    kernel = pe_extract_section(uki, ".linux", use_virtual_size=True)
    if kernel is None:
        raise ValueError(
            "UKI has no .linux section, so there is no embedded kernel for "
            "firmware to measure as the second boot application. PCR 4 for a "
            "boot chain like that is not something this tool can reconstruct."
        )

    return replay_digests(
        [
            EFI_ACTION_DIGESTS["Calling EFI Application from Boot Option"],
            SEPARATOR_DIGEST,
            pe_authenticode_digest(uki, "sha256"),
            pe_authenticode_digest(kernel, "sha256"),
        ]
    ).hex()


def _compute_pcr5(gpt_event_data: bytes) -> str:
    """Compute PCR 5, the partition table, from the disk's GPT.

    Event order (4 total):
      1. EV_SEPARATOR      SHA-256(0u32)
      2. EV_EFI_GPT_EVENT  SHA-256(EFI_GPT_DATA)
      3. EV_EFI_ACTION     "Exit Boot Services Invocation"
      4. EV_EFI_ACTION     "Exit Boot Services Returned with Success"

    Only valid for a VM's first boot. The release image ships
    /usr/lib/repart.d/30-scratch.conf, so systemd-repart appends a
    trusted_store partition on first boot, changing the table this register
    measures. The stock unit passes no --seed and /etc/machine-id reads
    'uninitialized' on a read-only squashfs, so that partition's UUID is
    random on every boot and PCR 5 is unpredictable afterwards rather than
    merely different. Pod VMs are created per pod and destroyed, so first
    boot is the normal case, but whether to pin this register is a policy
    decision.
    """
    return replay_digests(
        [
            SEPARATOR_DIGEST,
            hashlib.sha256(gpt_event_data).digest(),
            EFI_ACTION_DIGESTS["Exit Boot Services Invocation"],
            EFI_ACTION_DIGESTS["Exit Boot Services Returned with Success"],
        ]
    ).hex()


def compute_pcr8(initdata_digest: bytes) -> str:
    """Compute PCR 8, which binds the CoCo initdata, from its digest.

    One event, and it appears in no event log: process-user-data extends this
    register from userspace with tpm2_pcrextend after the firmware log is
    closed.

    **The digest is truncated to 32 bytes, not re-hashed.** This is what the
    initdata spec prescribes for a digest wider than the field binding it: it
    says to truncate the excess bytes off the end, and a SHA-256 PCR is a
    32-byte field. The unit shipped in the image implements that by reading
    the hex digest and keeping the first 64 characters:

        tpm2_pcrextend 8:sha256=$(head -c64 /run/peerpod/initdata.digest)

    So for the usual sha384 initdata the register holds
    SHA-256(0 || SHA-384(toml)[:32]), which is not SHA-256(0 || SHA-256(toml)).
    A sha256 initdata is already 32 bytes and nothing is cut.
    """
    if len(initdata_digest) < SHA256_SIZE:
        raise ValueError(
            f"initdata digest is {len(initdata_digest)} bytes, too short for the "
            f"{SHA256_SIZE}-byte value PCR 8 is extended with"
        )
    return extend(bytes(SHA256_SIZE), initdata_digest[:SHA256_SIZE]).hex()


def _compute_pcr9(uki: bytes) -> str:
    """Compute PCR 9, the command line and initrd, from the UKI.

    Event order (2 total), both logged by the Linux EFI stub as EV_EVENT_TAG
    records, though the digests are over the raw payloads rather than the
    tagged structures:
      1. SHA-256(UTF-16LE(cmdline) + 0x0000)   the stub's LoadOptions
      2. SHA-256(.ucode || .initrd)            the single blob it hands the
                                               kernel, microcode first

    This is where a dm-verity root hash reaches a verifier, since roothash=
    lives on the command line.
    """
    cmdline = uki_cmdline(uki)
    initrd = pe_extract_section(uki, ".initrd", use_virtual_size=True)
    if initrd is None:
        raise ValueError(
            "UKI has no .initrd section, so the Linux EFI stub measured "
            "something other than this tool models into PCR 9."
        )

    ucode = pe_extract_section(uki, ".ucode", use_virtual_size=True) or b""

    return replay_digests(
        [
            hashlib.sha256(cmdline.encode("utf-16-le") + b"\x00\x00").digest(),
            hashlib.sha256(ucode + initrd).digest(),
        ]
    ).hex()


def _compute_pcr11(uki: bytes) -> str:
    """Compute PCR 11, the UKI's identity, entirely from its sections.

    systemd-stub measures each section it recognises as two events, in the
    canonical order of UKI_MEASURED_SECTIONS rather than PE section order:
      1. SHA-256(section_name + '\\0')   the name as ASCII, NUL terminated
      2. SHA-256(section_content)        read at VirtualSize

    This is the same construction TDX folds into RTMR[2], at a different
    width.
    """
    digests = []
    for name, content in measured_sections(uki, register="PCR 11"):
        digests.append(hashlib.sha256((name + "\0").encode("ascii")).digest())
        digests.append(hashlib.sha256(content).digest())

    return replay_digests(digests).hex()


def uki_cmdline(uki: bytes) -> str:
    """The kernel command line as the EFI stub measures it.

    The .cmdline section is NUL-padded out to its virtual size, and the stub
    measures the string rather than the padding. An embedded NUL would end
    the string early for the stub while this tool went on measuring past it,
    so it is refused instead.
    """
    raw = pe_extract_section(uki, ".cmdline", use_virtual_size=True)
    if raw is None:
        raise ValueError(
            "UKI has no .cmdline section, so there is no command line for the "
            "EFI stub to measure into PCR 9."
        )

    stripped = raw.rstrip(b"\x00")
    if b"\x00" in stripped:
        raise ValueError(
            "UKI .cmdline contains an embedded NUL, which would terminate the "
            "command line early for the EFI stub but not for this tool."
        )
    try:
        return stripped.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "UKI .cmdline is not valid UTF-8, so the UTF-16 conversion the EFI "
            "stub measures cannot be reproduced."
        ) from exc


def roothash(uki: bytes) -> str | None:
    """The dm-verity root hash pinned on the command line, if there is one.

    Backs no register of its own: it is inside .cmdline and so already
    measured into PCR 9 and PCR 11 either way. Reported because reading it
    otherwise means hexdumping an 80 MB UKI.
    """
    for token in uki_cmdline(uki).split():
        if token.startswith(("roothash=", "usrhash=")):
            return token.split("=", 1)[1]
    return None
