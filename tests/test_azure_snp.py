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

"""Unit tests: Azure SEV-SNP vTPM PCR computation.

The oracle is a real VM. `azure_eventlog` is the firmware log it recorded and
`azure_golden` is the quote it signed, both from the same boot, so the tests
that use them check this tool against hardware rather than against itself.

Synthetic UKIs cover the parts a single real image cannot: section ordering,
what each register does and does not reach, and the refusals.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from cvm_measure.azure_snp import compute_all_pcrs, compute_pcr8
from cvm_measure.azure_snp.eventlog import parse_event_log, replay_event_log
from cvm_measure.azure_snp.registers import (
    EFI_ACTION_DIGESTS,
    SEPARATOR_DIGEST,
    replay_digests,
    roothash,
)
from cvm_measure.initdata import compute_digest
from cvm_measure.tcg import (
    EV_EFI_ACTION,
    EV_EFI_BOOT_SERVICES_APPLICATION,
    EV_EFI_GPT_EVENT,
    EV_EVENT_TAG,
    EV_IPL,
    EV_SEPARATOR,
    TPM_ALG_SHA256,
)

from .test_disk import _build_measurable_gpt_disk
from .test_pe import build_pe

# The event sequence each register is built from, as the live firmware
# recorded it. These are the recipes the _compute_pcrN docstrings describe;
# pinning them here is what catches a recipe drifting away from reality.
LIVE_EVENT_SEQUENCES = {
    4: [
        EV_EFI_ACTION,                      # "Calling EFI Application..."
        EV_SEPARATOR,
        EV_EFI_BOOT_SERVICES_APPLICATION,   # the UKI
        EV_EFI_BOOT_SERVICES_APPLICATION,   # its .linux, as its own PE
    ],
    5: [
        EV_SEPARATOR,
        EV_EFI_GPT_EVENT,
        EV_EFI_ACTION,                      # "Exit Boot Services Invocation"
        EV_EFI_ACTION,                      # "...Returned with Success"
    ],
    9: [EV_EVENT_TAG, EV_EVENT_TAG],        # LoadOptions, then ucode||initrd
    11: [EV_IPL] * 14,                      # 7 measured sections, name + content
}


def build_uki(
    *,
    cmdline: bytes = b"console=ttyS0",
    initrd: bytes = b"initrd-payload",
    ucode: bytes = b"ucode-payload",
    text: bytes = b"stub-code",
    extra: dict[str, bytes] | None = None,
    order: list[str] | None = None,
) -> bytes:
    """A synthetic UKI whose .linux section is itself a valid PE."""
    kernel = build_pe([(".text", 16, 16, b"kernel-payload!!")])
    sections: dict[str, bytes] = {
        ".text": text,
        ".linux": kernel,
        ".osrel": b'ID=test\n',
        ".cmdline": cmdline,
        ".initrd": initrd,
        ".ucode": ucode,
        ".uname": b"6.17.0-test",
        ".sbat": b"sbat,1\n",
    }
    sections.update(extra or {})

    names = order if order is not None else list(sections)
    return build_pe(
        [(name, len(sections[name]), len(sections[name]), sections[name]) for name in names]
    )


def gpt_event_data_for(disk_header: bytes, entries: list[bytes]) -> bytes:
    """The EFI_GPT_DATA layout, spelled out rather than imported."""
    return disk_header + len(entries).to_bytes(8, "little") + b"".join(entries)


class TestLiveEventLog:
    """Replaying the firmware log has to land on the register values the
    hardware signed. This exercises the parser and the SHA-256 replay."""

    def test_replays_to_the_signed_quote(self, azure_eventlog, azure_golden) -> None:
        pcrs = replay_event_log(parse_event_log(azure_eventlog))

        replayed = {f"pcr{i}": value.hex() for i, value in pcrs.items()}
        expected = {k: v for k, v in azure_golden.items() if k in replayed}

        assert replayed == expected
        assert len(expected) == 10, "expected PCRs 0-7, 9 and 11 in the log"

    def test_pcr8_is_absent_because_userspace_extends_it(self, azure_eventlog) -> None:
        log = parse_event_log(azure_eventlog)
        assert log.events_for_pcr(8) == []
        assert "pcr8" not in {f"pcr{i}" for i in replay_event_log(log)}


class TestRecipesAgainstLiveLog:
    """The event sequences the register functions model, checked against the
    sequence the firmware actually measured."""

    @pytest.mark.parametrize("pcr,event_types", LIVE_EVENT_SEQUENCES.items())
    def test_event_sequence_matches(self, azure_eventlog, pcr, event_types) -> None:
        log = parse_event_log(azure_eventlog)
        assert [e.event_type for e in log.events_for_pcr(pcr)] == event_types

    def test_sequences_fold_to_the_signed_quote(
        self, azure_eventlog, azure_golden
    ) -> None:
        log = parse_event_log(azure_eventlog)
        for pcr in LIVE_EVENT_SEQUENCES:
            digests = [e.digests[TPM_ALG_SHA256] for e in log.events_for_pcr(pcr)]
            assert replay_digests(digests).hex() == azure_golden[f"pcr{pcr}"]

    def test_hardcoded_constants_match_the_firmware(self, azure_eventlog) -> None:
        """The TCG action strings and separator we hardcode are the ones
        Azure's firmware measured, byte for byte."""
        log = parse_event_log(azure_eventlog)
        pcr4 = [e.digests[TPM_ALG_SHA256] for e in log.events_for_pcr(4)]
        pcr5 = [e.digests[TPM_ALG_SHA256] for e in log.events_for_pcr(5)]

        assert pcr4[0] == EFI_ACTION_DIGESTS["Calling EFI Application from Boot Option"]
        assert pcr4[1] == SEPARATOR_DIGEST
        assert pcr5[0] == SEPARATOR_DIGEST
        assert pcr5[2] == EFI_ACTION_DIGESTS["Exit Boot Services Invocation"]
        assert pcr5[3] == EFI_ACTION_DIGESTS["Exit Boot Services Returned with Success"]


class TestPcr11:

    def test_measures_sections_in_systemd_order_not_pe_order(self) -> None:
        """systemd-stub walks its UnifiedSection enum, so shuffling the PE
        section table must not move PCR 11."""
        forward = build_uki()
        shuffled = build_uki(
            order=[".sbat", ".uname", ".ucode", ".initrd", ".cmdline", ".osrel", ".linux", ".text"]
        )
        assert compute_pcrs(shuffled).pcr11 == compute_pcrs(forward).pcr11

    def test_measures_each_section_as_name_then_content(self) -> None:
        uki = build_uki(extra={".osrel": b"ID=probe\n"})
        expected = hashlib.sha256((".osrel" + "\0").encode("ascii")).digest()

        # The name digest is ASCII with one NUL, not UTF-16 as the log's
        # event data renders it.
        assert expected != hashlib.sha256(".osrel".encode("utf-16-le")).digest()
        assert _pcr11_digests(uki)[2] == expected
        assert _pcr11_digests(uki)[3] == hashlib.sha256(b"ID=probe\n").digest()


class TestPcr9:

    def test_measures_the_cmdline_as_utf16_with_a_terminator(self) -> None:
        # printf 'console=ttyS0' | iconv -t UTF-16LE | { cat; printf '\0\0'; } \
        #   | sha256sum
        expected = "884260a63f4a899f7d02781f726818e187e6e9554e4c418f08e38cc37fea763e"
        assert (
            hashlib.sha256("console=ttyS0".encode("utf-16-le") + b"\x00\x00").hexdigest()
            == expected
        )

        uki = build_uki(cmdline=b"console=ttyS0")
        assert compute_pcrs(uki).pcr9 == replay_digests(
            [
                bytes.fromhex(expected),
                hashlib.sha256(b"ucode-payload" + b"initrd-payload").digest(),
            ]
        ).hex()

    def test_ignores_the_nul_padding_on_the_cmdline_section(self) -> None:
        """The section is NUL-padded to its virtual size; the stub measures
        the string, not the padding."""
        kernel = build_pe([(".text", 16, 16, b"kernel-payload!!")])
        padded = build_pe(
            [
                (".linux", len(kernel), len(kernel), kernel),
                (".cmdline", 32, 13, b"console=ttyS0"),
                (".initrd", 14, 14, b"initrd-payload"),
                (".ucode", 13, 13, b"ucode-payload"),
            ]
        )
        expected = hashlib.sha256(
            "console=ttyS0".encode("utf-16-le") + b"\x00\x00"
        ).digest()
        assert _pcr9_digests(padded)[0] == expected

    def test_puts_microcode_ahead_of_the_initrd(self) -> None:
        with_ucode = build_uki(ucode=b"AB", initrd=b"CD")
        swapped = build_uki(ucode=b"CD", initrd=b"AB")
        assert compute_pcrs(with_ucode).pcr9 != compute_pcrs(swapped).pcr9
        assert _pcr9_digests(with_ucode)[1] == hashlib.sha256(b"ABCD").digest()


class TestPcr4:

    def test_covers_stub_code_that_pcr11_never_reaches(self) -> None:
        """The reason PCR 4 is worth pinning: swap the systemd-stub binary
        while every measured payload stays identical, and PCR 4 is the only
        register that moves."""
        v1 = compute_pcrs(build_uki(text=b"stub-v1"))
        v2 = compute_pcrs(build_uki(text=b"stub-v2"))

        assert v1.pcr9 == v2.pcr9
        assert v1.pcr11 == v2.pcr11
        assert v1.pcr4 != v2.pcr4

    def test_measures_the_inner_kernel_separately(self) -> None:
        base = build_uki()
        other_kernel = build_pe(
            [
                (name, len(data), len(data), data)
                for name, data in {
                    ".text": b"stub-code",
                    ".linux": build_pe([(".text", 16, 16, b"OTHER-payload!!!")]),
                    ".osrel": b"ID=test\n",
                    ".cmdline": b"console=ttyS0",
                    ".initrd": b"initrd-payload",
                    ".ucode": b"ucode-payload",
                    ".uname": b"6.17.0-test",
                    ".sbat": b"sbat,1\n",
                }.items()
            ]
        )
        assert compute_pcrs(base).pcr4 != compute_pcrs(other_kernel).pcr4


class TestPcr5:

    def test_folds_the_gpt_event_data(self) -> None:
        _, header, entries = _build_measurable_gpt_disk(num_entries=8, non_empty=3)
        event_data = gpt_event_data_for(header, entries)

        expected = replay_digests(
            [
                SEPARATOR_DIGEST,
                hashlib.sha256(event_data).digest(),
                EFI_ACTION_DIGESTS["Exit Boot Services Invocation"],
                EFI_ACTION_DIGESTS["Exit Boot Services Returned with Success"],
            ]
        ).hex()
        assert compute_all_pcrs(build_uki(), event_data).pcr5 == expected

    def test_tracks_the_partition_table(self) -> None:
        _, header_a, entries_a = _build_measurable_gpt_disk(non_empty=2)
        _, header_b, entries_b = _build_measurable_gpt_disk(non_empty=3)
        uki = build_uki()

        assert (
            compute_all_pcrs(uki, gpt_event_data_for(header_a, entries_a)).pcr5
            != compute_all_pcrs(uki, gpt_event_data_for(header_b, entries_b)).pcr5
        )


class TestPcr8:

    def test_dummy_initdata_reproduces_the_live_register(
        self, azure_initdata, azure_golden
    ) -> None:
        """End to end against hardware: the initdata this VM ran, hashed and
        extended, is the PCR 8 in its quote."""
        digest = compute_digest(azure_initdata)
        assert digest.hex() == azure_golden["initdata_digest"]
        assert compute_pcr8(digest) == azure_golden["pcr8"]

    def test_initdata_argument_reaches_the_same_register(
        self, azure_initdata, azure_golden
    ) -> None:
        """The one-step form callers are meant to use has to agree with the
        hand-composed one, and with the live quote."""
        assert compute_pcrs(build_uki(), initdata=azure_initdata).pcr8 == azure_golden["pcr8"]

    def test_accepts_toml_bytes_as_well_as_a_path(self, azure_initdata) -> None:
        """Initdata arrives as a pod annotation, so a caller may never have a
        file to point at."""
        from_path = compute_pcrs(build_uki(), initdata=azure_initdata)
        from_bytes = compute_pcrs(build_uki(), initdata=azure_initdata.read_bytes())
        assert from_bytes.pcr8 == from_path.pcr8

    def test_refuses_initdata_and_pcr8_together(self, azure_initdata) -> None:
        with pytest.raises(ValueError, match="not both"):
            compute_pcrs(build_uki(), initdata=azure_initdata, pcr8_hex="ab" * 32)

    def test_truncates_a_longer_digest_instead_of_rehashing(
        self, tmp_path: Path
    ) -> None:
        """The CAA unit runs `head -c64` over a hex digest, so a sha384
        initdata is cut to 32 bytes. Re-hashing it would be the natural
        implementation and the wrong answer."""
        toml = b'algorithm = "sha384"\nversion = "0.1.0"\n'
        path = tmp_path / "initdata.toml"
        path.write_bytes(toml)

        full = hashlib.sha384(toml).digest()
        assert compute_pcr8(compute_digest(path)) == hashlib.sha256(
            bytes(32) + full[:32]
        ).hexdigest()
        assert compute_pcr8(compute_digest(path)) != hashlib.sha256(
            bytes(32) + hashlib.sha256(toml).digest()
        ).hexdigest()

    def test_defaults_to_zero_without_initdata(self) -> None:
        _, header, entries = _build_measurable_gpt_disk()
        pcrs = compute_all_pcrs(build_uki(), gpt_event_data_for(header, entries))
        assert pcrs.pcr8 == "00" * 32

    def test_rejects_a_digest_too_short_to_extend(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            compute_pcr8(hashlib.sha1(b"nope").digest())


class TestRootHash:

    def test_reads_the_verity_hash_off_the_cmdline(self) -> None:
        uki = build_uki(cmdline=b"console=ttyS0 roothash=abc123 ro")
        assert roothash(uki) == "abc123"

    def test_absent_when_the_image_pins_none(self) -> None:
        assert roothash(build_uki(cmdline=b"console=ttyS0")) is None


class TestRefusals:

    def test_uki_without_a_linux_section(self) -> None:
        uki = build_pe([(".cmdline", 13, 13, b"console=ttyS0")])
        with pytest.raises(ValueError, match="no .linux section"):
            compute_pcrs(uki)

    def test_uki_without_a_cmdline_section(self) -> None:
        uki = build_uki(order=[".text", ".linux", ".osrel", ".initrd", ".ucode"])
        with pytest.raises(ValueError, match="no .cmdline section"):
            compute_pcrs(uki)

    def test_cmdline_with_an_embedded_nul(self) -> None:
        uki = build_uki(cmdline=b"console=ttyS0\x00quiet")
        with pytest.raises(ValueError, match="embedded NUL"):
            compute_pcrs(uki)

    def test_cmdline_that_is_not_utf8(self) -> None:
        uki = build_uki(cmdline=b"console=\xff\xfe")
        with pytest.raises(ValueError, match="not valid UTF-8"):
            compute_pcrs(uki)

    def test_uki_with_a_profile_section(self) -> None:
        uki = build_uki(extra={".profile": b"ID=profile-a\n"})
        with pytest.raises(ValueError, match="PCR 11"):
            compute_pcrs(uki)


# -- helpers -------------------------------------------------------------------


def compute_pcrs(uki: bytes, **kwargs):
    """Compute against a fixed throwaway GPT, for tests about the UKI."""
    _, header, entries = _build_measurable_gpt_disk()
    return compute_all_pcrs(uki, gpt_event_data_for(header, entries), **kwargs)


def _pcr11_digests(uki: bytes) -> list[bytes]:
    from cvm_measure.uki import measured_sections

    digests = []
    for name, content in measured_sections(uki, register="PCR 11"):
        digests.append(hashlib.sha256((name + "\0").encode("ascii")).digest())
        digests.append(hashlib.sha256(content).digest())
    return digests


def _pcr9_digests(uki: bytes) -> list[bytes]:
    from cvm_measure.azure_snp.registers import uki_cmdline
    from cvm_measure.tdx.pe import pe_extract_section

    cmdline = uki_cmdline(uki)
    ucode = pe_extract_section(uki, ".ucode", use_virtual_size=True) or b""
    initrd = pe_extract_section(uki, ".initrd", use_virtual_size=True) or b""
    return [
        hashlib.sha256(cmdline.encode("utf-16-le") + b"\x00\x00").digest(),
        hashlib.sha256(ucode + initrd).digest(),
    ]
