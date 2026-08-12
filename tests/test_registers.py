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

"""Unit tests: offline register computation and constants."""

from __future__ import annotations

import hashlib
import struct

import pytest

from cvm_measure.tdx.registers import (
    EFI_ACTION_DIGESTS,
    SEPARATOR_DIGEST,
    UKI_MEASURED_SECTIONS,
    ComputedRegisters,
    _compute_rtmr2,
    compute_all,
)
from cvm_measure.tdx.rtmr import SHA384_SIZE, replay_digests

from .test_pe import build_pe


class TestConstants:

    def test_separator_digest_is_sha384_of_zero_u32(self) -> None:
        expected = hashlib.sha384(struct.pack("<I", 0)).digest()
        assert SEPARATOR_DIGEST == expected

    def test_efi_action_constants_correct(self) -> None:
        for name, digest in EFI_ACTION_DIGESTS.items():
            expected = hashlib.sha384(name.encode("ascii")).digest()
            assert digest == expected, f"EFI action constant mismatch for {name}"

    def test_separator_digest_length(self) -> None:
        assert len(SEPARATOR_DIGEST) == SHA384_SIZE


class TestFirmwareBaselinePairing:
    """A baseline describes one firmware image; mixing halves is meaningless."""

    def test_rejects_firmware_the_baseline_was_not_captured_from(
        self, firmware_a3, uki_a3, baseline_a3
    ) -> None:
        other_firmware = firmware_a3 + b"\x00"
        with pytest.raises(ValueError, match="different firmware"):
            compute_all(other_firmware, uki_a3, baseline_a3, ram_gib=234)

    def test_accepts_matching_firmware(self, firmware_a3, uki_a3, baseline_a3) -> None:
        assert baseline_a3.firmware_sha384 == hashlib.sha384(firmware_a3).hexdigest()
        compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234)

    def test_baseline_without_recorded_hash_is_allowed(
        self, firmware_a3, uki_a3, baseline_a3
    ) -> None:
        baseline_a3.firmware_sha384 = ""
        compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234)


class TestDigestValidation:

    @pytest.mark.parametrize("bad", ["xyz", "ab", "ab" * 47, "ab" * 49, ""])
    def test_rejects_malformed_rtmr3(
        self, firmware_a3, uki_a3, baseline_a3, bad
    ) -> None:
        with pytest.raises(ValueError, match="rtmr3"):
            compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234, rtmr3_hex=bad)

    def test_normalizes_rtmr3_to_lowercase(
        self, firmware_a3, uki_a3, baseline_a3
    ) -> None:
        regs = compute_all(
            firmware_a3, uki_a3, baseline_a3, ram_gib=234, rtmr3_hex="AB" * 48
        )
        assert regs.rtmr3 == "ab" * 48

    def test_rejects_malformed_gpt_digest(
        self, firmware_a3, uki_a3, baseline_a3
    ) -> None:
        with pytest.raises(ValueError, match="GPT digest"):
            compute_all(
                firmware_a3, uki_a3, baseline_a3, ram_gib=234, gpt_digest_hex="beef"
            )

    def test_rejects_malformed_baseline_digest(
        self, firmware_a3, uki_a3, baseline_a3
    ) -> None:
        for event in baseline_a3.events:
            if event.label == "dbx":
                event.digest = "not-hex"
        with pytest.raises(ValueError, match="baseline dbx digest"):
            compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234)


class TestUnsupportedUkiSections:
    """RTMR[2] must fail loudly rather than omit sections systemd measures."""

    @pytest.mark.parametrize(
        "section", [".splash", ".dtb", ".dtbauto", ".profile", ".hwids", ".efifw"]
    )
    def test_rejects_unmodelled_measured_section(self, section) -> None:
        uki = build_pe([
            (".linux", 16, 512, b"kernel"),
            (section, 16, 512, b"extra"),
        ])
        with pytest.raises(ValueError, match="does not model yet"):
            _compute_rtmr2(uki)

    def test_accepts_uki_with_only_modelled_sections(self) -> None:
        uki = build_pe([
            (".linux", 16, 512, b"kernel"),
            (".osrel", 16, 512, b"ID=cos"),
        ])
        assert len(_compute_rtmr2(uki)) == SHA384_SIZE * 2


class TestRTMR3:

    def test_rtmr3_extend(self) -> None:
        from cvm_measure.tdx.rtmr import extend_rtmr
        fake_digest = hashlib.sha384(b"test initdata").digest()
        result = extend_rtmr(bytes(SHA384_SIZE), fake_digest)
        expected = hashlib.sha384(bytes(SHA384_SIZE) + fake_digest).digest()
        assert result == expected

    def test_rtmr3_defaults_to_zeros(self) -> None:
        assert bytes(SHA384_SIZE).hex() == "0" * 96


class TestRTMR0FromCCEL:
    """Verify RTMR[0] computed from baseline + CCEL matches golden."""

    def test_rtmr0_matches_golden(self, baseline_a3, golden_a3, ccel_data_a3) -> None:
        from cvm_measure.tdx.ccel import TPM_ALG_SHA384, parse_event_log
        from cvm_measure.tdx.uefi import compute_secureboot_digest

        log = parse_event_log(ccel_data_a3)
        cfv_event = None
        for e in log.events_for_rtmr(0):
            if "PLATFORM_FIRMWARE" in e.event_type_name:
                cfv_event = e.digests.get(TPM_ALG_SHA384)
                if cfv_event:
                    break

        assert cfv_event is not None, "No CFV event found in CCEL"

        baseline_events = baseline_a3.rtmr_events(0)
        sb_flag_data = b"\x01" if baseline_a3.secureboot_enabled else b"\x00"

        digests = []
        bi = 0
        digests.append(bytes.fromhex(baseline_events[bi].digest))
        bi += 1
        digests.append(cfv_event)
        digests.append(compute_secureboot_digest("SecureBoot", sb_flag_data))
        for _ in range(4):
            digests.append(bytes.fromhex(baseline_events[bi].digest))
            bi += 1
        digests.append(SEPARATOR_DIGEST)
        while bi < len(baseline_events):
            digests.append(bytes.fromhex(baseline_events[bi].digest))
            bi += 1

        rtmr0 = replay_digests(digests).hex()
        assert rtmr0 == golden_a3.rtmr0

    def test_rtmr0_is_order_independent_for_fixed_events(
        self, firmware_a3, uki_a3, baseline_a3
    ) -> None:
        """TdxTable/PK/KEK/db/dbx are addressed by label, not position."""
        expected = compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234).rtmr0

        fixed = {"TdxTable", "PK", "KEK", "db", "dbx"}
        reordered = [e for e in baseline_a3.events if e.label in fixed]
        reordered.reverse()
        baseline_a3.events = reordered + [
            e for e in baseline_a3.events if e.label not in fixed
        ]

        actual = compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234).rtmr0
        assert actual == expected

    def test_rtmr0_rejects_baseline_missing_fixed_event(
        self, firmware_a3, uki_a3, baseline_a3
    ) -> None:
        baseline_a3.events = [e for e in baseline_a3.events if e.label != "dbx"]

        with pytest.raises(ValueError, match="missing required event"):
            compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234)

    def test_rtmr0_rejects_reordered_positional_events(
        self, firmware_a3, uki_a3, baseline_a3
    ) -> None:
        """ACPI and Boot events are replayed positionally, so order must match."""
        rtmr0 = [e for e in baseline_a3.events if e.rtmr == 0]
        boot_order = next(e for e in rtmr0 if e.label == "BootOrder")
        boot0000 = next(e for e in rtmr0 if e.label == "Boot0000")
        i, j = rtmr0.index(boot_order), rtmr0.index(boot0000)
        rtmr0[i], rtmr0[j] = rtmr0[j], rtmr0[i]
        baseline_a3.events = rtmr0 + [e for e in baseline_a3.events if e.rtmr != 0]

        with pytest.raises(ValueError, match="unsupported order"):
            compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234)

    def test_rtmr0_rejects_unrecognized_event_set(
        self, firmware_a3, uki_a3, baseline_a3
    ) -> None:
        """Other firmware measures a different sequence; fail instead of guessing."""
        extra = next(e for e in baseline_a3.events if e.label == "Boot0000")
        baseline_a3.events = [*baseline_a3.events, extra]

        with pytest.raises(ValueError, match="supported event set"):
            compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234)


class TestRTMR1FromCCEL:

    def test_rtmr1_from_constants_and_baseline(self, baseline_a3, golden_a3, ccel_data_a3) -> None:
        from cvm_measure.tdx.ccel import TPM_ALG_SHA384, parse_event_log

        log = parse_event_log(ccel_data_a3)
        rtmr1_events = log.events_for_rtmr(1)
        ccel_digests = [e.digests[TPM_ALG_SHA384] for e in rtmr1_events]
        gpt_digest = bytes.fromhex(baseline_a3.rtmr_events(1)[0].digest)

        digests = [
            EFI_ACTION_DIGESTS["Calling EFI Application from Boot Option"],
            SEPARATOR_DIGEST,
            gpt_digest,
            ccel_digests[3],
            ccel_digests[4],
            EFI_ACTION_DIGESTS["Exit Boot Services Invocation"],
            EFI_ACTION_DIGESTS["Exit Boot Services Returned with Success"],
        ]

        rtmr1 = replay_digests(digests).hex()
        assert rtmr1 == golden_a3.rtmr1

    def test_rtmr1_uses_gpt_digest_override(
        self, firmware_a3, uki_a3, baseline_a3
    ) -> None:
        gpt_digest = hashlib.sha384(b"image-specific gpt").digest()
        regs = compute_all(
            firmware_a3,
            uki_a3,
            baseline_a3,
            ram_gib=234,
            gpt_digest_hex=gpt_digest.hex(),
        )

        from cvm_measure.tdx.pe import pe_authenticode_digest, pe_extract_section

        kernel_data = pe_extract_section(uki_a3, ".linux", use_virtual_size=True)
        assert kernel_data is not None
        expected = replay_digests([
            EFI_ACTION_DIGESTS["Calling EFI Application from Boot Option"],
            SEPARATOR_DIGEST,
            gpt_digest,
            pe_authenticode_digest(uki_a3, "sha384"),
            pe_authenticode_digest(kernel_data, "sha384"),
            EFI_ACTION_DIGESTS["Exit Boot Services Invocation"],
            EFI_ACTION_DIGESTS["Exit Boot Services Returned with Success"],
        ]).hex()

        assert regs.rtmr1 == expected

    def test_rtmr1_without_gpt_requires_legacy_baseline_event(
        self, firmware_a3, uki_a3, baseline_a3
    ) -> None:
        import pytest

        baseline_a3.events = [e for e in baseline_a3.events if e.rtmr != 1]

        with pytest.raises(ValueError, match="--disk"):
            compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234)

    def test_rtmr1_does_not_mistake_another_event_for_gpt(
        self, firmware_a3, uki_a3, baseline_a3
    ) -> None:
        """A non-GPT RTMR[1] event must not be replayed in the GPT slot."""
        import pytest

        from cvm_measure.tdx.baseline import BaselineEvent

        baseline_a3.events = [e for e in baseline_a3.events if e.rtmr != 1] + [
            BaselineEvent(
                rtmr=1,
                event_type="EV_EFI_VARIABLE_BOOT",
                label="BootOrder",
                digest="cc" * 48,
            )
        ]

        with pytest.raises(ValueError, match="--disk"):
            compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234)


class TestRTMR2FromCCEL:

    def test_rtmr2_from_ccel_matches_golden(self, golden_a3, ccel_data_a3) -> None:
        from cvm_measure.tdx.ccel import TPM_ALG_SHA384, parse_event_log

        log = parse_event_log(ccel_data_a3)
        digests = [e.digests[TPM_ALG_SHA384] for e in log.events_for_rtmr(2)]
        rtmr2 = replay_digests(digests).hex()
        assert rtmr2 == golden_a3.rtmr2

    def test_rtmr2_section_name_digests_are_constants(self, ccel_data_a3) -> None:
        from cvm_measure.tdx.ccel import parse_event_log

        log = parse_event_log(ccel_data_a3)
        events = log.events_for_rtmr(2)
        sections = [".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"]

        for i, section in enumerate(sections):
            name_event = events[i * 2]
            from cvm_measure.tdx.ccel import TPM_ALG_SHA384
            expected = hashlib.sha384((section + "\0").encode("ascii")).digest()
            actual = name_event.digests[TPM_ALG_SHA384]
            assert actual == expected, f"Section name mismatch for {section}"


class TestComputedRegisters:

    def test_as_dict_keys(self) -> None:
        regs = ComputedRegisters(
            mrtd="a" * 96,
            rtmr0="b" * 96,
            rtmr1="c" * 96,
            rtmr2="d" * 96,
            rtmr3="e" * 96,
        )
        d = regs.as_dict()
        assert set(d.keys()) == {"mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"}


class TestUKIMeasuredSections:

    def test_section_list_is_ordered(self) -> None:
        assert UKI_MEASURED_SECTIONS == [
            ".linux",
            ".osrel",
            ".cmdline",
            ".initrd",
            ".ucode",
            ".uname",
            ".sbat",
            ".pcrpkey",
        ]


class TestComputeAll:
    """End-to-end register computation using firmware + UKI + baseline."""

    def test_compute_all_returns_registers(
        self, firmware_a3: bytes, uki_a3: bytes, baseline_a3, golden_a3
    ) -> None:
        regs = compute_all(
            firmware_a3,
            uki_a3,
            baseline_a3,
            ram_gib=234,
        )
        assert isinstance(regs, ComputedRegisters)
        assert len(regs.mrtd) == 96
        assert len(regs.rtmr0) == 96
        assert len(regs.rtmr1) == 96
        assert len(regs.rtmr2) == 96
        assert len(regs.rtmr3) == 96

    def test_mrtd_matches_golden(
        self, firmware_a3: bytes, uki_a3: bytes, baseline_a3, golden_a3
    ) -> None:
        regs = compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234)
        assert regs.mrtd == golden_a3.mrtd

    def test_rtmr0_matches_golden(
        self, firmware_a3: bytes, uki_a3: bytes, baseline_a3, golden_a3
    ) -> None:
        regs = compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234)
        assert regs.rtmr0 == golden_a3.rtmr0

    def test_rtmr2_matches_golden(
        self, firmware_a3: bytes, uki_a3: bytes, baseline_a3, golden_a3
    ) -> None:
        regs = compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234)
        assert regs.rtmr2 == golden_a3.rtmr2

    def test_rtmr3_defaults_to_zeros(
        self, firmware_a3: bytes, uki_a3: bytes, baseline_a3
    ) -> None:
        regs = compute_all(firmware_a3, uki_a3, baseline_a3, ram_gib=234)
        assert regs.rtmr3 == "0" * 96

    def test_rtmr3_with_custom_value(
        self, firmware_a3: bytes, uki_a3: bytes, baseline_a3
    ) -> None:
        custom = "ab" * 48
        regs = compute_all(
            firmware_a3, uki_a3, baseline_a3, ram_gib=234, rtmr3_hex=custom
        )
        assert regs.rtmr3 == custom
