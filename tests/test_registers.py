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
    UKI_UNMEASURED_SECTION,
    ComputedRegisters,
    _compute_rtmr1,
    _compute_rtmr2,
    compute_all,
)
from cvm_measure.tdx.rtmr import SHA384_SIZE, replay_digests

from .test_pe import build_pe, stub_magic


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


class TestUkiSectionCoverage:
    """Every section systemd measures has to reach RTMR[2]."""

    @pytest.mark.parametrize(
        "section", [".splash", ".dtb", ".dtbauto", ".hwids", ".efifw", ".ucode"]
    )
    def test_optional_section_changes_the_register(self, section) -> None:
        """A section systemd measures cannot be silently left out."""
        without = _compute_rtmr2(build_pe([(".linux", 16, 512, b"kernel")]))
        with_section = _compute_rtmr2(build_pe([
            (".linux", 16, 512, b"kernel"),
            (section, 16, 512, b"extra"),
        ]))
        assert with_section != without

    def test_measures_in_canonical_order_not_section_table_order(self) -> None:
        """systemd walks its own enum, so the PE table order must not matter."""
        sections = [
            (".sbat", 16, 512, b"sbat"),
            (".linux", 16, 512, b"kernel"),
            (".uname", 16, 512, b"6.8.0"),
            (".osrel", 16, 512, b"ID=cos"),
        ]
        shuffled = [sections[1], sections[3], sections[2], sections[0]]
        assert _compute_rtmr2(build_pe(sections)) == _compute_rtmr2(build_pe(shuffled))

    def test_expected_digest_sequence(self) -> None:
        """.splash sits between .ucode and .uname, per systemd's enum."""
        uki = build_pe([
            (".uname", 16, 512, b"6.8.0"),
            (".splash", 16, 512, b"png"),
            (".ucode", 16, 512, b"microcode"),
        ])
        expected = []
        for name, content in [
            (".ucode", b"microcode"),
            (".splash", b"png"),
            (".uname", b"6.8.0"),
        ]:
            expected.append(hashlib.sha384((name + "\0").encode("ascii")).digest())
            expected.append(hashlib.sha384(content.ljust(16, b"\x00")).digest())
        assert _compute_rtmr2(uki) == replay_digests(expected).hex()

    def test_pcrsig_is_not_measured(self) -> None:
        """.pcrsig signs the expected result, so systemd keeps it out."""
        without = _compute_rtmr2(build_pe([(".linux", 16, 512, b"kernel")]))
        with_pcrsig = _compute_rtmr2(build_pe([
            (".linux", 16, 512, b"kernel"),
            (UKI_UNMEASURED_SECTION, 16, 512, b"sig"),
        ]))
        assert with_pcrsig == without

    def test_rejects_multi_profile_uki(self) -> None:
        uki = build_pe([
            (".linux", 16, 512, b"kernel"),
            (".profile", 16, 512, b"ID=default"),
        ])
        with pytest.raises(ValueError, match="which profile is selected"):
            _compute_rtmr2(uki)

    def test_rejects_repeated_measured_section(self) -> None:
        uki = build_pe([
            (".linux", 16, 512, b"kernel"),
            (".cmdline", 16, 512, b"quiet"),
            (".cmdline", 16, 512, b"debug"),
        ])
        with pytest.raises(ValueError, match="repeats measured section"):
            _compute_rtmr2(uki)


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

    def test_hardware_log_records_the_golden_boot_application_digests(
        self, ccel_data_a3: bytes, golden_a3
    ) -> None:
        from cvm_measure.tdx.ccel import (
            EV_EFI_BOOT_SERVICES_APPLICATION,
            TPM_ALG_SHA384,
            parse_event_log,
        )

        log = parse_event_log(ccel_data_a3)
        recorded = [
            e.digests[TPM_ALG_SHA384].hex()
            for e in log.events_for_rtmr(1)
            if e.event_type == EV_EFI_BOOT_SERVICES_APPLICATION
        ]
        assert recorded == [golden_a3.uki_image_digest, golden_a3.kernel_image_digest]

    def test_boot_application_digests_match_the_hardware_log(
        self, uki_a3: bytes, golden_a3
    ) -> None:
        """Pin the two RTMR[1] image measurements to what a real VM recorded.

        EDK2 measures the PE image it loaded, and this hashes bytes taken out
        of the file. The fixtures are a matched pair, one boot of one image, so
        equality here is what says the two agree for a UKI and for the kernel
        systemd-stub loads out of its .linux section.
        """
        from cvm_measure.tdx.pe import pe_authenticode_digest, pe_extract_section

        kernel = pe_extract_section(uki_a3, ".linux", use_virtual_size=True)
        assert kernel is not None
        assert pe_authenticode_digest(uki_a3, "sha384").hex() == (
            golden_a3.uki_image_digest
        )
        assert pe_authenticode_digest(kernel, "sha384").hex() == (
            golden_a3.kernel_image_digest
        )

    def test_rtmr1_requires_an_embedded_kernel(self, baseline_a3) -> None:
        """A UKI with no .linux section boots differently; do not guess."""
        uki = build_pe([(".osrel", 16, 512, b"ID=cos")])
        with pytest.raises(ValueError, match="no .linux section"):
            _compute_rtmr1(uki, baseline_a3)

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

    def test_matches_systemd_canonical_order(self) -> None:
        """From the UnifiedSection enum in systemd's src/fundamental/uki.h."""
        assert UKI_MEASURED_SECTIONS == [
            ".linux",
            ".osrel",
            ".cmdline",
            ".initrd",
            ".ucode",
            ".splash",
            ".dtb",
            ".uname",
            ".sbat",
            ".pcrpkey",
            ".profile",
            ".dtbauto",
            ".hwids",
            ".efifw",
        ]

    def test_pcrsig_is_the_only_section_systemd_skips(self) -> None:
        assert UKI_UNMEASURED_SECTION not in UKI_MEASURED_SECTIONS


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


# RTMR[1] event digests read out of the CCEL of two GCP c3-standard-4 TDX
# boots of the same PodVM image, one built with systemd-stub 256.5 and one with
# 259.5. Their UKI and GPT digests differ because the images differ; the inner
# kernel is the same file. Firmware logged the kernel for v256 and not for v259.
_CCEL_STUB256_RTMR1 = [
    "77a0dab2312b4e1e57a84d865a21e5b2ee8d677a21012ada819d0a98988078d3d740f6346bfe0abaa938ca20439a8d71",
    "394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0",
    "b02c9272c2faa42ec3bd9b1f9dd4fac5ca662bbcd48951db64f50ffdae42927d6c4ea00baf37e81f173be93bc27a3d60",
    "5f2f6aa33cd0283a102aee22e65abe1e4ca337462d00cc776b56bb56e1998c1f99abf6889d795c9ffa98166f449bd216",
    "19fc2880c1a79028127ca0b8bcebcfc9c1f0245dcbacea6fb83d2ac777ebe5ae4376f5f3b2e03f569df24cfa5d26c822",
    "214b0bef1379756011344877743fdc2a5382bac6e70362d624ccf3f654407c1b4badf7d8f9295dd3dabdef65b27677e0",
    "0a2e01c85deae718a530ad8c6d20a84009babe6c8989269e950d8cf440c6e997695e64d455c4174a652cd080f6230b74",
]
_CCEL_STUB256_RTMR1_VALUE = "b6930ca0f87c3ea2fc27e55443e3c00140684a7668c424eb9e884767ecc5ff76417a2e9ef3f81994a0d0b0897b7e55a3"
_CCEL_STUB259_RTMR1 = [
    "77a0dab2312b4e1e57a84d865a21e5b2ee8d677a21012ada819d0a98988078d3d740f6346bfe0abaa938ca20439a8d71",
    "394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0",
    "34402e0a8de839da579889204461b7f1edbd2bbec24aa1ca8039e7069cbd99a64bb1c726a9fe9fe32ab04b2ab30e0992",
    "1ff5e53a4cc1b0bb4bd7b5a90a884e29735be2db19c43adc36274c1bd93b496b020d822e31574265c79834fc009794bb",
    "214b0bef1379756011344877743fdc2a5382bac6e70362d624ccf3f654407c1b4badf7d8f9295dd3dabdef65b27677e0",
    "0a2e01c85deae718a530ad8c6d20a84009babe6c8989269e950d8cf440c6e997695e64d455c4174a652cd080f6230b74",
]
_CCEL_STUB259_RTMR1_VALUE = "1e5b26e03ed853c4d27c4cedd02cbd66434c5de382c79f82c1cfaf4c0085c15597a6be0514711d108c389228540ccfe6"


class TestRTMR1StubVersions:
    """systemd-stub v258 stopped loading the kernel through firmware."""

    @staticmethod
    def _uki(stub_major: int) -> bytes:
        kernel = build_pe([(".text", 16, 16, b"kernel-payload!!")])
        sections = [
            (".text", 9, 512, b"stub-code"),
            (".sdmagic", 48, 512, stub_magic(stub_major)),
            (".osrel", 8, 512, b"ID=test\n"),
            (".linux", len(kernel), len(kernel), kernel),
        ]
        return build_pe(sections)

    def _expected(self, uki: bytes, gpt: bytes, with_kernel: bool) -> str:
        from cvm_measure.tdx.pe import pe_authenticode_digest, pe_extract_section

        apps = [pe_authenticode_digest(uki, "sha384")]
        if with_kernel:
            kernel = pe_extract_section(uki, ".linux", use_virtual_size=True)
            assert kernel is not None
            apps.append(pe_authenticode_digest(kernel, "sha384"))
        return replay_digests([
            EFI_ACTION_DIGESTS["Calling EFI Application from Boot Option"],
            SEPARATOR_DIGEST,
            gpt,
            *apps,
            EFI_ACTION_DIGESTS["Exit Boot Services Invocation"],
            EFI_ACTION_DIGESTS["Exit Boot Services Returned with Success"],
        ]).hex()

    @pytest.mark.parametrize(
        ("stub_major", "with_kernel"), [(255, True), (256, True), (257, True), (258, False), (259, False)]
    )
    def test_kernel_event_depends_on_stub_version(
        self, baseline_a3, stub_major: int, with_kernel: bool
    ) -> None:
        uki = self._uki(stub_major)
        gpt = hashlib.sha384(b"gpt").digest()
        assert _compute_rtmr1(uki, baseline_a3, gpt.hex()) == self._expected(
            uki, gpt, with_kernel
        )

    def test_refuses_a_uki_without_a_stub_version(self, baseline_a3) -> None:
        kernel = build_pe([(".text", 16, 16, b"kernel-payload!!")])
        uki = build_pe([(".linux", len(kernel), len(kernel), kernel)])
        with pytest.raises(ValueError, match="sdmagic"):
            _compute_rtmr1(uki, baseline_a3, "00" * 48)

    def test_refuses_v258_with_secure_boot(self, baseline_a3) -> None:
        baseline_a3.secureboot_enabled = True
        with pytest.raises(ValueError, match="shim"):
            _compute_rtmr1(self._uki(259), baseline_a3, "00" * 48)

    @pytest.mark.parametrize(
        ("events", "value"),
        [
            (_CCEL_STUB256_RTMR1, _CCEL_STUB256_RTMR1_VALUE),
            (_CCEL_STUB259_RTMR1, _CCEL_STUB259_RTMR1_VALUE),
        ],
    )
    def test_hardware_sequences_fold_to_their_quotes(self, events, value) -> None:
        assert replay_digests([bytes.fromhex(d) for d in events]).hex() == value

    def test_hardware_logs_differ_only_by_the_kernel_event(self) -> None:
        """Same constants in the same slots; v259 has no kernel image event."""
        fixed = [0, 1, -2, -1]
        assert [_CCEL_STUB256_RTMR1[i] for i in fixed] == [
            _CCEL_STUB259_RTMR1[i] for i in fixed
        ]
        assert len(_CCEL_STUB256_RTMR1) == len(_CCEL_STUB259_RTMR1) + 1
