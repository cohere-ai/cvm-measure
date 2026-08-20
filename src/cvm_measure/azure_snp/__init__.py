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

"""cvm_measure.azure_snp -- Azure SEV-SNP vTPM PCR computation.

Public API:
    compute_all_pcrs()  -- compute PCR 4, 5, 8, 9, 11 from a UKI, GPT, initdata
    compute_pcr8()      -- compute PCR 8 alone, from a CoCo initdata digest
    roothash()          -- read the dm-verity root hash off the command line
"""

from __future__ import annotations

from pathlib import Path

from .registers import ComputedPcrs, compute_all, compute_pcr8, roothash

__all__ = [
    "ComputedPcrs",
    "compute_all_pcrs",
    "compute_pcr8",
    "roothash",
]


def compute_all_pcrs(
    uki: bytes,
    gpt_event_data: bytes,
    *,
    initdata: Path | bytes | None = None,
    pcr8_hex: str | None = None,
) -> ComputedPcrs:
    """Compute the Azure SEV-SNP vTPM PCRs from published inputs.

    Args:
        uki: Raw UKI (BOOTX64.EFI) bytes.
        gpt_event_data: EV_EFI_GPT_EVENT data, from disk.gpt_event_data().
        initdata: The deployment's CoCo initdata, as a Path or the TOML bytes.
            PCR 8 is derived from it.
        pcr8_hex: PCR 8 as a pre-computed hex string, for a caller who has the
            register value but not the initdata behind it.

    Returns:
        ComputedPcrs with pcr4, pcr5, pcr8, pcr9, pcr11 as hex strings.
    """
    return compute_all(uki, gpt_event_data, initdata=initdata, pcr8_hex=pcr8_hex)
