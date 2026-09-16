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

"""CoCo initdata digest for TDX, which is always SHA-384.

RTMR[3] is extended through
/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384, a 48-byte
interface that cannot carry a shorter digest, so an initdata file asking for
any other algorithm describes a measurement this platform cannot perform.
"""

from __future__ import annotations

from pathlib import Path

from ..initdata import compute_digest as _compute_digest

TDX_ALGORITHM = "sha384"


def compute_digest(initdata: Path | bytes) -> bytes:
    """Compute SHA-384 of the raw TOML bytes, from a path or the bytes."""
    return _compute_digest(initdata, require=TDX_ALGORITHM)
