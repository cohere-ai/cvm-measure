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

"""CoCo initdata SHA-384 digest computation.

Computes the initdata digest from a CoCo initdata TOML file per the
Confidential Containers Trustee specification. The digest is simply
SHA-384 of the raw TOML file bytes.

Format reference: https://github.com/confidential-containers/trustee/blob/main/kbs/docs/initdata.md
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def compute_digest(path: Path) -> bytes:
    """Compute SHA-384 of the raw TOML file bytes.

    Per the CoCo spec, the initdata digest is the hash of the entire file.
    """
    return hashlib.sha384(path.read_bytes()).digest()
