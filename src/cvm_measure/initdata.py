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

"""CoCo initdata digest computation.

The spec defines the digest as the declared hash algorithm applied to the
whole initdata, so the digest covers the ``algorithm`` key that selected it.
That key is not decoration: both the spec and CoCo's implementation switch on
it, and an algorithm neither supports is an error rather than a fallback. So
hardcoding one hash here would silently produce a wrong register for a file
that asks for another.

Which register the digest lands in, and in what form, is the platform's
business. TDX extends RTMR[3] with the whole digest. The Azure vTPM truncates
it to 32 bytes for PCR 8, following the spec's rule that a digest wider than
the field binding it loses the excess bytes off the end.

Format reference:
https://github.com/confidential-containers/trustee/blob/main/kbs/docs/initdata.md
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

# The algorithms CoCo implements. Anything else is refused rather than
# guessed at, since the digest would go into a register as though it were
# right.
SUPPORTED_ALGORITHMS = ("sha256", "sha384", "sha512")

# Python 3.10 has no tomllib and this tool has no dependencies, so rather than
# pretend to parse TOML we look for the one key that changes the answer. It is
# a top-level key, so the search stops at the first table header.
_ALGORITHM = re.compile(
    rb"""^[ \t]*algorithm[ \t]*=[ \t]*['"](?P<name>[A-Za-z0-9_-]+)['"]"""
)
_TABLE_HEADER = re.compile(rb"^[ \t]*\[")


def parse_algorithm(toml: bytes) -> str:
    """Read the digest algorithm an initdata TOML declares."""
    for line in toml.splitlines():
        if _TABLE_HEADER.match(line):
            break
        match = _ALGORITHM.match(line)
        if match is None:
            continue

        name = match.group("name").decode("ascii")
        if name not in SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"initdata declares algorithm {name!r}, which CoCo does not "
                f"implement. Supported: {', '.join(SUPPORTED_ALGORITHMS)}."
            )
        return name

    raise ValueError(
        "initdata declares no top-level 'algorithm' key, so the digest CoCo "
        "would compute for it is undefined. Add one of "
        f"{', '.join(SUPPORTED_ALGORITHMS)}."
    )


def compute_digest(initdata: Path | bytes, *, require: str | None = None) -> bytes:
    """Digest the raw TOML bytes with the algorithm the file declares.

    Args:
        initdata: A Path to read the plaintext initdata TOML from, or the TOML
            bytes themselves. Bytes are accepted because CoCo delivers initdata
            as a gzip+base64 pod annotation, so a caller verifying a pod spec
            has the TOML in memory and never on disk.
        require: Refuse the file unless it declares this algorithm. Used by
            platforms whose register is a fixed width.
    """
    data = initdata.read_bytes() if isinstance(initdata, Path) else initdata
    algorithm = parse_algorithm(data)
    if require is not None and algorithm != require:
        raise ValueError(
            f"initdata declares algorithm {algorithm!r}, but this platform "
            f"measures a {require} digest. The value CoCo computes for this "
            "file would not be the value the register holds."
        )
    return hashlib.new(algorithm, data).digest()
