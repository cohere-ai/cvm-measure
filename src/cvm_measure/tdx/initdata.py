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

"""CoCo initdata TOML parser and SHA-384 digest computation.

Computes the initdata digest from a CoCo initdata TOML file per the
Confidential Containers Trustee specification. The digest is simply
SHA-384 of the raw TOML file bytes.

Format reference: https://github.com/confidential-containers/trustee/blob/main/kbs/docs/initdata.md
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class InitData:
    """Parsed CoCo initdata TOML with metadata and key-value data sections."""

    version: str
    algorithm: str
    data: dict[str, str] = field(default_factory=dict)


def parse_toml(path: Path) -> InitData:
    """Parse a CoCo initdata TOML file.

    Only supports the subset needed for CoCo initdata.
    """
    text = path.read_text()
    return _parse_toml_text(text)


def _parse_toml_text(text: str) -> InitData:
    result = InitData(version="", algorithm="")
    lines = text.split("\n")
    current_section = ""
    current_key = ""
    current_value_lines: list[str] = []
    in_multiline = False

    for line in lines:
        stripped = line.strip()

        if in_multiline:
            if stripped == "'''" or stripped.endswith("'''"):
                if stripped.endswith("'''") and stripped != "'''":
                    current_value_lines.append(stripped[:-3])
                value = "\n".join(current_value_lines)
                result.data[current_key] = value
                in_multiline = False
                current_key = ""
                current_value_lines = []
            else:
                current_value_lines.append(line)
            continue

        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped[1:-1].strip()
            continue

        if "=" in stripped:
            key, _, value = stripped.partition("=")
            key = key.strip().strip('"').strip("'")
            value = value.strip()

            if current_section == "" or current_section == "metadata":
                if key == "version":
                    result.version = value.strip('"').strip("'")
                elif key == "algorithm":
                    result.algorithm = value.strip('"').strip("'")
            elif current_section == "data":
                if value == "'''":
                    in_multiline = True
                    current_key = key
                    current_value_lines = []
                elif value.startswith("'''") and value.endswith("'''") and len(value) > 6:
                    result.data[key] = value[3:-3]
                elif value.startswith('"') and value.endswith('"'):
                    result.data[key] = value[1:-1]
                elif value.startswith("'") and value.endswith("'"):
                    result.data[key] = value[1:-1]
                else:
                    result.data[key] = value

    return result


def compute_digest(path: Path) -> bytes:
    """Compute SHA-384 of the raw TOML file bytes.

    Per the CoCo spec, the initdata digest is the hash of the entire file.
    """
    return hashlib.sha384(path.read_bytes()).digest()


def compute_digest_hex(path: Path) -> str:
    return compute_digest(path).hex()


def build_initdata_toml(
    policy_path: Path | None = None,
    aa_path: Path | None = None,
    cdh_path: Path | None = None,
    version: str = "0.1.0",
    algorithm: str = "sha384",
) -> str:
    """Build an initdata TOML string from individual component files."""
    parts = [
        f'version = "{version}"',
        f'algorithm = "{algorithm}"',
        "",
        "[data]",
    ]

    for key, path in [("policy.rego", policy_path), ("aa.toml", aa_path), ("cdh.toml", cdh_path)]:
        if path is not None and path.exists():
            content = path.read_text()
            parts.append(f'"{key}" = \'\'\'')
            parts.append(content)
            parts.append("'''")

    return "\n".join(parts) + "\n"
