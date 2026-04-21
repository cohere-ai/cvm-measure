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

"""Unit tests: CoCo initdata digest."""

from __future__ import annotations

import hashlib

from cvm_measure.tdx.initdata import compute_digest


class TestInitDataDigest:

    def test_digest_is_sha384_of_raw_bytes(self, tmp_path) -> None:
        toml_content = b'version = "0.1.0"\nalgorithm = "sha384"\n[data]\n'
        path = tmp_path / "initdata.toml"
        path.write_bytes(toml_content)
        assert compute_digest(path) == hashlib.sha384(toml_content).digest()
