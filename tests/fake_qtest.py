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

"""A stand-in for ``qemu -accel qtest -qtest stdio``: PCI config space, fw_cfg DMA and S5.

On power-off it writes the config space of every device to the JSON file
named by FAKE_QTEST_STATE, as {devfn: hex bytes}.
"""

from __future__ import annotations

import base64
import json
import os
import struct
import sys

FILES = {
    "etc/table-loader": b"loader",
    "etc/acpi/rsdp": b"RSD PTR ",
    "etc/acpi/tables": b"tables" * 100,
}
# devfn -> vendor | device << 16: q35 host bridge, ICH9 LPC, a root port, virtio-serial.
DEVICES = {0: 0x29C0_8086, 0x1F << 3: 0x2918_8086, 0x09 << 3: 0x000C_1B36}
DEVICES[0x11 << 3] = 0x1003_1AF4


def main() -> None:
    config = {
        d: bytearray(struct.pack("<I", i) + bytes(252)) for d, i in DEVICES.items()
    }
    mem = bytearray(0x110000)
    selectors = {0x20 + i: data for i, data in enumerate(FILES.values())}
    file_dir = struct.pack(">I", len(FILES)) + b"".join(
        struct.pack(">IHH56s", len(data), sel, 0, name.encode())
        for (sel, data), name in zip(selectors.items(), FILES)
    )
    addr = 0

    def reply(value: str = "") -> None:
        print(f"OK {value}".rstrip(), flush=True)

    for line in sys.stdin:
        op, *args = line.split()
        if op.startswith("out"):
            port, value = int(args[0], 16), int(args[1], 16)
            size = {"b": 1, "w": 2, "l": 4}[op[3]]
            if port == 0xCF8:
                addr = value
            elif 0xCFC <= port < 0xD00 and (addr >> 8 & 0xFF) in config:
                off = (addr & 0xFC) + port - 0xCFC
                config[addr >> 8 & 0xFF][off : off + size] = value.to_bytes(
                    size, "little"
                )
            elif port == 0x518:
                dma = int.from_bytes(value.to_bytes(4, "little"), "big")
                control, length, dest = struct.unpack_from(">IIQ", mem, dma)
                key = control >> 16
                data = file_dir if key == 0x19 else selectors[key]
                mem[dest : dest + length] = data[:length].ljust(length, b"\0")
            elif port == 0x604 and value == 0x2000:
                reply()
                state = {str(d): c.hex() for d, c in config.items()}
                with open(os.environ["FAKE_QTEST_STATE"], "w") as f:
                    json.dump(state, f)
                return
            reply()
        elif op.startswith("in"):
            port, size = int(args[0], 16), {"b": 1, "w": 2, "l": 4}[op[2]]
            space = config.get(addr >> 8 & 0xFF)
            if space is None:
                reply(f"{(1 << 8 * size) - 1:#x}")
            else:
                off = (addr & 0xFC) + port - 0xCFC
                reply(f"{int.from_bytes(space[off : off + size], 'little'):#x}")
        elif op == "b64write":
            start, data = int(args[0], 16), base64.b64decode(args[2])
            mem[start : start + len(data)] = data
            reply()
        elif op == "b64read":
            start, length = int(args[0], 16), int(args[1], 16)
            reply(base64.b64encode(bytes(mem[start : start + length])).decode())
        else:
            print(f"FAIL unknown command {op}", flush=True)


if __name__ == "__main__":
    main()
