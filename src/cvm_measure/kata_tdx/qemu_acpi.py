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

"""Pure-Python port of QEMU 11.0 pc-q35 ACPI table generation (Kata code paths only).

Produces the fw_cfg blobs etc/acpi/tables, etc/acpi/rsdp and etc/table-loader
exactly as QEMU's acpi_build() does for the Kata TDX GPU configuration.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field

GiB = 1 << 30
MiB = 1 << 20

# include/hw/acpi/aml-build.h
ACPI_BUILD_APPNAME6 = "BOCHS "
ACPI_BUILD_APPNAME8 = "BXPC    "
ACPI_BUILD_TABLE_FILE = "etc/acpi/tables"
ACPI_BUILD_RSDP_FILE = "etc/acpi/rsdp"
ACPI_BUILD_LOADER_FILE = "etc/table-loader"
# hw/i386/acpi-build.c
ACPI_BUILD_ALIGN_SIZE = 0x1000
ACPI_BUILD_TABLE_SIZE = 0x20000
# hw/i386/acpi-common.h, include/hw/intc/ioapic.h, target/i386/cpu.h
ACPI_BUILD_IOAPIC_ID = 0x0
IO_APIC_DEFAULT_ADDRESS = 0xFEC00000
APIC_DEFAULT_ADDRESS = 0xFEE00000
# include/hw/i386/x86.h
ACPI_BUILD_PCI_IRQS = (1 << 5) | (1 << 9) | (1 << 10) | (1 << 11)
# include/hw/southbridge/ich9.h, include/hw/acpi/*.h, hw/i386/fw_cfg.h
ICH9_RST_CNT_IOPORT = 0xCF9
ICH9_PMIO_GPE0_STS = 0x20
ICH9_PMIO_GPE0_LEN = 16
ICH9_CPU_HOTPLUG_IO_BASE = 0x0CD8
ACPI_CPU_HOTPLUG_REG_LEN = 12
ACPI_CPU_FLAGS_OFFSET_RW = 4
ACPI_PCIHP_ADDR_ICH9 = 0x0CC0
ACPI_PCIHP_SIZE = 0x0018
ACPI_PCIHP_SEJ_BASE = 0x8
ACPI_PCIHP_BNMR_BASE = 0x10
ACPI_PCIHP_BSEL_DEFAULT = 0x0
RTC_CENTURY = 0x32
FW_CFG_IO_BASE = 0x510
FW_CFG_CTL_SIZE = 0x02
FW_CFG_MAX_FILE_PATH = 56
SIZEOF_DMA_ADDR_T = 8
PCIE_MMCFG_BUS_BIT = 20
PCIE_MMCFG_BUS_MASK = 0xFF
Q35_PCI_HOST_HOLE64_SIZE_DEFAULT = 1 << 35
# hw/acpi/cpu.c
CPHP_GET_NEXT_CPU_WITH_EVENT_CMD = 0
CPHP_OST_EVENT_CMD = 1
CPHP_OST_STATUS_CMD = 2

# include/hw/acpi/acpi-defs.h (FADT flag bit positions)
ACPI_FADT_F_WBINVD = 0
ACPI_FADT_F_PROC_C1 = 2
ACPI_FADT_F_SLP_BUTTON = 5
ACPI_FADT_F_RTC_S4 = 7
ACPI_FADT_F_RESET_REG_SUP = 10
ACPI_FADT_F_USE_PLATFORM_CLOCK = 15
ACPI_FADT_F_FORCE_APIC_CLUSTER_MODEL = 18

# include/hw/acpi/aml-build.h enums
AML_DECODE16 = 1
AML_ANY_ACC, AML_BYTE_ACC, AML_WORD_ACC, AML_DWORD_ACC = 0, 1, 2, 3
AML_NOLOCK = 0
AML_PRESERVE, AML_WRITE_AS_ONES, AML_WRITE_AS_ZEROS = 0, 1, 2
AML_AS_SYSTEM_MEMORY, AML_AS_SYSTEM_IO = 0, 1
AML_SYSTEM_MEMORY, AML_SYSTEM_IO, AML_PCI_CONFIG = 0, 1, 2
AML_MEMORY_RANGE, AML_IO_RANGE, AML_BUS_NUMBER_RANGE = 0, 1, 2
AML_POS_DECODE = 0
AML_MIN_FIXED = 1 << 2
AML_MAX_FIXED = 1 << 3
AML_ENTIRE_RANGE = 3
AML_NON_CACHEABLE, AML_CACHEABLE = 0, 1
AML_READ_WRITE = 1
AML_CONSUMER = 1
AML_LEVEL = 0
AML_ACTIVE_HIGH = 0
AML_SHARED = 1
AML_NOTSERIALIZED, AML_SERIALIZED = 0, 1

(
    AML_NO_OPCODE,
    AML_OPCODE,
    AML_PACKAGE,
    AML_EXT_PACKAGE,
    AML_BUFFER,
    AML_RES_TEMPLATE,
) = range(6)


# ---------------------------------------------------------------------------
# AML builder (hw/acpi/aml-build.c)
# ---------------------------------------------------------------------------


class Aml:
    __slots__ = ("block_flags", "buf", "op")

    def __init__(self, op: int = 0, block_flags: int = AML_NO_OPCODE):
        self.op = op
        self.block_flags = block_flags
        self.buf = bytearray()


def build_append_int_noprefix(value: int, size: int) -> bytes:
    return (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")


def _int_bytes(value: int) -> bytes:
    """build_append_int"""
    if value == 0:
        return b"\x00"
    if value == 1:
        return b"\x01"
    if value <= 0xFF:
        return b"\x0a" + value.to_bytes(1, "little")
    if value <= 0xFFFF:
        return b"\x0b" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\x0c" + value.to_bytes(4, "little")
    return b"\x0e" + value.to_bytes(8, "little")


def _pkg_length(length: int, incl_self: bool) -> bytes:
    """build_prepend_package_length"""
    if length + 1 < (1 << 6):
        n = 1
    elif length + 2 < (1 << 12):
        n = 2
    elif length + 3 < (1 << 20):
        n = 3
    else:
        n = 4
    if incl_self:
        length += n
    if n == 1:
        return bytes([length])
    tail = [(length >> 4) & 0xFF, (length >> 12) & 0xFF, (length >> 20) & 0xFF][: n - 1]
    return bytes([((n - 1) << 6) | (length & 0xF)] + tail)


def _require(condition: bool, what: str) -> None:
    """QEMU's g_assert: these hold for every valid machine, so a failure is a bug or bad input."""
    if not condition:
        raise ValueError(f"QEMU ACPI invariant violated: {what}")


def _nameseg(seg: str) -> bytes:
    """build_append_nameseg"""
    _require(len(seg) <= 4, "len(seg) <= 4")
    return seg.encode() + b"____"[: 4 - len(seg)]


def _namestring(s: str) -> bytes:
    """build_append_namestringv"""
    segs = s.split(".")
    _require(0 < len(segs) <= 255, "0 < len(segs) <= 255")
    out = bytearray()
    first = segs[0]
    i = 0
    while i < len(first) and first[i] in "\\^":
        out.append(ord(first[i]))
        i += 1
    first = first[i:]
    if len(segs) == 1:
        out += _nameseg(first) if first else b"\x00"
    elif len(segs) == 2:
        out += b"\x2e" + _nameseg(first) + _nameseg(segs[1])
    else:
        out += bytes([0x2F, len(segs)]) + _nameseg(first)
        for seg in segs[1:]:
            out += _nameseg(seg)
    return bytes(out)


def _package(buf: bytes, op: int) -> bytes:
    """build_package"""
    return bytes([op]) + _pkg_length(len(buf), True) + buf


def _buffer(buf: bytes, op: int) -> bytes:
    """build_buffer"""
    return _package(_int_bytes(len(buf)) + buf, op)


def aml_append(parent: Aml, child: Aml) -> None:
    buf = bytes(child.buf)
    flags = child.block_flags
    if flags == AML_OPCODE:
        parent.buf.append(child.op)
    elif flags == AML_EXT_PACKAGE:
        buf = b"\x5b" + _package(buf, child.op)
    elif flags == AML_PACKAGE:
        buf = _package(buf, child.op)
    elif flags == AML_RES_TEMPLATE:
        buf = _buffer(buf + b"\x79\x00", child.op)
    elif flags == AML_BUFFER:
        buf = _buffer(buf, child.op)
    elif flags != AML_NO_OPCODE:
        raise AssertionError(flags)
    parent.buf += buf


def _aml_raw(data: bytes) -> Aml:
    var = Aml()
    var.buf += data
    return var


def _aml_opcode(op: int, *children: Aml) -> Aml:
    var = Aml(op, AML_OPCODE)
    for c in children:
        aml_append(var, c)
    return var


def aml_scope(name: str) -> Aml:
    var = Aml(0x10, AML_PACKAGE)
    var.buf += _namestring(name)
    return var


def aml_return(val: Aml) -> Aml:
    return _aml_opcode(0xA4, val)


def aml_debug() -> Aml:
    return _aml_raw(b"\x5b\x31")


def aml_int(val: int) -> Aml:
    return _aml_raw(_int_bytes(val))


def aml_name(name: str) -> Aml:
    return _aml_raw(_namestring(name))


def aml_name_decl(name: str, val: Aml) -> Aml:
    var = Aml(0x08, AML_OPCODE)
    var.buf += _namestring(name)
    aml_append(var, val)
    return var


def aml_arg(pos: int) -> Aml:
    _require(pos <= 6, "pos <= 6")
    return Aml(0x68 + pos, AML_OPCODE)


def aml_local(num: int) -> Aml:
    _require(num <= 7, "num <= 7")
    return Aml(0x60 + num, AML_OPCODE)


def _opcode_2arg_dst(op: int, arg1: Aml, arg2: Aml, dst: Aml | None) -> Aml:
    """build_opcode_2arg_dst"""
    var = _aml_opcode(op, arg1, arg2)
    if dst is not None:
        aml_append(var, dst)
    else:
        var.buf.append(0x00)
    return var


def aml_to_hexstring(src: Aml, dst: Aml | None) -> Aml:
    var = _aml_opcode(0x98, src)
    if dst is not None:
        aml_append(var, dst)
    else:
        var.buf.append(0x00)
    return var


def aml_to_buffer(src: Aml, dst: Aml | None) -> Aml:
    var = _aml_opcode(0x96, src)
    if dst is not None:
        aml_append(var, dst)
    else:
        var.buf.append(0x00)
    return var


def aml_store(val: Aml, target: Aml) -> Aml:
    return _aml_opcode(0x70, val, target)


def aml_and(arg1: Aml, arg2: Aml, dst: Aml | None) -> Aml:
    return _opcode_2arg_dst(0x7B, arg1, arg2, dst)


def aml_or(arg1: Aml, arg2: Aml, dst: Aml | None) -> Aml:
    return _opcode_2arg_dst(0x7D, arg1, arg2, dst)


def aml_land(arg1: Aml, arg2: Aml) -> Aml:
    return _aml_opcode(0x90, arg1, arg2)


def aml_lor(arg1: Aml, arg2: Aml) -> Aml:
    return _aml_opcode(0x91, arg1, arg2)


def aml_shiftleft(arg1: Aml, count: Aml) -> Aml:
    return _opcode_2arg_dst(0x79, arg1, count, None)


def aml_lless(arg1: Aml, arg2: Aml) -> Aml:
    return _aml_opcode(0x95, arg1, arg2)


def aml_subtract(arg1: Aml, arg2: Aml, dst: Aml | None) -> Aml:
    return _opcode_2arg_dst(0x74, arg1, arg2, dst)


def aml_increment(arg: Aml) -> Aml:
    return _aml_opcode(0x75, arg)


def aml_index(arg1: Aml, idx: Aml) -> Aml:
    return _opcode_2arg_dst(0x88, arg1, idx, None)


def aml_notify(arg1: Aml, arg2: Aml) -> Aml:
    return _aml_opcode(0x86, arg1, arg2)


def aml_break() -> Aml:
    return Aml(0xA5, AML_OPCODE)


def aml_call(method: str, *args: Aml) -> Aml:
    """aml_call0 .. aml_call6"""
    var = _aml_raw(_namestring(method))
    for a in args:
        aml_append(var, a)
    return var


aml_call0 = aml_call1 = aml_call2 = aml_call4 = aml_call5 = aml_call


def aml_interrupt(
    con_and_pro: int,
    level_and_edge: int,
    high_and_low: int,
    shared: int,
    irq_list: list[int],
) -> Aml:
    _require(bool(irq_list), "irq_list")
    flags = con_and_pro | (level_and_edge << 1) | (high_and_low << 2) | (shared << 3)
    length = 2 + 4 * len(irq_list)
    data = bytes([0x89, length & 0xFF, length >> 8, flags, len(irq_list)])
    data += b"".join(build_append_int_noprefix(i, 4) for i in irq_list)
    return _aml_raw(data)


def aml_io(dec: int, min_base: int, max_base: int, aln: int, length: int) -> Aml:
    return _aml_raw(struct.pack("<BBHHBB", 0x47, dec, min_base, max_base, aln, length))


def aml_irq_no_flags(irq: int) -> Aml:
    _require(irq < 16, "irq < 16")
    return _aml_raw(struct.pack("<BH", 0x22, 1 << irq))


def aml_lnot(arg: Aml) -> Aml:
    return _aml_opcode(0x92, arg)


def aml_equal(arg1: Aml, arg2: Aml) -> Aml:
    return _aml_opcode(0x93, arg1, arg2)


def aml_lgreater(arg1: Aml, arg2: Aml) -> Aml:
    return _aml_opcode(0x94, arg1, arg2)


def aml_if(predicate: Aml) -> Aml:
    var = Aml(0xA0, AML_PACKAGE)
    aml_append(var, predicate)
    return var


def aml_else() -> Aml:
    return Aml(0xA1, AML_PACKAGE)


def aml_while(predicate: Aml) -> Aml:
    var = Aml(0xA2, AML_PACKAGE)
    aml_append(var, predicate)
    return var


def aml_method(name: str, arg_count: int, sflag: int) -> Aml:
    _require(arg_count < 8, "arg_count < 8")
    var = Aml(0x14, AML_PACKAGE)
    var.buf += _namestring(name) + bytes([arg_count | (sflag << 3)])
    return var


def aml_device(name: str) -> Aml:
    var = Aml(0x82, AML_EXT_PACKAGE)
    var.buf += _namestring(name)
    return var


def aml_resource_template() -> Aml:
    return Aml(0x11, AML_RES_TEMPLATE)


def aml_buffer(byte_list: bytes) -> Aml:
    var = Aml(0x11, AML_BUFFER)
    var.buf += byte_list
    return var


def aml_package(num_elements: int) -> Aml:
    var = Aml(0x12, AML_PACKAGE)
    var.buf.append(num_elements & 0xFF)
    return var


def aml_operation_region(name: str, rs: int, offset: Aml, length: int) -> Aml:
    var = _aml_raw(b"\x5b\x80" + _namestring(name) + bytes([rs]))
    aml_append(var, offset)
    var.buf += _int_bytes(length)
    return var


def aml_named_field(name: str, length: int) -> Aml:
    return _aml_raw(_nameseg(name) + _pkg_length(length, False))


def aml_reserved_field(length: int) -> Aml:
    return _aml_raw(b"\x00" + _pkg_length(length, False))


def aml_field(name: str, typ: int, lock: int, rule: int) -> Aml:
    var = Aml(0x81, AML_EXT_PACKAGE)
    var.buf += _namestring(name) + bytes([(rule << 5) | typ | (lock << 4)])
    return var


def aml_create_dword_field(srcbuf: Aml, index: Aml, name: str) -> Aml:
    var = _aml_opcode(0x8A, srcbuf, index)
    var.buf += _namestring(name)
    return var


def aml_string(s: str) -> Aml:
    var = Aml(0x0D, AML_OPCODE)
    var.buf += s.encode() + b"\x00"
    return var


def aml_processor(proc_id: int, pblk_addr: int, pblk_len: int, name: str) -> Aml:
    var = Aml(0x83, AML_EXT_PACKAGE)
    var.buf += _namestring(name) + struct.pack(
        "<BIB", proc_id & 0xFF, pblk_addr, pblk_len
    )
    return var


def _hex2digit(c: str) -> int:
    return ord(c) - ord("A") + 10 if c >= "A" else ord(c) - ord("0")


def aml_eisaid(s: str) -> Aml:
    _require(len(s) == 7, "len(s) == 7")
    eid = (
        (ord(s[0]) - 0x40) << 26
        | (ord(s[1]) - 0x40) << 21
        | (ord(s[2]) - 0x40) << 16
        | _hex2digit(s[3]) << 12
        | _hex2digit(s[4]) << 8
        | _hex2digit(s[5]) << 4
        | _hex2digit(s[6])
    )
    return _aml_raw(b"\x0c" + eid.to_bytes(4, "big"))


def _as_desc_header(
    typ: int, min_fixed: int, max_fixed: int, dec: int, type_flags: int
) -> bytes:
    """aml_as_desc_header"""
    return bytes([typ, max_fixed | min_fixed | dec, type_flags])


def aml_word_bus_number(
    min_fixed: int,
    max_fixed: int,
    dec: int,
    gran: int,
    amin: int,
    amax: int,
    trans: int,
    length: int,
) -> Aml:
    return _aml_raw(
        b"\x88\x0d\x00"
        + _as_desc_header(AML_BUS_NUMBER_RANGE, min_fixed, max_fixed, dec, 0)
        + struct.pack("<5H", gran, amin, amax, trans, length)
    )


def aml_word_io(
    min_fixed: int,
    max_fixed: int,
    dec: int,
    isa_ranges: int,
    gran: int,
    amin: int,
    amax: int,
    trans: int,
    length: int,
) -> Aml:
    return _aml_raw(
        b"\x88\x0d\x00"
        + _as_desc_header(AML_IO_RANGE, min_fixed, max_fixed, dec, isa_ranges)
        + struct.pack("<5H", gran, amin, amax, trans, length)
    )


def aml_dword_memory(
    dec: int,
    min_fixed: int,
    max_fixed: int,
    cacheable: int,
    rw: int,
    gran: int,
    amin: int,
    amax: int,
    trans: int,
    length: int,
) -> Aml:
    flags = rw | (cacheable << 1)
    return _aml_raw(
        bytes([0x87, 23, 0])
        + _as_desc_header(AML_MEMORY_RANGE, min_fixed, max_fixed, dec, flags)
        + struct.pack("<5I", gran, amin, amax, trans, length)
    )


def aml_qword_memory(
    dec: int,
    min_fixed: int,
    max_fixed: int,
    cacheable: int,
    rw: int,
    gran: int,
    amin: int,
    amax: int,
    trans: int,
    length: int,
) -> Aml:
    flags = rw | (cacheable << 1)
    return _aml_raw(
        b"\x8a\x2b\x00"
        + _as_desc_header(AML_MEMORY_RANGE, min_fixed, max_fixed, dec, flags)
        + struct.pack("<5Q", gran, amin, amax, trans, length)
    )


def aml_touuid(uuid: str) -> Aml:
    _require(
        len(uuid) == 36 and uuid[8] == uuid[13] == uuid[18] == uuid[23] == "-",
        'len(uuid) == 36 and uuid[8] == uuid[13] == uuid[18] == uuid[23] == "-"',
    )
    order = (6, 4, 2, 0, 11, 9, 16, 14, 19, 21, 24, 26, 28, 30, 32, 34)
    return aml_buffer(bytes(int(uuid[i : i + 2], 16) for i in order))


def aml_derefof(arg: Aml) -> Aml:
    return _aml_opcode(0x83, arg)


def aml_sizeof(arg: Aml) -> Aml:
    return _aml_opcode(0x87, arg)


def aml_mutex(name: str, sync_level: int) -> Aml:
    _require(not sync_level & 0xF0, "not sync_level & 0xF0")
    return _aml_raw(b"\x5b\x01" + _namestring(name) + bytes([sync_level]))


def aml_acquire(mutex: Aml, timeout: int) -> Aml:
    var = _aml_raw(b"\x5b\x23")
    aml_append(var, mutex)
    var.buf += struct.pack("<H", timeout)
    return var


def aml_release(mutex: Aml) -> Aml:
    var = _aml_raw(b"\x5b\x27")
    aml_append(var, mutex)
    return var


def crs_replace_with_free_ranges(
    ranges: list[tuple[int, int]], start: int, end: int
) -> list[tuple[int, int]]:
    free = []
    free_base = start
    for base, limit in sorted(ranges, key=lambda r: r[0]):
        if free_base < base:
            free.append((free_base, base - 1))
        free_base = limit + 1
    if free_base < end:
        free.append((free_base, end))
    return free


# ---------------------------------------------------------------------------
# BIOS linker (hw/acpi/bios-linker-loader.c) and table header helpers
# ---------------------------------------------------------------------------

BIOS_LINKER_LOADER_COMMAND_ALLOCATE = 0x1
BIOS_LINKER_LOADER_COMMAND_ADD_POINTER = 0x2
BIOS_LINKER_LOADER_COMMAND_ADD_CHECKSUM = 0x3
BIOS_LINKER_LOADER_ALLOC_ZONE_HIGH = 0x1
BIOS_LINKER_LOADER_ALLOC_ZONE_FSEG = 0x2
_ENTRY_SIZE = 128


def _fname(name: str) -> bytes:
    raw = name.encode()[: FW_CFG_MAX_FILE_PATH - 1]
    return raw.ljust(FW_CFG_MAX_FILE_PATH, b"\x00")


class BIOSLinker:
    def __init__(self) -> None:
        self.cmd_blob = bytearray()
        self.files: dict[str, bytearray] = {}

    def alloc(self, file_name: str, blob: bytearray, align: int, fseg: bool) -> None:
        """bios_linker_loader_alloc"""
        _require(not align & (align - 1), "not align & (align - 1)")
        _require(file_name not in self.files, "file_name not in self.files")
        self.files[file_name] = blob
        zone = (
            BIOS_LINKER_LOADER_ALLOC_ZONE_FSEG
            if fseg
            else BIOS_LINKER_LOADER_ALLOC_ZONE_HIGH
        )
        entry = struct.pack(
            "<I56sIB",
            BIOS_LINKER_LOADER_COMMAND_ALLOCATE,
            _fname(file_name),
            align,
            zone,
        )
        self.cmd_blob[0:0] = entry.ljust(_ENTRY_SIZE, b"\x00")

    def add_checksum(
        self, file_name: str, start: int, size: int, checksum_offset: int
    ) -> None:
        """bios_linker_loader_add_checksum"""
        blob = self.files[file_name]
        _require(
            start < len(blob) and start + size <= len(blob),
            "start < len(blob) and start + size <= len(blob)",
        )
        _require(
            start <= checksum_offset < start + size,
            "start <= checksum_offset < start + size",
        )
        blob[checksum_offset] = 0
        entry = struct.pack(
            "<I56sIII",
            BIOS_LINKER_LOADER_COMMAND_ADD_CHECKSUM,
            _fname(file_name),
            checksum_offset,
            start,
            size,
        )
        self.cmd_blob += entry.ljust(_ENTRY_SIZE, b"\x00")

    def add_pointer(
        self, dest_file: str, dst_off: int, dst_size: int, src_file: str, src_off: int
    ) -> None:
        """bios_linker_loader_add_pointer"""
        dst = self.files[dest_file]
        src = self.files[src_file]
        _require(
            dst_off + dst_size <= len(dst) and src_off < len(src),
            "dst_off + dst_size <= len(dst) and src_off < len(src)",
        )
        _require(dst_size in (1, 2, 4, 8), "dst_size in (1, 2, 4, 8)")
        entry = struct.pack(
            "<I56s56sIB",
            BIOS_LINKER_LOADER_COMMAND_ADD_POINTER,
            _fname(dest_file),
            _fname(src_file),
            dst_off,
            dst_size,
        )
        dst[dst_off : dst_off + dst_size] = src_off.to_bytes(8, "little")[:dst_size]
        self.cmd_blob += entry.ljust(_ENTRY_SIZE, b"\x00")


def _padded(s: str, n: int) -> bytes:
    """build_append_padded_str with '\\0'"""
    raw = s.encode()
    _require(len(raw) <= n, "len(raw) <= n")
    return raw.ljust(n, b"\x00")


def acpi_table_begin(
    array: bytearray, sig: str, rev: int, oem_id: str, oem_table_id: str
) -> int:
    off = len(array)
    _require(len(sig) == 4, "len(sig) == 4")
    array += sig.encode() + build_append_int_noprefix(0, 4) + bytes([rev, 0])
    array += _padded(oem_id, 6) + _padded(oem_table_id, 8)
    array += (
        build_append_int_noprefix(1, 4)
        + ACPI_BUILD_APPNAME8.encode()[:4]
        + build_append_int_noprefix(1, 4)
    )
    return off


def acpi_table_end(linker: BIOSLinker, array: bytearray, table_offset: int) -> None:
    table_len = len(array) - table_offset
    array[table_offset + 4 : table_offset + 8] = struct.pack("<I", table_len)
    linker.add_checksum(
        ACPI_BUILD_TABLE_FILE, table_offset, table_len, table_offset + 9
    )


def build_append_gas(
    as_id: int, bit_width: int, bit_offset: int, access_width: int, address: int
) -> bytes:
    return struct.pack("<BBBBQ", as_id, bit_width, bit_offset, access_width, address)


# ---------------------------------------------------------------------------
# Platform description
# ---------------------------------------------------------------------------

BRIDGE_KINDS = ("pci-bridge", "pcie-root-port")


@dataclass
class PciBus:
    """A PCI bus; devices are listed in qdev realize (creation) order."""

    devices: list[PciDevice] = field(default_factory=list)
    express: bool = False


@dataclass
class PciDevice:
    """A PCI function. kind: endpoint, host-bridge, lpc, smbus, pci-bridge, pcie-root-port."""

    slot: int
    function: int = 0
    kind: str = "endpoint"
    name: str = ""
    hotpluggable: bool = True
    slot_hotplug: bool = True
    acpi_index: int = 0
    bus: PciBus | None = None

    @property
    def devfn(self) -> int:
        return (self.slot << 3) | self.function

    @property
    def secondary(self) -> PciBus:
        if self.bus is None:
            raise ValueError(f"{self.name or self.kind} has no secondary bus")
        return self.bus

    @property
    def is_bridge(self) -> bool:
        return self.kind in BRIDGE_KINDS


@dataclass
class Rtc:
    """mc146818rtc on the ICH9 ISA bus."""

    io_base: int = 0x70
    isairq: int = 8


@dataclass
class I8042:
    """i8042 keyboard controller on the ICH9 ISA bus."""

    kbd_irq: int = 1
    mouse_irq: int = 12


@dataclass
class Topology:
    """Everything acpi_build() reads from the machine, besides CPU and RAM sizing."""

    root: PciBus
    isa_devices: list[Rtc | I8042] = field(default_factory=lambda: [Rtc(), I8042()])
    oem_id: str = ACPI_BUILD_APPNAME6
    oem_table_id: str = ACPI_BUILD_APPNAME8
    pm_io_base: int = 0x600
    sci_int: int = 9
    s3_disabled: bool = False
    s4_disabled: bool = False
    s4_val: int = 2
    mcfg_base: int = 0xE0000000
    mcfg_size: int = 0x10000000
    pic: bool = False
    pci_root_uid: int = 0
    pci_hole64_size: int = Q35_PCI_HOST_HOLE64_SIZE_DEFAULT
    pci_hole64_fix: bool = True
    max_ram_below_4g: int = 4 * GiB
    smm: bool = False
    smi_negotiated_features: int = 0
    pcihp_bridge: bool = True
    pcihp_root: bool = False
    hpet: bool = False
    tpm: bool = False
    nvdimm: bool = False
    ram_slots: int = 0
    sgx_epc_size: int = 0
    cxl: bool = False
    vmbus: bool = False
    pxb_buses: int = 0
    iommu: str | None = None
    numa_nodes: int = 0
    vmgenid: bool = False
    vmclock: bool = False
    erst: bool = False
    ioapic2: bool = False
    acpi_tables: tuple[bytes, ...] = ()
    slic: bool = False


def _check_supported(t: Topology) -> None:
    unsupported = {
        "smm": t.smm,
        "smi_negotiated_features": t.smi_negotiated_features,
        "pcihp_bridge disabled": not t.pcihp_bridge,
        "pcihp_root": t.pcihp_root,
        "hpet": t.hpet,
        "tpm": t.tpm,
        "nvdimm": t.nvdimm,
        "memory hotplug (ram_slots)": t.ram_slots,
        "sgx_epc": t.sgx_epc_size,
        "cxl": t.cxl,
        "vmbus": t.vmbus,
        "pxb expander buses": t.pxb_buses,
        "iommu": t.iommu,
        "numa/srat": t.numa_nodes,
        "vmgenid": t.vmgenid,
        "vmclock": t.vmclock,
        "erst": t.erst,
        "ioapic2": t.ioapic2,
        "user acpi tables": t.acpi_tables,
        "slic": t.slic,
    }
    bad = [k for k, v in unsupported.items() if v]
    if bad:
        raise NotImplementedError("unported QEMU ACPI features: " + ", ".join(bad))
    for bus in _iter_buses(t.root):
        seen = set()
        for d in bus.devices:
            if d.devfn in seen:
                raise ValueError(f"duplicate devfn {d.devfn:#x}")
            seen.add(d.devfn)
            if d.is_bridge != (d.bus is not None):
                raise ValueError(
                    f"{d.name or d.kind}: bridges and only bridges carry a secondary bus"
                )
            if d.acpi_index and not d.hotpluggable:
                raise NotImplementedError(
                    "acpi-index on non-hotpluggable device (aml_pci_static_endpoint_dsm)"
                )
            if d.kind == "lpc" and d.devfn != 0xF8:
                raise NotImplementedError(
                    "ICH9 LPC must be at 1f.0 (PCI0.SF8.PIRQ is hardcoded)"
                )
    for isa in t.isa_devices:
        if not isinstance(isa, (Rtc, I8042)):
            raise NotImplementedError(f"ISA device {type(isa).__name__}")


def _iter_buses(bus: PciBus) -> Iterator[PciBus]:
    yield bus
    for d in bus.devices:
        if d.bus is not None:
            yield from _iter_buses(d.bus)


def _child_bridges(bus: PciBus) -> list[PciDevice]:
    """bus->child order: QLIST_INSERT_HEAD at bridge realize, so newest first."""
    return [d for d in reversed(bus.devices) if d.bus is not None]


def acpi_set_bsel(root: PciBus, t: Topology) -> dict[int, int]:
    """acpi_set_pci_info / acpi_set_bsel via pci_for_each_bus_depth_first (hw/acpi/pcihp.c)."""
    bsel: dict[int, int] = {}
    alloc = ACPI_PCIHP_BSEL_DEFAULT

    def hotpluggable(parent: PciDevice | None) -> bool:
        if parent is None:
            return t.pcihp_root
        if parent.kind == "pcie-root-port" and not parent.slot_hotplug:
            return False
        return t.pcihp_bridge

    def visit(bus: PciBus, parent: PciDevice | None) -> None:
        nonlocal alloc
        if hotpluggable(parent):
            bsel[id(bus)] = alloc
            alloc += 1
        for br in _child_bridges(bus):
            visit(br.secondary, br)

    visit(root, None)
    return bsel


# ---------------------------------------------------------------------------
# hw/i386/acpi-build.c DSDT helpers
# ---------------------------------------------------------------------------


def build_dbg_aml(table: Aml) -> None:
    scope = aml_scope("\\")
    buf, length, idx = aml_local(0), aml_local(1), aml_local(2)
    aml_append(scope, aml_operation_region("DBG", AML_SYSTEM_IO, aml_int(0x0402), 0x01))
    fld = aml_field("DBG", AML_BYTE_ACC, AML_NOLOCK, AML_PRESERVE)
    aml_append(fld, aml_named_field("DBGB", 8))
    aml_append(scope, fld)
    method = aml_method("DBUG", 1, AML_NOTSERIALIZED)
    aml_append(method, aml_to_hexstring(aml_arg(0), buf))
    aml_append(method, aml_to_buffer(buf, buf))
    aml_append(method, aml_subtract(aml_sizeof(buf), aml_int(1), length))
    aml_append(method, aml_store(aml_int(0), idx))
    while_ctx = aml_while(aml_lless(idx, length))
    aml_append(while_ctx, aml_store(aml_derefof(aml_index(buf, idx)), aml_name("DBGB")))
    aml_append(while_ctx, aml_increment(idx))
    aml_append(method, while_ctx)
    aml_append(method, aml_store(aml_int(0x0A), aml_name("DBGB")))
    aml_append(scope, method)
    aml_append(table, scope)


def build_link_dev(name: str, uid: int, reg: Aml) -> Aml:
    dev = aml_device(name)
    aml_append(dev, aml_name_decl("_HID", aml_eisaid("PNP0C0F")))
    aml_append(dev, aml_name_decl("_UID", aml_int(uid)))
    crs = aml_resource_template()
    aml_append(
        crs,
        aml_interrupt(
            AML_CONSUMER, AML_LEVEL, AML_ACTIVE_HIGH, AML_SHARED, [5, 10, 11]
        ),
    )
    aml_append(dev, aml_name_decl("_PRS", crs))
    method = aml_method("_STA", 0, AML_NOTSERIALIZED)
    aml_append(method, aml_return(aml_call1("IQST", reg)))
    aml_append(dev, method)
    method = aml_method("_DIS", 0, AML_NOTSERIALIZED)
    aml_append(method, aml_or(reg, aml_int(0x80), reg))
    aml_append(dev, method)
    method = aml_method("_CRS", 0, AML_NOTSERIALIZED)
    aml_append(method, aml_return(aml_call1("IQCR", reg)))
    aml_append(dev, method)
    method = aml_method("_SRS", 1, AML_NOTSERIALIZED)
    aml_append(method, aml_create_dword_field(aml_arg(0), aml_int(5), "PRRI"))
    aml_append(method, aml_store(aml_name("PRRI"), reg))
    aml_append(dev, method)
    return dev


def build_gsi_link_dev(name: str, uid: int, gsi: int) -> Aml:
    dev = aml_device(name)
    aml_append(dev, aml_name_decl("_HID", aml_eisaid("PNP0C0F")))
    aml_append(dev, aml_name_decl("_UID", aml_int(uid)))
    crs = aml_resource_template()
    aml_append(
        crs, aml_interrupt(AML_CONSUMER, AML_LEVEL, AML_ACTIVE_HIGH, AML_SHARED, [gsi])
    )
    aml_append(dev, aml_name_decl("_PRS", crs))
    aml_append(dev, aml_name_decl("_CRS", crs))
    aml_append(dev, aml_method("_DIS", 0, AML_NOTSERIALIZED))
    aml_append(dev, aml_method("_SRS", 1, AML_NOTSERIALIZED))
    return dev


def build_iqcr_method(is_piix4: bool) -> Aml:
    method = aml_method("IQCR", 1, AML_SERIALIZED)
    crs = aml_resource_template()
    aml_append(
        crs, aml_interrupt(AML_CONSUMER, AML_LEVEL, AML_ACTIVE_HIGH, AML_SHARED, [0])
    )
    aml_append(method, aml_name_decl("PRR0", crs))
    aml_append(method, aml_create_dword_field(aml_name("PRR0"), aml_int(5), "PRRI"))
    if is_piix4:
        raise NotImplementedError("piix4")
    aml_append(
        method, aml_store(aml_and(aml_arg(0), aml_int(0xF), None), aml_name("PRRI"))
    )
    aml_append(method, aml_return(aml_name("PRR0")))
    return method


def build_irq_status_method() -> Aml:
    method = aml_method("IQST", 1, AML_NOTSERIALIZED)
    if_ctx = aml_if(aml_and(aml_int(0x80), aml_arg(0), None))
    aml_append(if_ctx, aml_return(aml_int(0x09)))
    aml_append(method, if_ctx)
    aml_append(method, aml_return(aml_int(0x0B)))
    return method


def append_q35_prt_entry(ctx: Aml, nr: int, name: str) -> None:
    base = "A" if name[3] < "E" else "E"
    a_nr = aml_int((nr << 16) | 0xFFFF)
    head = ord(name[3]) - ord(base)
    for i in range(4):
        if head + i > 3:
            head = -i
        s = name[:3] + chr(ord(base) + head + i)
        pkg = aml_package(4)
        aml_append(pkg, a_nr)
        aml_append(pkg, aml_int(i))
        aml_append(pkg, aml_name(s))
        aml_append(pkg, aml_int(0))
        aml_append(ctx, pkg)


def build_q35_routing_table(prefix: str) -> Aml:
    pkg = aml_package(128)
    for i in range(0x18):
        append_q35_prt_entry(pkg, i, prefix + chr(ord("E") + (i & 0x3)))
    append_q35_prt_entry(pkg, 0x18, prefix + "E")
    for i in range(0x19, 0x1E):
        append_q35_prt_entry(pkg, i, prefix + "A")
    append_q35_prt_entry(pkg, 0x1E, prefix + "E")
    append_q35_prt_entry(pkg, 0x1F, prefix + "A")
    return pkg


def build_q35_pci0_int(table: Aml) -> None:
    sb_scope = aml_scope("_SB")
    pci0_scope = aml_scope("PCI0")
    aml_append(table, aml_name_decl("PICF", aml_int(0)))
    method = aml_method("_PIC", 1, AML_NOTSERIALIZED)
    aml_append(method, aml_store(aml_arg(0), aml_name("PICF")))
    aml_append(table, method)
    aml_append(pci0_scope, aml_name_decl("PRTP", build_q35_routing_table("LNK")))
    aml_append(pci0_scope, aml_name_decl("PRTA", build_q35_routing_table("GSI")))
    method = aml_method("_PRT", 0, AML_NOTSERIALIZED)
    if_ctx = aml_if(aml_equal(aml_name("PICF"), aml_int(0)))
    aml_append(if_ctx, aml_return(aml_name("PRTP")))
    aml_append(method, if_ctx)
    else_ctx = aml_else()
    aml_append(else_ctx, aml_return(aml_name("PRTA")))
    aml_append(method, else_ctx)
    aml_append(pci0_scope, method)
    aml_append(sb_scope, pci0_scope)
    aml_append(sb_scope, build_irq_status_method())
    aml_append(sb_scope, build_iqcr_method(False))
    for i, c in enumerate("ABCDEFGH"):
        aml_append(sb_scope, build_link_dev("LNK" + c, i, aml_name("PRQ" + c)))
    for i, c in enumerate("ABCDEFGH"):
        aml_append(sb_scope, build_gsi_link_dev("GSI" + c, 0x10 + i, 0x10 + i))
    aml_append(table, sb_scope)


def build_q35_dram_controller(base: int, size: int) -> Aml:
    dev = aml_device("DRAC")
    aml_append(dev, aml_name_decl("_HID", aml_string("PNP0C01")))
    rt = aml_resource_template()
    if base + size - 1 >= (1 << 32):
        aml_append(
            rt,
            aml_qword_memory(
                AML_POS_DECODE,
                AML_MIN_FIXED,
                AML_MAX_FIXED,
                AML_NON_CACHEABLE,
                AML_READ_WRITE,
                0,
                base,
                base + size - 1,
                0,
                size,
            ),
        )
    else:
        aml_append(
            rt,
            aml_dword_memory(
                AML_POS_DECODE,
                AML_MIN_FIXED,
                AML_MAX_FIXED,
                AML_NON_CACHEABLE,
                AML_READ_WRITE,
                0,
                base,
                base + size - 1,
                0,
                size,
            ),
        )
    aml_append(dev, aml_name_decl("_CRS", rt))
    return dev


# ---------------------------------------------------------------------------
# hw/acpi/pci.c, hw/acpi/pci-bridge.c, hw/acpi/pcihp.c
# ---------------------------------------------------------------------------


def build_pci_host_bridge_osc_method(enable_native_pcie_hotplug: bool) -> Aml:
    a_cwd1 = aml_name("CDW1")
    a_ctrl = aml_local(0)
    method = aml_method("_OSC", 4, AML_NOTSERIALIZED)
    aml_append(method, aml_create_dword_field(aml_arg(3), aml_int(0), "CDW1"))
    if_ctx = aml_if(
        aml_equal(aml_arg(0), aml_touuid("33DB4D5B-1FF7-401C-9657-7441C03DD766"))
    )
    aml_append(if_ctx, aml_create_dword_field(aml_arg(3), aml_int(4), "CDW2"))
    aml_append(if_ctx, aml_create_dword_field(aml_arg(3), aml_int(8), "CDW3"))
    aml_append(if_ctx, aml_store(aml_name("CDW3"), a_ctrl))
    aml_append(
        if_ctx,
        aml_and(
            a_ctrl, aml_int(0x1E | (0x1 if enable_native_pcie_hotplug else 0x0)), a_ctrl
        ),
    )
    if_ctx2 = aml_if(aml_lnot(aml_equal(aml_arg(1), aml_int(1))))
    aml_append(if_ctx2, aml_or(a_cwd1, aml_int(0x08), a_cwd1))
    aml_append(if_ctx, if_ctx2)
    if_ctx2 = aml_if(aml_lnot(aml_equal(aml_name("CDW3"), a_ctrl)))
    aml_append(if_ctx2, aml_or(a_cwd1, aml_int(0x10), a_cwd1))
    aml_append(if_ctx, if_ctx2)
    aml_append(if_ctx, aml_store(a_ctrl, aml_name("CDW3")))
    aml_append(method, if_ctx)
    else_ctx = aml_else()
    aml_append(else_ctx, aml_or(a_cwd1, aml_int(4), a_cwd1))
    aml_append(method, else_ctx)
    aml_append(method, aml_return(aml_arg(3)))
    return method


def build_append_pci_dsm_func0_common(ctx: Aml, retvar: Aml) -> None:
    aml_append(ctx, aml_store(aml_buffer(b"\x00"), retvar))
    uuid = aml_touuid("E5C937D0-3553-4D7A-9117-EA4D19C3434D")
    ifctx1 = aml_if(aml_lnot(aml_equal(aml_arg(0), uuid)))
    aml_append(ifctx1, aml_return(retvar))
    aml_append(ctx, ifctx1)
    ifctx1 = aml_if(aml_lless(aml_arg(1), aml_int(2)))
    aml_append(ifctx1, aml_return(retvar))
    aml_append(ctx, ifctx1)


def build_pci_bridge_edsm() -> Aml:
    zero = aml_int(0)
    func = aml_arg(2)
    ret = aml_local(0)
    aidx = aml_local(1)
    params = aml_arg(4)
    method = aml_method("EDSM", 5, AML_SERIALIZED)
    ifctx = aml_if(aml_equal(func, zero))
    build_append_pci_dsm_func0_common(ifctx, ret)
    aml_append(ifctx, aml_store(aml_int(1 | (1 << 7)), aml_index(ret, zero)))
    aml_append(ifctx, aml_return(ret))
    aml_append(method, ifctx)
    ifctx = aml_if(aml_equal(func, aml_int(7)))
    pkg = aml_package(2)
    aml_append(pkg, zero)
    aml_append(pkg, aml_string(""))
    aml_append(ifctx, aml_store(pkg, ret))
    aml_append(ifctx, aml_store(aml_derefof(aml_index(params, aml_int(0))), aidx))
    aml_append(ifctx, aml_store(aidx, aml_index(ret, zero)))
    aml_append(ifctx, aml_return(ret))
    aml_append(method, ifctx)
    return method


def aml_pci_pdsm() -> Aml:
    ret, caps, acpi_index = aml_local(0), aml_local(1), aml_local(2)
    zero, one = aml_int(0), aml_int(1)
    not_supp = aml_int(0xFFFFFFFF)
    func = aml_arg(2)
    params = aml_arg(4)
    bnum = aml_derefof(aml_index(params, aml_int(0)))
    sunum = aml_derefof(aml_index(params, aml_int(1)))
    method = aml_method("PDSM", 5, AML_SERIALIZED)

    ifctx = aml_if(aml_equal(func, zero))
    build_append_pci_dsm_func0_common(ifctx, ret)
    aml_append(ifctx, aml_store(zero, caps))
    aml_append(ifctx, aml_store(aml_call2("AIDX", bnum, sunum), acpi_index))
    ifctx1 = aml_if(
        aml_lnot(
            aml_or(aml_equal(acpi_index, zero), aml_equal(acpi_index, not_supp), None)
        )
    )
    aml_append(ifctx1, aml_or(caps, one, caps))
    aml_append(ifctx1, aml_or(caps, aml_shiftleft(one, aml_int(7)), caps))
    aml_append(ifctx, ifctx1)
    aml_append(ifctx, aml_store(caps, aml_index(ret, zero)))
    aml_append(ifctx, aml_return(ret))
    aml_append(method, ifctx)

    ifctx = aml_if(aml_equal(func, aml_int(7)))
    pkg = aml_package(2)
    aml_append(ifctx, aml_store(aml_call2("AIDX", bnum, sunum), acpi_index))
    aml_append(ifctx, aml_store(pkg, ret))
    ifctx1 = aml_if(
        aml_lnot(aml_lor(aml_equal(acpi_index, zero), aml_equal(acpi_index, not_supp)))
    )
    aml_append(ifctx1, aml_store(acpi_index, aml_index(ret, zero)))
    aml_append(ifctx1, aml_store(aml_string(""), aml_index(ret, one)))
    aml_append(ifctx, ifctx1)
    aml_append(ifctx, aml_return(ret))
    aml_append(method, ifctx)
    return method


def build_acpi_pci_hotplug(table: Aml, rs: int, pcihp_addr: int) -> None:
    scope = aml_scope("_SB.PCI0")
    aml_append(scope, aml_operation_region("PCST", rs, aml_int(pcihp_addr), 0x08))
    fld = aml_field("PCST", AML_DWORD_ACC, AML_NOLOCK, AML_WRITE_AS_ZEROS)
    aml_append(fld, aml_named_field("PCIU", 32))
    aml_append(fld, aml_named_field("PCID", 32))
    aml_append(scope, fld)
    aml_append(
        scope,
        aml_operation_region(
            "SEJ", rs, aml_int(pcihp_addr + ACPI_PCIHP_SEJ_BASE), 0x04
        ),
    )
    fld = aml_field("SEJ", AML_DWORD_ACC, AML_NOLOCK, AML_WRITE_AS_ZEROS)
    aml_append(fld, aml_named_field("B0EJ", 32))
    aml_append(scope, fld)
    aml_append(
        scope,
        aml_operation_region(
            "BNMR", rs, aml_int(pcihp_addr + ACPI_PCIHP_BNMR_BASE), 0x08
        ),
    )
    fld = aml_field("BNMR", AML_DWORD_ACC, AML_NOLOCK, AML_WRITE_AS_ZEROS)
    aml_append(fld, aml_named_field("BNUM", 32))
    aml_append(fld, aml_named_field("PIDX", 32))
    aml_append(scope, fld)
    aml_append(scope, aml_mutex("BLCK", 0))

    method = aml_method("PCEJ", 2, AML_NOTSERIALIZED)
    aml_append(method, aml_acquire(aml_name("BLCK"), 0xFFFF))
    aml_append(method, aml_store(aml_arg(0), aml_name("BNUM")))
    aml_append(
        method, aml_store(aml_shiftleft(aml_int(1), aml_arg(1)), aml_name("B0EJ"))
    )
    aml_append(method, aml_release(aml_name("BLCK")))
    aml_append(method, aml_return(aml_int(0)))
    aml_append(scope, method)

    method = aml_method("AIDX", 2, AML_NOTSERIALIZED)
    aml_append(method, aml_acquire(aml_name("BLCK"), 0xFFFF))
    aml_append(method, aml_store(aml_arg(0), aml_name("BNUM")))
    aml_append(
        method, aml_store(aml_shiftleft(aml_int(1), aml_arg(1)), aml_name("PIDX"))
    )
    aml_append(method, aml_store(aml_name("PIDX"), aml_local(0)))
    aml_append(method, aml_release(aml_name("BLCK")))
    aml_append(method, aml_return(aml_local(0)))
    aml_append(scope, method)

    aml_append(scope, aml_pci_pdsm())
    aml_append(table, scope)


def build_append_pcihp_resources(scope: Aml, io_addr: int, io_len: int) -> None:
    dev = aml_device("PHPR")
    aml_append(dev, aml_name_decl("_HID", aml_string("PNP0A06")))
    aml_append(dev, aml_name_decl("_UID", aml_string("PCI Hotplug resources")))
    aml_append(dev, aml_name_decl("_STA", aml_int(0xB)))
    crs = aml_resource_template()
    aml_append(crs, aml_io(AML_DECODE16, io_addr, io_addr, 1, io_len))
    aml_append(dev, aml_name_decl("_CRS", crs))
    aml_append(scope, dev)


def build_append_notification_callback(
    parent_scope: Aml, bus: PciBus, bsel: dict[int, int]
) -> bool:
    nr_notifiers = 0
    pcnt_bus_list = []
    for br in _child_bridges(bus):
        br_scope = aml_scope(f"S{br.devfn:02X}")
        nr_notifiers += build_append_notification_callback(br_scope, br.secondary, bsel)
        if nr_notifiers:
            pcnt_bus_list.append(br)
            aml_append(parent_scope, br_scope)
    method = aml_method("PCNT", 0, AML_NOTSERIALIZED)
    if id(bus) in bsel:
        aml_append(method, aml_store(aml_int(bsel[id(bus)]), aml_name("BNUM")))
        aml_append(method, aml_call2("DVNT", aml_name("PCIU"), aml_int(1)))
        aml_append(method, aml_call2("DVNT", aml_name("PCID"), aml_int(3)))
        nr_notifiers += 1
    for br in pcnt_bus_list:
        aml_append(method, aml_name(f"^S{br.devfn:02X}.PCNT"))
    aml_append(parent_scope, method)
    return bool(nr_notifiers)


def aml_pci_device_dsm() -> Aml:
    method = aml_method("_DSM", 4, AML_SERIALIZED)
    params = aml_local(0)
    pkg = aml_package(2)
    aml_append(pkg, aml_int(0))
    aml_append(pkg, aml_int(0))
    aml_append(method, aml_store(pkg, params))
    aml_append(method, aml_store(aml_name("BSEL"), aml_index(params, aml_int(0))))
    aml_append(method, aml_store(aml_name("ASUN"), aml_index(params, aml_int(1))))
    aml_append(
        method,
        aml_return(
            aml_call5("PDSM", aml_arg(0), aml_arg(1), aml_arg(2), aml_arg(3), params)
        ),
    )
    return method


def build_append_pcihp_notify_entry(method: Aml, slot: int) -> None:
    if_ctx = aml_if(aml_and(aml_arg(0), aml_int(1 << slot), None))
    aml_append(if_ctx, aml_notify(aml_name("S%02X" % (slot << 3)), aml_arg(1)))
    aml_append(method, if_ctx)


def is_devfn_ignored_hotplug(
    devfn: int, bus: PciBus, devices: dict[int, PciDevice]
) -> bool:
    pdev = devices.get(devfn)
    if pdev is not None:
        # cold plugged bridges are not hot-pluggable; is_devfn_ignored_generic only drops hotplugged bridges
        return not pdev.hotpluggable or pdev.is_bridge
    return bool((devfn & 7) or (bus.express and (devfn >> 3) > 0))


def build_append_pcihp_slots(
    parent_scope: Aml, bus: PciBus, bsel: dict[int, int]
) -> None:
    devices = {d.devfn: d for d in bus.devices}
    aml_append(parent_scope, aml_name_decl("BSEL", aml_int(bsel[id(bus)])))
    notify_method = aml_method("DVNT", 2, AML_NOTSERIALIZED)
    for devfn in range(256):
        slot = devfn >> 3
        adr = (slot << 16) | (devfn & 7)
        if is_devfn_ignored_hotplug(devfn, bus, devices):
            continue
        if devfn in devices:
            dev = aml_scope(f"S{devfn:02X}")
        else:
            dev = aml_device(f"S{devfn:02X}")
            aml_append(dev, aml_name_decl("_ADR", aml_int(adr)))
        aml_append(dev, aml_name_decl("ASUN", aml_int(slot)))
        aml_append(dev, aml_pci_device_dsm())
        aml_append(dev, aml_name_decl("_SUN", aml_int(slot)))
        method = aml_method("_EJ0", 1, AML_NOTSERIALIZED)
        aml_append(method, aml_call2("PCEJ", aml_name("BSEL"), aml_name("_SUN")))
        aml_append(dev, method)
        build_append_pcihp_notify_entry(notify_method, slot)
        aml_append(parent_scope, dev)
    aml_append(parent_scope, notify_method)


def build_append_pci_bus_devices(
    parent_scope: Aml, bus: PciBus, ctx: _BuildCtx
) -> None:
    for pdev in sorted(bus.devices, key=lambda d: d.devfn):
        devfn = pdev.devfn
        dev = aml_device(f"S{devfn:02X}")
        aml_append(
            dev, aml_name_decl("_ADR", aml_int(((devfn >> 3) << 16) | (devfn & 7)))
        )
        call_dev_aml_func(pdev, dev, ctx)
        aml_append(parent_scope, dev)


def build_pci_bridge_aml(pdev: PciDevice, scope: Aml, ctx: _BuildCtx) -> None:
    sec_bus = pdev.secondary
    build_append_pci_bus_devices(scope, sec_bus, ctx)
    if id(sec_bus) in ctx.bsel:
        build_append_pcihp_slots(scope, sec_bus, ctx.bsel)


def build_ich9_isa_aml(scope: Aml, ctx: _BuildCtx) -> None:
    """build_ich9_isa_aml (hw/isa/lpc_ich9.c)"""
    sb_scope = aml_scope("\\_SB")
    aml_append(scope, aml_operation_region("PIRQ", AML_PCI_CONFIG, aml_int(0x60), 0x0C))
    fld = aml_field("PCI0.SF8.PIRQ", AML_BYTE_ACC, AML_NOLOCK, AML_PRESERVE)
    for c in "ABCD":
        aml_append(fld, aml_named_field("PRQ" + c, 8))
    aml_append(fld, aml_reserved_field(0x20))
    for c in "EFGH":
        aml_append(fld, aml_named_field("PRQ" + c, 8))
    aml_append(sb_scope, fld)
    aml_append(scope, sb_scope)
    # qbus_build_aml: bus children are QTAILQ_INSERT_HEAD, so newest first
    for isa in reversed(ctx.topology.isa_devices):
        if isinstance(isa, I8042):
            i8042_build_aml(isa, scope)
        else:
            rtc_build_aml(isa, scope)


def i8042_build_aml(isa: I8042, scope: Aml) -> None:
    """i8042_build_aml (hw/input/pckbd.c)"""
    crs = aml_resource_template()
    aml_append(crs, aml_io(AML_DECODE16, 0x0060, 0x0060, 0x01, 0x01))
    aml_append(crs, aml_io(AML_DECODE16, 0x0064, 0x0064, 0x01, 0x01))
    aml_append(crs, aml_irq_no_flags(isa.kbd_irq))
    kbd = aml_device("KBD")
    aml_append(kbd, aml_name_decl("_HID", aml_eisaid("PNP0303")))
    aml_append(kbd, aml_name_decl("_STA", aml_int(0xF)))
    aml_append(kbd, aml_name_decl("_CRS", crs))
    crs = aml_resource_template()
    aml_append(crs, aml_irq_no_flags(isa.mouse_irq))
    mou = aml_device("MOU")
    aml_append(mou, aml_name_decl("_HID", aml_eisaid("PNP0F13")))
    aml_append(mou, aml_name_decl("_STA", aml_int(0xF)))
    aml_append(mou, aml_name_decl("_CRS", crs))
    aml_append(scope, kbd)
    aml_append(scope, mou)


def rtc_build_aml(isa: Rtc, scope: Aml) -> None:
    """rtc_build_aml (hw/rtc/mc146818rtc.c)"""
    crs = aml_resource_template()
    aml_append(crs, aml_io(AML_DECODE16, isa.io_base, isa.io_base, 0x01, 0x08))
    aml_append(crs, aml_irq_no_flags(isa.isairq))
    dev = aml_device("RTC")
    aml_append(dev, aml_name_decl("_HID", aml_eisaid("PNP0B00")))
    aml_append(dev, aml_name_decl("_CRS", crs))
    aml_append(scope, dev)


def call_dev_aml_func(pdev: PciDevice, scope: Aml, ctx: _BuildCtx) -> None:
    """call_dev_aml_func: only devices implementing TYPE_ACPI_DEV_AML_IF emit AML."""
    if pdev.is_bridge:
        build_pci_bridge_aml(pdev, scope, ctx)
    elif pdev.kind == "lpc":
        build_ich9_isa_aml(scope, ctx)
    elif pdev.kind == "smbus":
        pass  # build_ich9_smb_aml: smbus-eeprom children emit nothing
    elif pdev.kind not in ("endpoint", "host-bridge"):
        raise NotImplementedError(f"PCI device kind {pdev.kind}")


def fw_cfg_add_acpi_dsdt(scope: Aml) -> None:
    dev = aml_device("FWCF")
    crs = aml_resource_template()
    io_size = ((FW_CFG_CTL_SIZE + 3) & ~3) + SIZEOF_DMA_ADDR_T
    aml_append(dev, aml_name_decl("_HID", aml_string("QEMU0002")))
    aml_append(dev, aml_name_decl("_STA", aml_int(0xB)))
    aml_append(crs, aml_io(AML_DECODE16, FW_CFG_IO_BASE, FW_CFG_IO_BASE, 0x01, io_size))
    aml_append(dev, aml_name_decl("_CRS", crs))
    aml_append(scope, dev)


# ---------------------------------------------------------------------------
# hw/i386/acpi-common.c, hw/acpi/cpu.c
# ---------------------------------------------------------------------------


def pc_madt_cpu_entry(
    uid: int, apic_ids: list[int], present: int, force_enabled: bool
) -> bytes:
    apic_id = apic_ids[uid]
    flags = 1 if (uid < present or force_enabled) else 0
    if apic_id < 255:
        return struct.pack("<BBBBI", 0, 8, uid & 0xFF, apic_id, flags)
    return struct.pack("<BBHIII", 9, 16, 0, apic_id, flags, uid)


def acpi_build_madt(
    tables: bytearray,
    linker: BIOSLinker,
    t: Topology,
    apic_ids: list[int],
    present: int,
) -> None:
    off = acpi_table_begin(tables, "APIC", 3, t.oem_id, t.oem_table_id)
    tables += struct.pack("<II", APIC_DEFAULT_ADDRESS, 1 if t.pic else 0)
    x2apic_mode = False
    for i in range(len(apic_ids)):
        tables += pc_madt_cpu_entry(i, apic_ids, present, False)
        if apic_ids[i] > 254:
            x2apic_mode = True
    tables += struct.pack(
        "<BBBBII", 1, 12, ACPI_BUILD_IOAPIC_ID, 0, IO_APIC_DEFAULT_ADDRESS, 0
    )
    tables += struct.pack("<BBBBIH", 2, 10, 0, 0, 2, 0)
    for i in range(1, 16):
        if ACPI_BUILD_PCI_IRQS & (1 << i):
            tables += struct.pack("<BBBBIH", 2, 10, 0, i, i, 0xD)
    if x2apic_mode:
        tables += struct.pack("<BBHIB3s", 0xA, 12, 0, 0xFFFFFFFF, 1, b"")
    else:
        tables += struct.pack("<BBBHB", 4, 6, 0xFF, 0, 1)
    acpi_table_end(linker, tables, off)


def build_cpus_aml(
    table: Aml,
    apic_ids: list[int],
    present: int,
    base_addr: int,
    res_root: str,
    event_handler_method: str,
    rs: int,
) -> None:
    zero, one = aml_int(0), aml_int(1)
    sb_scope = aml_scope("_SB")
    n = len(apic_ids)
    res = res_root + ".PRES"

    cpu_ctrl_dev = aml_device(res)
    aml_append(cpu_ctrl_dev, aml_name_decl("_HID", aml_eisaid("PNP0A06")))
    aml_append(cpu_ctrl_dev, aml_name_decl("_UID", aml_string("CPU Hotplug resources")))
    aml_append(cpu_ctrl_dev, aml_mutex("CPLK", 0))
    _require(rs == AML_SYSTEM_IO, "rs == AML_SYSTEM_IO")
    crs = aml_resource_template()
    aml_append(
        crs, aml_io(AML_DECODE16, base_addr, base_addr, 1, ACPI_CPU_HOTPLUG_REG_LEN)
    )
    aml_append(cpu_ctrl_dev, aml_name_decl("_CRS", crs))
    aml_append(
        cpu_ctrl_dev,
        aml_operation_region("PRST", rs, aml_int(base_addr), ACPI_CPU_HOTPLUG_REG_LEN),
    )
    fld = aml_field("PRST", AML_BYTE_ACC, AML_NOLOCK, AML_WRITE_AS_ZEROS)
    aml_append(fld, aml_reserved_field(ACPI_CPU_FLAGS_OFFSET_RW * 8))
    for name in ("CPEN", "CINS", "CRMV", "CEJ0", "CEJF"):
        aml_append(fld, aml_named_field(name, 1))
    aml_append(fld, aml_reserved_field(3))
    aml_append(fld, aml_named_field("CCMD", 8))
    aml_append(cpu_ctrl_dev, fld)
    fld = aml_field("PRST", AML_DWORD_ACC, AML_NOLOCK, AML_PRESERVE)
    aml_append(fld, aml_named_field("CSEL", 32))
    aml_append(fld, aml_reserved_field(4 * 8))
    aml_append(fld, aml_named_field("CDAT", 32))
    aml_append(cpu_ctrl_dev, fld)
    aml_append(sb_scope, cpu_ctrl_dev)

    cpus_dev = aml_device("\\_SB.CPUS")
    ctrl_lock = aml_name(res + ".CPLK")
    cpu_selector = aml_name(res + ".CSEL")
    is_enabled = aml_name(res + ".CPEN")
    cpu_cmd = aml_name(res + ".CCMD")
    cpu_data = aml_name(res + ".CDAT")
    ins_evt = aml_name(res + ".CINS")
    rm_evt = aml_name(res + ".CRMV")
    ej_evt = aml_name(res + ".CEJ0")

    aml_append(cpus_dev, aml_name_decl("_HID", aml_string("ACPI0010")))
    aml_append(cpus_dev, aml_name_decl("_CID", aml_eisaid("PNP0A05")))

    method = aml_method("CTFY", 2, AML_NOTSERIALIZED)
    for i in range(n):
        ifctx = aml_if(aml_equal(aml_arg(0), aml_int(i)))
        aml_append(ifctx, aml_notify(aml_name(f"C{i:03X}"), aml_arg(1)))
        aml_append(method, ifctx)
    aml_append(cpus_dev, method)

    method = aml_method("CSTA", 1, AML_SERIALIZED)
    sta = aml_local(0)
    aml_append(method, aml_acquire(ctrl_lock, 0xFFFF))
    aml_append(method, aml_store(aml_arg(0), cpu_selector))
    aml_append(method, aml_store(zero, sta))
    ifctx = aml_if(aml_equal(is_enabled, one))
    aml_append(ifctx, aml_store(aml_int(0xF), sta))
    aml_append(method, ifctx)
    aml_append(method, aml_release(ctrl_lock))
    aml_append(method, aml_return(sta))
    aml_append(cpus_dev, method)

    method = aml_method("CEJ0", 1, AML_SERIALIZED)
    aml_append(method, aml_acquire(ctrl_lock, 0xFFFF))
    aml_append(method, aml_store(aml_arg(0), cpu_selector))
    aml_append(method, aml_store(one, ej_evt))
    aml_append(method, aml_release(ctrl_lock))
    aml_append(cpus_dev, method)

    method = aml_method("CSCN", 0, AML_SERIALIZED)
    max_cpus_per_pass = 255
    has_event = aml_local(0)
    dev_chk, eject_req = aml_int(1), aml_int(3)
    next_cpu_cmd = aml_int(CPHP_GET_NEXT_CPU_WITH_EVENT_CMD)
    num_added_cpus, cpu_idx, uid, has_job = (
        aml_local(1),
        aml_local(2),
        aml_local(3),
        aml_local(4),
    )
    new_cpus, ej_cpus = aml_name("CNEW"), aml_name("CEJL")
    num_ej_cpus = aml_local(5)
    aml_append(method, aml_acquire(ctrl_lock, 0xFFFF))
    aml_append(method, aml_name_decl("CNEW", aml_package(max_cpus_per_pass)))
    aml_append(method, aml_name_decl("CEJL", aml_package(max_cpus_per_pass)))
    aml_append(method, aml_store(zero, uid))
    aml_append(method, aml_store(one, has_job))
    while_ctx2 = aml_while(aml_equal(has_job, one))
    aml_append(while_ctx2, aml_store(zero, has_job))
    aml_append(while_ctx2, aml_store(one, has_event))
    aml_append(while_ctx2, aml_store(zero, num_added_cpus))
    aml_append(while_ctx2, aml_store(zero, num_ej_cpus))
    while_ctx = aml_while(
        aml_land(aml_equal(has_event, one), aml_lless(uid, aml_int(n)))
    )
    aml_append(while_ctx, aml_store(zero, has_event))
    aml_append(while_ctx, aml_store(uid, cpu_selector))
    aml_append(while_ctx, aml_store(next_cpu_cmd, cpu_cmd))
    ifctx = aml_if(aml_lless(cpu_data, uid))
    aml_append(ifctx, aml_break())
    aml_append(while_ctx, ifctx)
    ifctx = aml_if(
        aml_lor(
            aml_equal(num_added_cpus, aml_int(max_cpus_per_pass)),
            aml_equal(num_ej_cpus, aml_int(max_cpus_per_pass)),
        )
    )
    aml_append(ifctx, aml_store(one, has_job))
    aml_append(ifctx, aml_break())
    aml_append(while_ctx, ifctx)
    aml_append(while_ctx, aml_store(cpu_data, uid))
    ifctx = aml_if(aml_equal(ins_evt, one))
    aml_append(ifctx, aml_store(uid, aml_index(new_cpus, num_added_cpus)))
    aml_append(ifctx, aml_increment(num_added_cpus))
    aml_append(ifctx, aml_store(one, has_event))
    aml_append(while_ctx, ifctx)
    ifctx = aml_if(aml_equal(rm_evt, one))
    aml_append(ifctx, aml_store(uid, aml_index(ej_cpus, num_ej_cpus)))
    aml_append(ifctx, aml_increment(num_ej_cpus))
    aml_append(ifctx, aml_store(one, has_event))
    aml_append(while_ctx, ifctx)
    aml_append(while_ctx, aml_increment(uid))
    aml_append(while_ctx2, while_ctx)
    aml_append(while_ctx2, aml_store(zero, cpu_idx))
    while_ctx = aml_while(aml_lless(cpu_idx, num_added_cpus))
    aml_append(while_ctx, aml_store(aml_derefof(aml_index(new_cpus, cpu_idx)), uid))
    aml_append(while_ctx, aml_call2("CTFY", uid, dev_chk))
    aml_append(while_ctx, aml_store(uid, aml_debug()))
    aml_append(while_ctx, aml_store(uid, cpu_selector))
    aml_append(while_ctx, aml_store(one, ins_evt))
    aml_append(while_ctx, aml_increment(cpu_idx))
    aml_append(while_ctx2, while_ctx)
    aml_append(while_ctx2, aml_store(zero, cpu_idx))
    while_ctx = aml_while(aml_lless(cpu_idx, num_ej_cpus))
    aml_append(while_ctx, aml_store(aml_derefof(aml_index(ej_cpus, cpu_idx)), uid))
    aml_append(while_ctx, aml_call2("CTFY", uid, eject_req))
    aml_append(while_ctx, aml_store(uid, cpu_selector))
    aml_append(while_ctx, aml_store(one, rm_evt))
    aml_append(while_ctx, aml_increment(cpu_idx))
    aml_append(while_ctx2, while_ctx)
    aml_append(method, while_ctx2)
    aml_append(method, aml_release(ctrl_lock))
    aml_append(cpus_dev, method)

    method = aml_method("COST", 4, AML_SERIALIZED)
    aml_append(method, aml_acquire(ctrl_lock, 0xFFFF))
    aml_append(method, aml_store(aml_arg(0), cpu_selector))
    aml_append(method, aml_store(aml_int(CPHP_OST_EVENT_CMD), cpu_cmd))
    aml_append(method, aml_store(aml_arg(1), cpu_data))
    aml_append(method, aml_store(aml_int(CPHP_OST_STATUS_CMD), cpu_cmd))
    aml_append(method, aml_store(aml_arg(2), cpu_data))
    aml_append(method, aml_release(ctrl_lock))
    aml_append(cpus_dev, method)

    for i in range(n):
        uid_i = aml_int(i)
        if apic_ids[i] < 255:
            dev = aml_processor(i, 0, 0, f"C{i:03X}")
        else:
            dev = aml_device(f"C{i:03X}")
            aml_append(dev, aml_name_decl("_HID", aml_string("ACPI0007")))
            aml_append(dev, aml_name_decl("_UID", uid_i))
        method = aml_method("_STA", 0, AML_SERIALIZED)
        aml_append(method, aml_return(aml_call1("CSTA", uid_i)))
        aml_append(dev, method)
        aml_append(
            dev,
            aml_name_decl(
                "_MAT", aml_buffer(pc_madt_cpu_entry(i, apic_ids, present, True))
            ),
        )
        if i != 0:
            method = aml_method("_EJ0", 1, AML_NOTSERIALIZED)
            aml_append(method, aml_call1("CEJ0", uid_i))
            aml_append(dev, method)
        method = aml_method("_OST", 3, AML_SERIALIZED)
        aml_append(method, aml_call4("COST", uid_i, aml_arg(0), aml_arg(1), aml_arg(2)))
        aml_append(dev, method)
        aml_append(cpus_dev, dev)
    aml_append(sb_scope, cpus_dev)
    aml_append(table, sb_scope)

    method = aml_method(event_handler_method, 0, AML_NOTSERIALIZED)
    aml_append(method, aml_call0("\\_SB.CPUS.CSCN"))
    aml_append(table, method)


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------


@dataclass
class _BuildCtx:
    topology: Topology
    bsel: dict[int, int]


def build_facs(tables: bytearray) -> None:
    tables += b"FACS" + struct.pack("<IIIII", 64, 0, 0, 0, 0) + bytes(40)


def build_dsdt(
    tables: bytearray,
    linker: BIOSLinker,
    t: Topology,
    apic_ids: list[int],
    present: int,
    pci_hole: tuple[int, int],
    pci_hole64: tuple[int, int] | None,
) -> None:
    pcihp_io_base, pcihp_io_len = ACPI_PCIHP_ADDR_ICH9, ACPI_PCIHP_SIZE
    gpe0_addr = t.pm_io_base + ICH9_PMIO_GPE0_STS
    gpe0_bit_width = ICH9_PMIO_GPE0_LEN * 8
    ctx = _BuildCtx(t, acpi_set_bsel(t.root, t))
    off = acpi_table_begin(tables, "DSDT", 1, t.oem_id, t.oem_table_id)
    dsdt = Aml()

    build_dbg_aml(dsdt)
    sb_scope = aml_scope("_SB")
    dev = aml_device("PCI0")
    aml_append(dev, aml_name_decl("_HID", aml_eisaid("PNP0A08")))
    aml_append(dev, aml_name_decl("_CID", aml_eisaid("PNP0A03")))
    aml_append(dev, aml_name_decl("_UID", aml_int(t.pci_root_uid)))
    aml_append(dev, build_pci_host_bridge_osc_method(not t.pcihp_bridge))
    aml_append(dev, build_pci_bridge_edsm())
    aml_append(sb_scope, dev)
    aml_append(sb_scope, build_q35_dram_controller(t.mcfg_base, t.mcfg_size))
    aml_append(dsdt, sb_scope)
    build_acpi_pci_hotplug(dsdt, AML_SYSTEM_IO, pcihp_io_base)
    build_q35_pci0_int(dsdt)

    scope = aml_scope("_GPE")
    aml_append(scope, aml_name_decl("_HID", aml_string("ACPI0006")))
    aml_append(dsdt, scope)

    build_cpus_aml(
        dsdt,
        apic_ids,
        present,
        ICH9_CPU_HOTPLUG_IO_BASE,
        "\\_SB.PCI0",
        "\\_GPE._E02",
        AML_SYSTEM_IO,
    )

    root_bus_limit = 0xFF
    mem_ranges = [(t.mcfg_base, t.mcfg_base + t.mcfg_size - 1)]
    scope = aml_scope("\\_SB.PCI0")
    crs = aml_resource_template()
    aml_append(
        crs,
        aml_word_bus_number(
            AML_MIN_FIXED,
            AML_MAX_FIXED,
            AML_POS_DECODE,
            0x0000,
            0x0,
            root_bus_limit,
            0x0000,
            root_bus_limit + 1,
        ),
    )
    aml_append(crs, aml_io(AML_DECODE16, 0x0CF8, 0x0CF8, 0x01, 0x08))
    aml_append(
        crs,
        aml_word_io(
            AML_MIN_FIXED,
            AML_MAX_FIXED,
            AML_POS_DECODE,
            AML_ENTIRE_RANGE,
            0x0000,
            0x0000,
            0x0CF7,
            0x0000,
            0x0CF8,
        ),
    )
    for base, limit in crs_replace_with_free_ranges([], 0x0D00, 0xFFFF):
        aml_append(
            crs,
            aml_word_io(
                AML_MIN_FIXED,
                AML_MAX_FIXED,
                AML_POS_DECODE,
                AML_ENTIRE_RANGE,
                0x0000,
                base,
                limit,
                0x0000,
                limit - base + 1,
            ),
        )
    aml_append(
        crs,
        aml_dword_memory(
            AML_POS_DECODE,
            AML_MIN_FIXED,
            AML_MAX_FIXED,
            AML_CACHEABLE,
            AML_READ_WRITE,
            0,
            0x000A0000,
            0x000BFFFF,
            0,
            0x00020000,
        ),
    )
    for base, limit in crs_replace_with_free_ranges(
        mem_ranges, pci_hole[0], pci_hole[1]
    ):
        aml_append(
            crs,
            aml_dword_memory(
                AML_POS_DECODE,
                AML_MIN_FIXED,
                AML_MAX_FIXED,
                AML_NON_CACHEABLE,
                AML_READ_WRITE,
                0,
                base,
                limit,
                0,
                limit - base + 1,
            ),
        )
    if pci_hole64 is not None and pci_hole64[0] <= pci_hole64[1]:
        for base, limit in crs_replace_with_free_ranges(
            [], pci_hole64[0], pci_hole64[1]
        ):
            aml_append(
                crs,
                aml_qword_memory(
                    AML_POS_DECODE,
                    AML_MIN_FIXED,
                    AML_MAX_FIXED,
                    AML_CACHEABLE,
                    AML_READ_WRITE,
                    0,
                    base,
                    limit,
                    0,
                    limit - base + 1,
                ),
            )
    aml_append(scope, aml_name_decl("_CRS", crs))

    dev = aml_device("GPE0")
    aml_append(dev, aml_name_decl("_HID", aml_string("PNP0A06")))
    aml_append(dev, aml_name_decl("_UID", aml_string("GPE0 resources")))
    aml_append(dev, aml_name_decl("_STA", aml_int(0xB)))
    crs = aml_resource_template()
    aml_append(crs, aml_io(AML_DECODE16, gpe0_addr, gpe0_addr, 1, gpe0_bit_width // 8))
    aml_append(dev, aml_name_decl("_CRS", crs))
    aml_append(scope, dev)
    if pcihp_io_len:
        build_append_pcihp_resources(scope, pcihp_io_base, pcihp_io_len)
    aml_append(dsdt, scope)

    scope = aml_scope("\\")
    if not t.s3_disabled:
        pkg = aml_package(4)
        for v in (1, 1, 0, 0):
            aml_append(pkg, aml_int(v))
        aml_append(scope, aml_name_decl("_S3", pkg))
    if not t.s4_disabled:
        pkg = aml_package(4)
        for v in (t.s4_val, t.s4_val, 0, 0):
            aml_append(pkg, aml_int(v))
        aml_append(scope, aml_name_decl("_S4", pkg))
    pkg = aml_package(4)
    for v in (0, 0, 0, 0):
        aml_append(pkg, aml_int(v))
    aml_append(scope, aml_name_decl("_S5", pkg))
    aml_append(dsdt, scope)

    scope = aml_scope("\\_SB.PCI0")
    fw_cfg_add_acpi_dsdt(scope)
    aml_append(dsdt, scope)

    sb_scope = aml_scope("\\_SB")
    ascope = aml_scope("PCI0")
    build_append_pci_bus_devices(ascope, t.root, ctx)
    if id(t.root) in ctx.bsel:
        build_append_pcihp_slots(ascope, t.root, ctx.bsel)
    aml_append(sb_scope, ascope)
    aml_append(dsdt, sb_scope)

    scope = aml_scope("\\_SB.PCI0")
    has_pcnt = build_append_notification_callback(scope, t.root, ctx.bsel)
    if has_pcnt:
        aml_append(dsdt, scope)
    scope = aml_scope("_GPE")
    method = aml_method("_E01", 0, AML_NOTSERIALIZED)
    if has_pcnt:
        aml_append(method, aml_acquire(aml_name("\\_SB.PCI0.BLCK"), 0xFFFF))
        aml_append(method, aml_call0("\\_SB.PCI0.PCNT"))
        aml_append(method, aml_release(aml_name("\\_SB.PCI0.BLCK")))
    aml_append(scope, method)
    aml_append(dsdt, scope)

    tables += dsdt.buf
    acpi_table_end(linker, tables, off)


def build_fadt(
    tables: bytearray,
    linker: BIOSLinker,
    t: Topology,
    max_cpus: int,
    facs: int,
    dsdt: int,
) -> None:
    """build_fadt with init_common_fadt_data + acpi_get_pm_info (ICH9 LPC, rev 3)"""
    io = t.pm_io_base
    flags = (
        (1 << ACPI_FADT_F_WBINVD)
        | (1 << ACPI_FADT_F_PROC_C1)
        | (1 << ACPI_FADT_F_SLP_BUTTON)
        | (1 << ACPI_FADT_F_RTC_S4)
        | (1 << ACPI_FADT_F_USE_PLATFORM_CLOCK)
        | ((1 << ACPI_FADT_F_FORCE_APIC_CLUSTER_MODEL) if max_cpus > 8 else 0)
        | (1 << ACPI_FADT_F_RESET_REG_SUP)
    )
    iapc_boot_arch = (
        (0x1 << 1) if any(isinstance(d, I8042) for d in t.isa_devices) else 0x0
    )
    pm1a_evt = (AML_AS_SYSTEM_IO, 4 * 8, 0, 0, io)
    pm1a_cnt = (AML_AS_SYSTEM_IO, 2 * 8, 0, 0, io + 0x04)
    pm_tmr = (AML_AS_SYSTEM_IO, 4 * 8, 0, 0, io + 0x08)
    gpe0_blk = (AML_AS_SYSTEM_IO, ICH9_PMIO_GPE0_LEN * 8, 0, 0, io + ICH9_PMIO_GPE0_STS)
    reset_reg = (AML_AS_SYSTEM_IO, 8, 0, 0, ICH9_RST_CNT_IOPORT)
    zero_gas = build_append_gas(AML_AS_SYSTEM_MEMORY, 0, 0, 0, 0)

    off = acpi_table_begin(tables, "FACP", 3, t.oem_id, t.oem_table_id)
    p_facs = len(tables)
    tables += build_append_int_noprefix(0, 4)
    linker.add_pointer(ACPI_BUILD_TABLE_FILE, p_facs, 4, ACPI_BUILD_TABLE_FILE, facs)
    p_dsdt = len(tables)
    tables += build_append_int_noprefix(0, 4)
    linker.add_pointer(ACPI_BUILD_TABLE_FILE, p_dsdt, 4, ACPI_BUILD_TABLE_FILE, dsdt)
    tables += struct.pack("<BBHIBBBB", 1, 0, t.sci_int, 0, 0, 0, 0, 0)
    tables += struct.pack(
        "<8I", pm1a_evt[4], 0, pm1a_cnt[4], 0, 0, pm_tmr[4], gpe0_blk[4], 0
    )
    tables += struct.pack(
        "<8B",
        pm1a_evt[1] // 8,
        pm1a_cnt[1] // 8,
        0,
        pm_tmr[1] // 8,
        gpe0_blk[1] // 8,
        0,
        0,
        0,
    )
    tables += struct.pack("<HHHHBBBBB", 0xFFF, 0xFFF, 0, 0, 0, 0, 0, 0, RTC_CENTURY)
    tables += struct.pack("<HBI", iapc_boot_arch, 0, flags)
    tables += build_append_gas(*reset_reg) + bytes([0xF]) + bytes(3)
    tables += build_append_int_noprefix(0, 8)
    p_xdsdt = len(tables)
    tables += build_append_int_noprefix(0, 8)
    linker.add_pointer(ACPI_BUILD_TABLE_FILE, p_xdsdt, 8, ACPI_BUILD_TABLE_FILE, dsdt)
    tables += (
        build_append_gas(*pm1a_evt)
        + zero_gas
        + build_append_gas(*pm1a_cnt)
        + zero_gas
        + zero_gas
    )
    tables += build_append_gas(*pm_tmr) + build_append_gas(*gpe0_blk) + zero_gas
    acpi_table_end(linker, tables, off)


def build_mcfg(
    tables: bytearray,
    linker: BIOSLinker,
    base: int,
    size: int,
    oem_id: str,
    oem_table_id: str,
) -> None:
    off = acpi_table_begin(tables, "MCFG", 1, oem_id, oem_table_id)
    tables += struct.pack(
        "<QQHBBI",
        0,
        base,
        0,
        0,
        ((size - 1) >> PCIE_MMCFG_BUS_BIT) & PCIE_MMCFG_BUS_MASK,
        0,
    )
    acpi_table_end(linker, tables, off)


def build_waet(
    tables: bytearray, linker: BIOSLinker, oem_id: str, oem_table_id: str
) -> None:
    off = acpi_table_begin(tables, "WAET", 1, oem_id, oem_table_id)
    tables += struct.pack("<I", 1 << 1)
    acpi_table_end(linker, tables, off)


def build_rsdt(
    tables: bytearray,
    linker: BIOSLinker,
    table_offsets: list[int],
    oem_id: str,
    oem_table_id: str,
) -> None:
    off = acpi_table_begin(tables, "RSDT", 1, oem_id, oem_table_id)
    for ref in table_offsets:
        entry = len(tables)
        tables += build_append_int_noprefix(0, 4)
        linker.add_pointer(ACPI_BUILD_TABLE_FILE, entry, 4, ACPI_BUILD_TABLE_FILE, ref)
    acpi_table_end(linker, tables, off)


def build_rsdp(rsdp: bytearray, linker: BIOSLinker, oem_id: str, rsdt: int) -> None:
    """build_rsdp, revision 0"""
    tbl_off = len(rsdp)
    linker.alloc(ACPI_BUILD_RSDP_FILE, rsdp, 16, True)
    rsdp += (
        b"RSD PTR "
        + b"\x00"
        + oem_id.encode()[:6]
        + b"\x00"
        + build_append_int_noprefix(0, 4)
    )
    linker.add_pointer(
        ACPI_BUILD_RSDP_FILE, tbl_off + 16, 4, ACPI_BUILD_TABLE_FILE, rsdt
    )
    linker.add_checksum(ACPI_BUILD_RSDP_FILE, tbl_off, 20, 8)


def _round_up(v: int, a: int) -> int:
    return (v + a - 1) // a * a


def q35_below_4g_mem_size(ram_bytes: int, max_ram_below_4g: int = 4 * GiB) -> int:
    """pc_q35_init low/high RAM split."""
    lowmem = 0x80000000 if ram_bytes >= 0xB0000000 else 0xB0000000
    lowmem = min(lowmem, max_ram_below_4g)
    return min(lowmem, ram_bytes)


def q35_pci_holes(
    t: Topology, ram_bytes: int, hole64: tuple[int, int] | None
) -> tuple[tuple[int, int], tuple[int, int] | None]:
    """acpi_get_pci_holes using the q35 host getters; returns ((lob, upb), (lob, upb) or None)."""
    below_4g = q35_below_4g_mem_size(ram_bytes, t.max_ram_below_4g)
    pci_hole = (below_4g, IO_APIC_DEFAULT_ADDRESS - 1)
    if hole64 is not None and hole64[0] < hole64[1]:
        w64_lob, w64_end = hole64
    else:
        w64_lob, w64_end = 0, 0
    start = w64_lob
    if not start and t.pci_hole64_fix:
        # pc_pci_hole64_start without reserved device memory, CXL or SGX (all guarded)
        above_4g = ram_bytes - below_4g
        start = _round_up(4 * GiB + above_4g, GiB)
    end = w64_end
    hole64_end = _round_up(start + t.pci_hole64_size, 1 << 30)
    if t.pci_hole64_fix and end < hole64_end:
        end = hole64_end
    if not start and not end:
        return pci_hole, None
    return pci_hole, (start, end - 1)


def build(
    topology: Topology,
    *,
    vcpus: int,
    ram_bytes: int,
    hole64: tuple[int, int] | None,
    max_cpus: int | None = None,
    apic_ids: list[int] | None = None,
) -> dict[str, bytes]:
    """acpi_build(): returns the three fw_cfg blobs.

    hole64 is the 64-bit MMIO window the firmware programmed, [start, end) as
    reported by pci_bus_get_w64_range (lowest 64-bit BAR / prefetch window base,
    highest limit + 1), or None if nothing was placed above 4 GiB.
    apic_ids defaults to 0..max_cpus-1, which is what "-smp N" yields on
    pc-q35-11.0 (one socket, N cores, one thread).
    """
    t = topology
    _check_supported(t)
    max_cpus = vcpus if max_cpus is None else max_cpus
    _require(0 < vcpus <= max_cpus, "0 < vcpus <= max_cpus")
    apic_ids = list(range(max_cpus)) if apic_ids is None else list(apic_ids)
    _require(len(apic_ids) == max_cpus, "len(apic_ids) == max_cpus")
    pci_hole, pci_hole64 = q35_pci_holes(t, ram_bytes, hole64)

    linker = BIOSLinker()
    tables = bytearray()
    rsdp = bytearray()
    table_offsets: list[int] = []
    linker.alloc(ACPI_BUILD_TABLE_FILE, tables, 64, False)

    facs = len(tables)
    build_facs(tables)
    dsdt = len(tables)
    build_dsdt(tables, linker, t, apic_ids, vcpus, pci_hole, pci_hole64)
    table_offsets.append(len(tables))
    build_fadt(tables, linker, t, max_cpus, facs, dsdt)
    table_offsets.append(len(tables))
    acpi_build_madt(tables, linker, t, apic_ids, vcpus)
    table_offsets.append(len(tables))
    build_mcfg(tables, linker, t.mcfg_base, t.mcfg_size, t.oem_id, t.oem_table_id)
    table_offsets.append(len(tables))
    build_waet(tables, linker, t.oem_id, t.oem_table_id)
    rsdt = len(tables)
    build_rsdt(tables, linker, table_offsets, t.oem_id, t.oem_table_id)
    build_rsdp(rsdp, linker, t.oem_id, rsdt)

    tables += bytes(_round_up(len(tables), ACPI_BUILD_TABLE_SIZE) - len(tables))
    linker.cmd_blob += bytes(
        _round_up(len(linker.cmd_blob), ACPI_BUILD_ALIGN_SIZE) - len(linker.cmd_blob)
    )
    return {
        ACPI_BUILD_TABLE_FILE: bytes(tables),
        ACPI_BUILD_RSDP_FILE: bytes(rsdp),
        ACPI_BUILD_LOADER_FILE: bytes(linker.cmd_blob),
    }
