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

"""CLI entry point for cvm-measure.

Usage:
    cvm-measure tdx --firmware OVMF.fd --uki BOOTX64.EFI --baseline baseline.json --ram 234
    cvm-measure tdx --firmware OVMF.fd --uki BOOTX64.EFI --baseline baseline.json --ram 234 --output-format json
    cvm-measure tdx --firmware OVMF.fd --ram 234 --mode mrtd
    cvm-measure tdx extract-baseline --ccel ccel.bin --machine-type a3-highgpu-1g -o baseline.json
    cvm-measure tdx extract-baseline --ccel ccel.bin --machine-type a3-highgpu-1g --firmware-sha384 abc...def
    cvm-measure tdx replay --ccel ccel.bin
    cvm-measure extract-uki --disk disk.raw --output BOOTX64.EFI
    cvm-measure extract-uki --disk disk.tar.gz --output BOOTX64.EFI
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .disk import DEFAULT_MAX_EXTRACT_BYTES


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="cvm-measure",
        description="Compute expected confidential VM register values from published inputs.",
    )
    parser.add_argument("--version", action="version", version=f"cvm-measure {__version__}")

    sub = parser.add_subparsers(dest="subcommand", help="Subcommand")

    # -- extract-uki (top-level, not TEE-specific) -----------------------------
    uki_parser = sub.add_parser(
        "extract-uki",
        help="Extract UKI (BOOTX64.EFI) from a pod VM disk image",
    )
    uki_parser.add_argument("--disk", required=True, type=Path, help="Path to disk image (.raw or .tar.gz)")
    uki_parser.add_argument("--output", "-o", required=True, type=Path, help="Output path for extracted UKI")

    # -- tdx -------------------------------------------------------------------
    tdx_parser = sub.add_parser("tdx", help="Intel TDX measurement")
    tdx_sub = tdx_parser.add_subparsers(dest="command", required=False)

    # -- tdx (default: compute) ------------------------------------------------
    _add_compute_args(tdx_parser)

    # -- tdx extract-baseline --------------------------------------------------
    eb_parser = tdx_sub.add_parser(
        "extract-baseline",
        help="Extract baseline from a CCEL binary",
    )
    eb_parser.add_argument("--ccel", required=True, type=Path, help="Path to CCEL binary")
    eb_parser.add_argument("--machine-type", required=True, help="Machine type label (e.g. a3-highgpu-1g)")
    eb_parser.add_argument("--firmware-sha384", type=str, default=None, help="SHA-384 of OVMF firmware binary (set in baseline if provided)")
    eb_parser.add_argument("--provider", type=str, default=None, help="Cloud provider (auto-detected from machine type if omitted)")
    eb_parser.add_argument("--platform", type=str, default=None, help="TEE platform (auto-set to 'tdx' if omitted)")
    eb_parser.add_argument("-o", "--output", type=Path, default=None, help="Output JSON path (default: stdout)")

    # -- tdx replay ------------------------------------------------------------
    rp_parser = tdx_sub.add_parser(
        "replay",
        help="Replay a CCEL event log to compute RTMR values",
    )
    rp_parser.add_argument("--ccel", required=True, type=Path, help="Path to CCEL binary")

    args = parser.parse_args(argv)

    if args.subcommand is None:
        parser.print_help()
        sys.exit(1)

    if args.subcommand == "extract-uki":
        _cmd_extract_uki(args)
    elif args.subcommand == "tdx":
        if args.command == "extract-baseline":
            _cmd_extract_baseline(args)
        elif args.command == "replay":
            _cmd_replay(args)
        else:
            _cmd_compute(args, tdx_parser)


def _add_compute_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--firmware", type=Path, help="Path to OVMF firmware binary")
    parser.add_argument("--uki", type=Path, help="Path to UKI (BOOTX64.EFI)")
    parser.add_argument(
        "--disk",
        type=Path,
        default=None,
        help="Path to pod VM disk image (.raw or .tar.gz); computes GPT digest for RTMR[1]",
    )
    parser.add_argument(
        "--max-extract-bytes",
        type=int,
        default=DEFAULT_MAX_EXTRACT_BYTES,
        help=(
            "Cap on bytes unpacked from a .tar.gz disk image "
            f"(default: {DEFAULT_MAX_EXTRACT_BYTES})"
        ),
    )
    parser.add_argument("--baseline", type=Path, help="Path to baseline JSON")
    parser.add_argument("--ram", type=int, help="Total guest RAM in GiB")
    parser.add_argument("--numa-nodes", type=int, default=1, help="Number of NUMA nodes (default: 1)")
    parser.add_argument("--max-per-node", type=int, default=None, help="Max GiB per NUMA node (default: same as --ram)")
    parser.add_argument(
        "--mode",
        choices=["all", "mrtd"],
        default="all",
        help="What to compute: 'all' (default) or 'mrtd' only",
    )
    parser.add_argument("--rtmr3", type=str, default=None, help="Pre-computed RTMR[3] hex (96 chars)")
    parser.add_argument("--initdata", type=Path, default=None, help="Path to initdata TOML; computes RTMR[3] automatically (mutually exclusive with --rtmr3)")
    parser.add_argument(
        "--output-format",
        choices=["text", "json"],
        default="text",
        help="Output format: 'text' (default) or 'json'",
    )


def _resolve_rtmr3(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str | None:
    """Resolve RTMR[3] from --initdata or --rtmr3 (mutually exclusive)."""
    if args.initdata is not None and args.rtmr3 is not None:
        parser.error("--initdata and --rtmr3 are mutually exclusive")

    if args.initdata is not None:
        _require_file(args.initdata, "--initdata")

        from .tdx.initdata import compute_digest
        from .tdx.rtmr import SHA384_SIZE, extend_rtmr

        digest = compute_digest(args.initdata)
        rtmr3 = extend_rtmr(bytes(SHA384_SIZE), digest)
        return rtmr3.hex()

    return str(args.rtmr3) if args.rtmr3 is not None else None


def _require_file(path: Path, flag: str) -> None:
    if not path.exists():
        print(f"error: {flag} file not found: {path}", file=sys.stderr)
        sys.exit(1)


def _cmd_compute(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.firmware is None:
        parser.error("--firmware is required")
    if args.ram is None:
        parser.error("--ram is required")

    _require_file(args.firmware, "--firmware")
    firmware = args.firmware.read_bytes()

    if args.mode == "mrtd":
        from .tdx import compute_mrtd
        result = compute_mrtd(
            firmware,
            ram_gib=args.ram,
            numa_nodes=args.numa_nodes,
            max_per_node_gib=args.max_per_node,
        )
        _output_registers({"mrtd": result}, args.output_format)
        return

    if args.uki is None:
        parser.error("--uki is required for full computation (use --mode mrtd to compute MRTD only)")
    if args.baseline is None:
        parser.error("--baseline is required for full computation (use --mode mrtd to compute MRTD only)")

    rtmr3_hex = _resolve_rtmr3(args, parser)

    from .tdx import compute_all_registers, load_baseline

    _require_file(args.uki, "--uki")
    _require_file(args.baseline, "--baseline")

    uki = args.uki.read_bytes()
    baseline = load_baseline(args.baseline)
    gpt_digest_hex = None
    if args.disk is not None:
        _require_file(args.disk, "--disk")
        from .disk import compute_gpt_digest
        gpt_digest_hex = compute_gpt_digest(args.disk, args.max_extract_bytes).hex()

    regs = compute_all_registers(
        firmware,
        uki,
        baseline,
        ram_gib=args.ram,
        numa_nodes=args.numa_nodes,
        max_per_node_gib=args.max_per_node,
        rtmr3_hex=rtmr3_hex,
        gpt_digest_hex=gpt_digest_hex,
    )

    _output_registers(regs.as_dict(), args.output_format)


def _output_registers(data: dict[str, str], fmt: str) -> None:
    if fmt == "json":
        import json
        print(json.dumps(data, indent=2))
    else:
        for key, value in data.items():
            print(f"{key}:  {value}" if key == "mrtd" else f"{key}: {value}")


def _cmd_extract_baseline(args: argparse.Namespace) -> None:
    import json

    from .tdx.baseline import extract_from_ccel, save

    _require_file(args.ccel, "--ccel")
    ccel_data = args.ccel.read_bytes()
    baseline = extract_from_ccel(ccel_data, args.machine_type)

    if args.firmware_sha384 is not None:
        baseline.firmware_sha384 = args.firmware_sha384
    if args.provider is not None:
        baseline.provider = args.provider
    if args.platform is not None:
        baseline.platform = args.platform

    if args.output is not None:
        save(baseline, args.output)
        print(f"Baseline written to {args.output}", file=sys.stderr)
    else:
        print(json.dumps(baseline.to_dict(), indent=2))


def _cmd_replay(args: argparse.Namespace) -> None:
    from .tdx.ccel import parse_event_log
    from .tdx.rtmr import replay_event_log

    _require_file(args.ccel, "--ccel")
    ccel_data = args.ccel.read_bytes()
    log = parse_event_log(ccel_data)
    rtmrs = replay_event_log(log)

    for i in sorted(rtmrs):
        print(f"rtmr{i}: {rtmrs[i].hex()}")


def _cmd_extract_uki(args: argparse.Namespace) -> None:
    from .disk import extract_uki

    _require_file(args.disk, "--disk")
    digest = extract_uki(args.disk, args.output)
    size = args.output.stat().st_size
    print(f"Size: {size} bytes", file=sys.stderr)
    print(f"SHA-384: {digest.hex()}", file=sys.stderr)
