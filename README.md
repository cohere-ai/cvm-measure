# cvm-measure

![](banner.png)

[![CI](https://github.com/cohere-ai/cvm-measure/actions/workflows/ci.yaml/badge.svg)](https://github.com/cohere-ai/cvm-measure/actions/workflows/ci.yaml)
[![PyPI](https://img.shields.io/pypi/v/cvm-measure)](https://pypi.org/project/cvm-measure/)
![License](https://img.shields.io/github/license/cohere-ai/cvm-measure)

Compute expected confidential VM register values from published inputs, entirely offline. `cvm-measure` reads the artifacts a CVM boots and produces the hex register values a correctly-launched VM should report, letting you verify attestation without booting anything.

**Zero Python dependencies.** Python 3.10+ standard library only. Extracting the UKI out of a disk image shells out to `mcopy` from [mtools](https://www.gnu.org/software/mtools/); pass `--uki` directly to avoid it.

## Supported Hardware

| Platform | Technology | Registers | Inputs needed | Status |
|----------|------------|-----------|---------------|--------|
| Intel | [TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) | MRTD, RTMR[0-3] | Firmware, UKI, baseline, RAM topology | Supported |
| AMD | [SEV-SNP](https://www.amd.com/en/developer/sev.html) on Azure | vTPM PCR 4, 5, 8, 9, 11 | Disk image | Supported |

Each platform is a subcommand, `cvm-measure tdx` and `cvm-measure azure-snp`, and the sections below are organised the same way. Azure needs no firmware and no baseline: Microsoft publishes no firmware blob, and every event in the registers above is either a TCG-defined constant or a function of the image. See [registers left alone](#azure-sev-snp-registers-left-alone) for the ones it does not compute, and why.

## Install

```bash
pip install cvm-measure
```

Or from source:

```bash
git clone https://github.com/cohere-ai/cvm-measure.git
cd cvm-measure
pip install -e .
```

## CLI Usage

### Intel TDX

#### Compute all registers

```bash
cvm-measure tdx \
  --firmware OVMF.fd \
  --uki BOOTX64.EFI \
  --baseline baseline.json \
  --ram 234
```

Output:

```
mrtd:  3a7b2c...
rtmr0: 8f4e1d...
rtmr1: c2a9b7...
rtmr2: 5e8f3a...
rtmr3: 000000...
```

#### Multi-NUMA topology

```bash
cvm-measure tdx \
  --firmware OVMF.fd \
  --uki BOOTX64.EFI \
  --baseline baseline.json \
  --ram 704 --numa-nodes 4 --max-per-node 176
```

`--numa-nodes` defaults to 1 and `--max-per-node` defaults to the `--ram` value, so single-NUMA users just pass `--ram`.

#### MRTD only

```bash
cvm-measure tdx --mode mrtd \
  --firmware OVMF.fd \
  --ram 234
```

#### Extract baseline from CCEL

```bash
cvm-measure tdx extract-baseline \
  --ccel ccel.bin \
  --machine-type a3-highgpu-1g \
  -o baseline.json
```

#### Replay CCEL event log

```bash
cvm-measure tdx replay --ccel ccel.bin
```

Replays the CC Event Log to compute RTMR values. Useful for verifying a published CCEL against the hardware-signed attestation report.

### Azure SEV-SNP

#### Compute all registers

```bash
cvm-measure azure-snp --disk podvm.raw
```

Output:

```
pcr4:     03e74a...
pcr5:     f27e34...
pcr8:     000000...
pcr9:     e95cd6...
pcr11:    12a8c8...
roothash: 6f3a1b...
```

The disk supplies both the UKI and the partition table, so one argument covers
every register except PCR 8. `--uki BOOTX64.EFI` skips extraction if you
already have the file, and `roothash` is echoed only when the image pins a
dm-verity hash on its command line.

Add the deployment's initdata to fill in PCR 8:

```bash
cvm-measure azure-snp --disk podvm.raw --initdata initdata.toml
```

`--pcr8 <hex>` sets it directly. Without either, PCR 8 is reported as zeros,
which is what the register holds when no initdata was supplied.

#### Replay vTPM event log

```bash
cvm-measure azure-snp replay --eventlog binary_bios_measurements.bin
```

Replays the firmware log to compute PCRs 0-7, 9 and 11. Useful for checking a
published log against a hardware-signed vTPM quote. PCR 8 never appears:
`process-user-data` extends it from userspace after the log is closed.

### Output formats

Applies to both platforms. Compute commands print aligned text by default; add
`--output-format json` for machine-readable output, useful in CI pipelines and
scripting:

```bash
cvm-measure tdx --firmware OVMF.fd --uki BOOTX64.EFI --baseline baseline.json \
  --ram 234 --output-format json

cvm-measure azure-snp --disk podvm.raw --output-format json
```

The keys are the register names in lower case, so the TDX command above prints:

```json
{
  "mrtd": "3a7b2c...",
  "rtmr0": "8f4e1d...",
  "rtmr1": "c2a9b7...",
  "rtmr2": "5e8f3a...",
  "rtmr3": "000000..."
}
```

The `replay` subcommands are text only.

## Python API

### Intel TDX

```python
from pathlib import Path
from cvm_measure.tdx import compute_all_registers, compute_mrtd, load_baseline

firmware = Path("OVMF.fd").read_bytes()
uki = Path("BOOTX64.EFI").read_bytes()
baseline = load_baseline("baseline.json")

# Compute all registers
regs = compute_all_registers(firmware, uki, baseline, ram_gib=234)
print(regs.mrtd, regs.rtmr0, regs.rtmr1, regs.rtmr2, regs.rtmr3)

# MRTD only
mrtd = compute_mrtd(firmware, ram_gib=234)

# Multi-NUMA
regs = compute_all_registers(
    firmware, uki, baseline,
    ram_gib=704, numa_nodes=4, max_per_node_gib=176,
)
```

### Azure SEV-SNP

```python
from pathlib import Path
from cvm_measure.azure_snp import compute_all_pcrs
from cvm_measure.disk import gpt_event_data

uki = Path("BOOTX64.EFI").read_bytes()
gpt = gpt_event_data("podvm.raw")

# PCR 8 is zeros without initdata, matching a deployment that supplied none
pcrs = compute_all_pcrs(uki, gpt)
print(pcrs.pcr4, pcrs.pcr5, pcrs.pcr9, pcrs.pcr11)

# Pass the deployment's initdata to fill in PCR 8
pcrs = compute_all_pcrs(uki, gpt, initdata=Path("initdata.toml"))
print(pcrs.pcr8)
```

`initdata` also takes the TOML bytes directly, which is what you have when the
initdata came from a pod annotation rather than a file. `pcr8_hex=` is there for
a caller who already knows the register value but not the initdata behind it;
passing both is refused.

## What It Computes

### Intel TDX

| Register | Inputs | Description |
|----------|--------|-------------|
| MRTD | Firmware + RAM topology | Measures the initial TD memory image (firmware code/data + TDHOB) |
| RTMR[0] | Firmware + baseline | Firmware config: TdxTable, CFV, SecureBoot, PK/KEK/db/dbx, ACPI, boot vars |
| RTMR[1] | UKI + baseline | Boot chain: EFI actions, GPT, UKI Authenticode hash, kernel Authenticode hash |
| RTMR[2] | UKI | OS identity: systemd-stub measured UKI sections (.linux, .osrel, .cmdline, .initrd, .uname, .sbat) |
| RTMR[3] | initdata (optional) | CoCo initdata digest (runtime policy). Defaults to zeros if not provided |

### Azure SEV-SNP

Each numbered item below is one **extend** of that register:

```
PCR := SHA-256(PCR ‖ event_digest)
```

starting from 32 zero bytes, applied once per item in the order shown. `‖` is
byte concatenation. The order is part of the definition, not presentation, so
the numbering is significant.

| Register | Inputs | Extends, in order |
|----------|--------|-------------------|
| PCR 4 | UKI | 1. `EV_EFI_ACTION` — SHA-256("Calling EFI Application from Boot Option")<br>2. `EV_SEPARATOR` — SHA-256(0x00000000)<br>3. `EV_EFI_BOOT_SERVICES_APPLICATION` — SHA-256 Authenticode digest of the whole UKI<br>4. `EV_EFI_BOOT_SERVICES_APPLICATION` — SHA-256 Authenticode digest of its `.linux` section, loaded as its own PE |
| PCR 5 | Disk GPT | 1. `EV_SEPARATOR` — SHA-256(0x00000000)<br>2. `EV_EFI_GPT_EVENT` — SHA-256(EFI_GPT_DATA)<br>3. `EV_EFI_ACTION` — SHA-256("Exit Boot Services Invocation")<br>4. `EV_EFI_ACTION` — SHA-256("Exit Boot Services Returned with Success") |
| PCR 8 | initdata (optional) | 1. The CoCo initdata digest itself, **truncated to 32 bytes** and not re-hashed<br><br>Extended from userspace, so it appears in no event log. Zeros if no initdata was supplied. |
| PCR 9 | UKI | 1. SHA-256(UTF-16LE(cmdline) ‖ 0x0000) — the command line the EFI stub passes as LoadOptions, UTF-16 encoded with a UTF-16 NUL terminator<br>2. SHA-256(`.ucode` ‖ `.initrd`) — the single blob the stub hands the kernel, microcode first (`.ucode` contributes nothing if the UKI has no such section) |
| PCR 11 | UKI | Two extends per measured section, walking systemd's canonical section order:<br>1. `EV_IPL` — SHA-256(section name ‖ 0x00), the name in ASCII with a single NUL<br>2. `EV_IPL` — SHA-256(section content), read at VirtualSize<br><br>Only sections actually present are measured; the pod VM image carries 7 of them, giving 14 extends. |

Two encoding details are easy to get wrong. The `EV_EFI_ACTION` strings in
PCR 4 and 5 are hashed as ASCII with **no** NUL terminator, unlike the section
names in PCR 11, which carry exactly one. And the kernel's EFI stub logs both
PCR 9 events as `EV_EVENT_TAG` records, but the digests cover the raw payloads
above, not the `TCG_EfiTaggedEvent` structures wrapping them.

Notes that change how you should use these:

- **PCR 4 is the only register that covers the systemd-stub binary itself.**
  PCR 11 covers the payload sections the stub recognises, but not its `.text`,
  `.rodata`, `.data` or PE headers. Swap the stub and leave the payloads
  identical, and PCR 4 is the only value that moves.
- **PCR 5 is first-boot-only.** The release image ships
  `/usr/lib/repart.d/30-scratch.conf`, so `systemd-repart` appends a
  `trusted_store` partition on first boot. The stock unit passes no `--seed`
  and `/etc/machine-id` reads `uninitialized` on a read-only squashfs, so that
  partition's UUID is random on every boot: PCR 5 is unpredictable afterwards,
  not merely different. Pod VMs are created per pod and destroyed, so first
  boot is the normal case, but whether to pin PCR 5 is a policy decision.
- **PCR 8 truncates, it does not re-hash.** The
  [initdata spec](https://github.com/confidential-containers/trustee/blob/main/kbs/docs/initdata.md)
  says a digest wider than the field binding it loses the excess bytes off the
  end, and a SHA-256 PCR is a 32-byte field. The unit in the image implements
  that as `tpm2_pcrextend 8:sha256=$(head -c64 /run/peerpod/initdata.digest)`,
  so a `sha384` initdata gives `SHA-256(0 ‖ SHA-384(toml)[:32])`, which is
  *not* `SHA-256(0 ‖ SHA-256(toml))`.
- **PCR 9 is where a dm-verity root hash reaches a verifier**, since
  `roothash=` lives on the kernel command line.

## Baselines (Intel TDX only)

Everything in this section is TDX-specific. The Azure SEV-SNP path needs no
baseline, because every event it computes is either a TCG-defined constant or a
function of the image.

A baseline file contains SHA-384 digests for events that **cannot be computed offline**. These are generated by the VMM/hypervisor at boot time and depend on the firmware version, machine type, and VMM version:

- **TdxTable**: TDX handoff table injected by the VMM
- **PK/KEK/db/dbx**: Secure Boot certificate databases injected by the hypervisor
- **ACPI tables**: Machine-specific ACPI data
- **Boot variables**: BootOrder, Boot0000-Boot0003
- **GPT**: Disk partition table hash

Baselines are **not shipped with this tool**. Each CVM operator should publish baselines for their images. For an example, see Cohere's [cohere-cc-baselines](https://github.com/cohere-ai/cohere-cc-baselines) repository, organized by provider, platform, and machine type.

### How baselines are created

1. Boot a CVM with the target image
2. Extract the CCEL: `cat /sys/firmware/acpi/tables/data/CCEL > ccel.bin`
3. Run: `cvm-measure tdx extract-baseline --ccel ccel.bin --machine-type <type> -o baseline.json`
4. Publish the baseline JSON alongside the UKI for the image release

### How users verify baselines

Users can verify a published baseline without booting a VM:

1. Download the published CCEL binary
2. Replay it: `cvm-measure tdx replay --ccel published_ccel.bin`
3. Compare the RTMR values against the hardware-signed attestation report
4. If they match, the CCEL is authentic (hardware-signed RTMRs cannot be forged)
5. Extract the baseline from the verified CCEL and use it for independent computation

See `examples/baseline-example.json` for an annotated example.

### Where do the inputs come from?

- **Firmware (OVMF.fd)**: Published by Google in the `gce_tcb_integrity` bucket. The filename is the SHA-384 hash, making it self-authenticating. URL: `https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/{sha384}.fd`
- **UKI (BOOTX64.EFI)**: Built by the CVM operator's image pipeline. Must be published to a public artifact store.
- **Baseline (baseline.json)**: Extracted from a reference VM's CCEL. Published alongside the UKI for each image release.
- **RAM size**: Known from the cloud provider's machine type specification.

### The baseline trust model

The baseline follows a Trust-On-First-Use (TOFU) model. The 14 VMM-generated events in the baseline cannot be independently computed -- they must be captured from a running VM. Users can verify a published baseline by replaying the CCEL and checking that the resulting RTMRs match the hardware-signed attestation report, but they must trust that the CCEL was captured from a correctly-configured VM.

## Scope and Limitations

### What this tool covers

Intel TDX:

- MRTD: firmware identity (code + data pages measured during TD build)
- RTMR[0]: firmware configuration (CFV, SecureBoot state, certificate databases, ACPI tables, boot variables)
- RTMR[1]: boot chain (EFI boot actions, GPT, UKI + kernel Authenticode hashes)
- RTMR[2]: OS identity (UKI PE sections measured by systemd-stub)
- RTMR[3]: runtime policy (CoCo initdata digest)

Azure SEV-SNP:

- PCR 4: boot chain (EFI boot action, UKI + kernel Authenticode hashes)
- PCR 5: partition table (GPT, framed by the Exit Boot Services actions)
- PCR 8: runtime policy (CoCo initdata digest)
- PCR 9: command line and initrd, as the Linux EFI stub measures them
- PCR 11: OS identity (UKI PE sections measured by systemd-stub)

### Azure SEV-SNP registers left alone

None of these is a property of the image, and pinning any of them would break
attestation the moment Microsoft updates firmware:

- **PCR 0** measures Azure's own firmware blob and its S-CRTM version.
- **PCR 1, 2, 3** hold a separator and nothing else on this platform, because
  Azure's firmware measures no boot variables on the removable-media path.
  That absence is Azure's boot configuration, not ours to predict.
- **PCR 6** measures the per-VM `vmUniqueId`, assigned at deployment.
- **PCR 7** measures Azure's Secure Boot variables. Secure Boot is off on this
  image, so it records `SecureBoot = 0` plus Azure's certificate databases,
  which move with Azure's firmware.
- **PCR 10** is IMA, which keeps extending with `ima-ng` template hashes as
  files are measured, so it has no final value to predict.

Pin the firmware in policy instead, using the SNP report's `ID_KEY_DIGEST`.
That identifies Microsoft as the signer and survives firmware updates, whereas
the report's `MEASUREMENT` field does not. This is also why the Azure path
needs no baseline file at all.

### Inputs this tool refuses

A wrong register value is worse than no register value, so anything outside
what is modelled raises instead of producing a plausible answer.

Both platforms:

- A UKI with no `.linux` section, with a `.profile` section (what gets measured
  then depends on the profile selected at boot), or repeating a section
  systemd measures.
- An event log that is truncated, declares a length or count its buffer cannot
  hold, or carries unexplained bytes after its last event.
- An initdata file that declares no top-level `algorithm`, or one CoCo does not
  implement.

Intel TDX:

- A baseline whose recorded firmware hash is not the firmware you passed.
- An RTMR[0] baseline whose event set or order is not the sequence the
  supported firmware measures. The ACPI and boot-variable events are replayed
  positionally because three consecutive ACPI events are indistinguishable by
  label.
- Firmware whose TDX metadata does not describe exactly one CFV section, or
  places it outside the image.
- A NUMA topology whose per-node cap cannot hold the requested RAM.
- An initdata file declaring anything but `sha384`, since RTMR[3] is a 48-byte
  interface that cannot carry a shorter digest.
- A CCEL digest that reaches into the unused tail of the ACPI table. The fill is
  not a source of event bytes, so a truncated log cannot be completed with fill
  and replayed.

Azure SEV-SNP:

- A UKI with no `.cmdline` or `.initrd` section, or a command line with an
  embedded NUL, which would terminate the string early for the EFI stub but not
  for this tool.

### What this tool does NOT cover

These apply to both platforms. They are real attack surfaces that require separate tools and controls:

- **Unmeasured runtime inputs**: Environment variables, command-line arguments injected after boot, and other runtime configuration are not captured in any register. A compromised host can inject malicious values through these channels. (Ref: Trail of Bits TOB-WAPI-7, WhatsApp Private Processing audit)

- **ACPI table content**: TDX RTMR[0] measures that ACPI tables were loaded, but does not validate their content. Malicious ACPI tables could alter guest behavior. On Azure the equivalent events land in PCR 0, which this tool does not compute at all. (Ref: TOB-WAPI-8)

- **Disk encryption**: Attestation does not verify disk encryption keys or ciphers. The LUKS2 null cipher attack (CVE-2025-59054) demonstrated that a compromised host can replace the encryption cipher with a null cipher, making disk encryption ineffective. This requires separate validation.

- **Attestation replay**: This tool computes expected values but does not verify quotes, check quote freshness, or validate TCB versions. A separate verification tool is needed to compare computed values against a live attestation report. On Azure that verifier is also where the SNP report's `ID_KEY_DIGEST` gets pinned.

- **GPU attestation**: NVIDIA H100 CC attestation is separate from CPU attestation and requires its own verification flow.

- **Physical attacks**: Side-channel attacks, voltage glitching, and cold-boot attacks against the CPU are outside the software trust boundary. (Ref: Trail of Bits "After Wiretap and Battering RAM")

- **TLS channel binding**: The connection between a user and the CVM is not cryptographically bound to the attestation report by this tool.

## Development

```bash
pip install -e .
python -m pytest tests/ -v
```

Tests that require CCEL binary fixtures are automatically skipped if the fixture files are not present in `tests/fixtures/ccel/`.

The Azure SEV-SNP tests are never skipped. A real 36 KB vTPM event log and the
PCR values from the same VM's signed quote are committed under
`tests/fixtures/eventlog/` and `tests/fixtures/golden/`, so the register
recipes are checked against hardware on every run.

## License

Apache 2.0
