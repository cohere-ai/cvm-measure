# UKI Test Fixtures

Place UKI (Unified Kernel Image) binaries here to enable PE parsing and
end-to-end register computation tests.

## How to obtain

The UKI (BOOTX64.EFI) is extracted from a PodVM disk image built with
[mkosi](https://github.com/systemd/mkosi). Any TDX-capable disk image
that contains a systemd-stub UKI on its EFI System Partition will work.

### 1. Obtain a disk image

Download or build a `disk.tar.gz` containing a raw disk image with an
EFI System Partition. For example, build one with mkosi or obtain one
from your CI pipeline.

### 2. Extract the UKI

The UKI lives on the EFI System Partition inside the disk image. Use the
`extract-uki` CLI command (requires `mtools`):

```bash
# Install mtools if needed
brew install mtools   # macOS
apt install mtools    # Linux

# Extract BOOTX64.EFI from the disk image
cvm-measure extract-uki \
  --disk /tmp/disk.tar.gz \
  --output tests/fixtures/uki/bootx64-a3-highgpu-1g.efi
```

The command will print the file size and SHA-384 hash to stderr.

### 3. Clean up

```bash
rm /tmp/disk.tar.gz
```

Without UKI binaries, tests that depend on them are automatically skipped.
