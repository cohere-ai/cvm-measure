# UKI Test Fixtures

Place UKI (Unified Kernel Image) binaries here to enable PE parsing and
end-to-end register computation tests.

## How to obtain

The UKI (BOOTX64.EFI) is extracted from a PodVM disk image built by the
fortress CI pipeline. The disk images are stored in GCS.

### 1. Download the disk image

```bash
gsutil cp \
  gs://cohere-confidential-computing-podvm-build/ubuntu-mkosi-tdx-debug-2026-03-27/disk.tar.gz \
  /tmp/disk.tar.gz
```

### 2. Extract the UKI

Use the extraction script from the fortress repo (requires `mtools`):

```bash
# Install mtools if needed
brew install mtools   # macOS
apt install mtools    # Linux

# Extract BOOTX64.EFI from the disk image
python3 ../fortress/deployment/terraform/podvm-build/scripts/extract-uki.py \
  /tmp/disk.tar.gz \
  tests/fixtures/uki/bootx64-a3-highgpu-1g.efi
```

The script will print the file size and SHA-384 hash to stderr.

### 3. Clean up

```bash
rm /tmp/disk.tar.gz
```

Without UKI binaries, tests that depend on them are automatically skipped.
