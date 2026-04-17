# CCEL Test Fixtures

Place CCEL binary files here to enable the full test suite.

To get a CCEL from a running TDX CVM:

```bash
cat /sys/firmware/acpi/tables/data/CCEL > a3-highgpu-1g.bin
```

The golden values in `fixtures/golden/a3-highgpu-1g.json` were captured from a
specific a3-highgpu-1g attestation token. The CCEL binary must come from the
same VM boot to match.

Without the CCEL binary, tests that depend on it are automatically skipped.
