# Firmware Test Fixtures

Place OVMF firmware binaries here to enable MRTD integration tests.

## How to obtain

Google publishes OVMF firmware binaries for GCE TDX VMs in a public GCS bucket.
Files are named by their SHA-384 hash. Look up the hash in the corresponding
baseline file (`fixtures/baselines/a3-highgpu-1g.json`, field `firmware_sha384`),
then download:

```bash
HASH=f53fdf89544e1e6d785eee42d0a4bb38e26b36e951be537ac22114d210f2d5239eba243dd71991afe8345e7020974a46

gsutil cp \
  gs://gce_tcb_integrity/ovmf_x64_csm/${HASH}.fd \
  tests/fixtures/firmware/ovmf-a3-highgpu-1g.fd
```

To verify the download:

```bash
sha384sum tests/fixtures/firmware/ovmf-a3-highgpu-1g.fd
```

The output should match the hash used above.

## Available firmware images

Browse all available images:

```bash
gsutil ls gs://gce_tcb_integrity/ovmf_x64_csm/
```

Without firmware binaries, tests that depend on them are automatically skipped.
