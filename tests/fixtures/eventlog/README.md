# vTPM Event Log Fixtures

`azure-snp-ncc40ads-h100-v5.bin` is a real TCG event log, captured from an
Azure `Standard_NCC40ads_H100_v5` confidential VM running the CoCo pod VM
image built from cloud-api-adaptor commit `9873875`:

```bash
cat /sys/kernel/security/tpm0/binary_bios_measurements > azure-snp-ncc40ads-h100-v5.bin
```

Unlike the CCEL fixture, this one is committed, so the tests that use it
always run. It is 36 KB, which is small enough to keep in the repo, and a
test that only runs when someone happens to have the artifact is a test that
rots.

The golden values in `fixtures/golden/azure-snp-ncc40ads-h100-v5.json` come
from a signed vTPM quote taken on the same boot, so replaying this log
reproduces them exactly. The one exception is PCR 8, which is extended from
userspace after the log is closed and therefore has no record here.
