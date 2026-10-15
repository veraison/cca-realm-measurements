# uefi-eventlog-rs

This is a parser for the UEFI Boot Log.

This file is on Linux systems usually available on: `/sys/kernel/security/tpm0/binary_bios_measurements`.

This repository includes a debugging tool, you can run the following commands to run the tool and get your own log:

```
cargo build
sudo target/debug/uefi-eventlog-dump /sys/kernel/security/tpm0/binary_bios_measurements
```

## Specifications
This implements parsing of structures from the following specifications:
- `Unified Extensible Firmware Interface (UEFI) Specification, Version 2.8 Errata B`
- `TCG PC Client Specific Implementation Specification for Conventional BIOS, Version 1.21 Errata, Revision 1.00 For TPM Family 1.2; Level 2`
- `TCG EFI Platform Specification For TPM Family 1.1 or 1.2, Version 1.22, Revision 15`
- `TCG EFI Protocol Specification, Family 2.0, Level 00 Revision 00.13`
