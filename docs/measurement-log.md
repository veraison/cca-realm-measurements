The Realm Token Log
===================

In Arm CCA, the Realm Token contains five hashes describing the state of
the Realm VM. A verifier attempts to reproduce these hashes to confirm
that the realm is executing what is expected. The Realm Initial
Measurement (RIM) is a hash of the initial, pre-boot state of the VM. Four
Realm Extensible Measurements (REM[0-3]) are hashes of additional components
measured by firmware, bootloaders, operating system and applications
running in the Realm.


Why is a log needed?
--------------------

To reproduce RIM and REMs, a verifier benefits from a log that describes
everything that went into these measurements. It is generally accepted that
REMs need an accompanying log because firmware, bootloaders, OS and
applications are free to append measurements for any event, in any order. But
having a log for the RIM may be useful as well, to avoid a strict specification
of the VMs:

* Future versions of the VMM don't have to maintain a specific order of
  operations that contribute to the RIM. They don't need any extra efforts to
  maintain backward compatibility of the RIM.

* A log can provide information about the VMM and the hypervisor, to help
  the verifier reconstruct the RIM. The Reference Value (RV) provider doesn't
  need to calculate and upload a RIM for each combination of VM configuration
  and image. It only has to provide one hash for each image, and the verifier
  can reconstruct the RIM based on the log. This enables more configurability
  in VMs.

* A log can also contain plain data written into Realm memory at boot
  (RIM) or passed to firmware (REM), so that the verifier itself can
  verify their content. We're talking here about the firmware tables
  (device tree or ACPI). A malicious host could falsify information in
  those tables to exploit vulnerabilities in the FW or OS parser, for
  example it could add pointers to unmeasured initrd, weaken the kernel
  parameters, or corrupt the nodes to throw off a parser.

  Several solutions could ensure that the host didn't provide invalid
  content in the firmware tables:

  1. The RV provider or verifier independently generates the firmware
     tables, to confirm that their hash matches. Those generated firmware
     tables could also be passed as-is for the VMM to load. This is
     certainly the easiest to implement, but it may not scale well, if
     more options are added to VMs (more memory sizes, vCPU numbers, MMIO
     devices...)

  2. Software in the Realm verifies the content of the firmware tables.
     The advantage is that the firmware tables don't need to be measured.
     This is difficult to implement because each software that could
     parse the raw firmware tables must now be hardened: each UEFI
     implementation, each OS, possibly bootloaders as well. Going forward
     any change to their firmware tables parser will require extra
     scrutiny to protect against invalid values, which wasn't part of the
     thread model until now. The maintenance burden seems too high.

  3. A single dedicated piece of software, included in the verifier,
     could verify the content of the firmware tables that are provided in
     the log.

  Combining options 1 and 3 might be a good solution: the VMM declares in the
  log a few parameters the influence the firmware table, such as number of
  vCPUs, amount of memory, IRQ routes or memory-mapped devices, allowing the
  verifier to reconstruct exactly the firmware tables and compute their hash.
  It's worth prototyping, but requires defining a canonical way to generate
  firmware tables.


How does the log get to the verifier?
-------------------------------------

Here is an example flow describing remote attestation and some components
involved in measurement and logging:

           ┌─────────┬───────────────────────────┐
           │    NS   │         REALM             │
     ┌─────┼─────────┼───────────────────────────┤   ┌────────┐
     │     │         │                           │   │        │
     │     │         │                           │   │        │
     │ EL0 │   VMM   │ cca-workload-attestation ─┼───┼─►      │
     │     │    │    │       ▲                   │   │ (4)    │
     │     │    │    │       │(3)                │   │        │
     ├─────┼────┼────┼───────┼───────────────────┤   │        │
     │     │    │    │       │                   │   │        │
     │     │    │    │    kernel ◄── BL          │   │        │
     │     │    │    │       ▲       │           │   │        │
     │ EL1 │    │    │       │       │ (2)       │   │        │
     │     │    │    │       │      EFI ─────────┼───┼─►      │
     │     │    │    │       │       ▲           │   │        │
     │     │    │    │       │       │           │   └────────┘
     │     │    │    ├───────┼───────┼───────────┤    VERIFIER
     │     │    │    │       │ (1)   │           │
     │     │    │    │       └─┬─────┘           │
     │     │    ▼    │         │                 │
     │ EL2 │   KVM───┼──────► RMM                │
     │     │         │                           │
     └─────┴─────────┴───────────────────────────┘
                       ATTESTER


(1) The VMM initializes the Realm by performing a set of operations measured
    by RMM into the RIM. The Realm boots by entering either firmware (EFI)
    or the kernel directly.

(2) EFI and the bootloader may need to perform early attestation, for
    example to unlock storage containing kernel and secrets.

(3) Applications obtain the Realm Token along with a log in order to
(4) perform attestation.


### (1) VMM

The VMM creates an event log, loads it into Realm memory unmeasured. It writes
the address into the FW tables. This change may affect verification:

* If the FW tables are measured (in RIM or REM), and the RV provider
  generates the FW tables, we need to specify exactly where to create this
  log, as part of the platform memory map. Or log the pointer so that the
  verifier can reconstruct the tables.

* Since the log is unmeasured, parsers must be hardened against invalid
  format and value (don't let a malicious host exploit parser
  vulnerabilities by setting out of bounds sizes, for example).

The FW tables:

* ACPI table [CCEL] is defined specifically for the confidential computing
  measurement log. It has a pointer to the event log.

* We introduce a new device-tree node to pass the measurement log address:

      {
          compatible = "confidential-computing-event-log";
          log-base = IPA;
          log-size = SIZE;
      }

* FwCfg could pass the event log. But not all VMMs implement it. QEMU as well
  as Google and AWS implement it, but kvmtool doesn't and cloudhv
  [will not](https://github.com/cloud-hypervisor/cloud-hypervisor/issues/4814#issuecomment-1290113552).

* RMM RSI could be used to get the event log location. The advantage is that
  the measured FW tables don't have a pointer in them. But CCEL exists and is
  standardized.

(For TPMs, the kernel finds the TPM measurement log by following pointers
 given in [ACPI TPM2] and [devicetree node tpm].)

### (2) Firmware

If it doesn't find a log, FW creates a new one. Otherwise it takes ownership of
the one created by the VMM. It can also allocate a new one and fill it with the
VMM entries. It modifies the FW tables to point to the new log.

Bootloaders call EFI_TCG2_PROTOCOL.[HashLogExtendEvent] to extend a REM and
the log. The kernel EFI stub calls GetEventLog and ExitBootServices,
then moves the log to the EFI config tables (LINUX_EFI_TPM_EVENT_LOG_GUID)


### (3) Linux

The ACPI [CCEL] blob is
[exposed](https://lore.kernel.org/lkml/20230322191313.22804-1-sathyanarayanan.kuppuswamy@linux.intel.com/)
in /sys/firmware/acpi/tables/data/ccel.  There is no equivalent for DT at
the moment, it might make sense to add it for example in 
/sys/firmware/devicetree/data/cc-event-log.

The log is reserved memory and Linux makes sure not to override it.


#### Existing interfaces and logs:

* [TPM event log](https://docs.kernel.org/security/tpm/tpm_event_log.html)
  in /sys/kernel/security/$tpm/binary_bios_measurements. 
  Format is [TCG2] (TCG PC Client Firmware Profile).


* [IMA event log](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/dm-ima.html)
  in /sys/kernel/security/integrity/ima/{ascii,binary}_runtime_measurements.
  Format is custom: [IMA event log]

* TCG introduced Canonical Event Log ([CEL]) format to represent TCG2, IMA,
  and others. One CEL file can contain events in multiple formats. Google
  [may use it](https://lore.kernel.org/all/6DEAEC08-420C-46A9-8877-EBF60331A931@google.com/).

* confidential-containers introduced a
  [custom text format](https://github.com/confidential-containers/guest-components/issues/495)
  that can be exported with CEL.

* There are [discussions](https://lore.kernel.org/linux-coco/20240907-tsm-rtmr-v1-0-12fc4d43d4e7@intel.com/)
  about an API for extending the measurements in Linux, which would also
  have log files, but in the initial proposal the log format is specific
  to Linux and doesn't contain pre-Linux events. Similarly to the CC format, it
  could be exported in CEL. In that thread there is a suggestions to provide
  multiple log formats, but I don't know if they would complement or duplicate
  each others.


### (4) Verification

Userspace obtains a realm token via configfs-tsm report, obtains the event
log from the FW sysfs, and aggregates FW event log and Linux runtime
measurement log into a single file. CEL-CBOR might be a good idea for the
encoding. Then we send it as a Conceptual Message Wrapper ([CMW]), with media
type "application/vnd.veraison.cmw+cbor":

    cca-token-with-log = {
      1 => cca-token-collection-wrapper
      2 => cca-measurement-log
    }
    
    cca-token-collection-wrapper = {
      type: "application/eat+cwt; profile=\"tag:arm.com,2023:cca#1.0.0\""
      value: cca-token-collection
    }
    
    cca-measurement-log = {
      type: "application/vnd.veraison.cel-cbor-log" // or something like that
      value: cel-cbor-events-list
    }

`cca-token-collection` is described in [RATS-CCA-TOKEN], and
`cel-cbor-event-list` is the list of events defined here.

Alternatively, we can extend cca-token-collection to include the CEL-CBOR
log:

    cca-token-collection = {
        44234 => cca-platform-token          ; 44234 = 0xACCA
        44241 => cca-realm-delegated-token
        44242 => cca-measurement-log
    }

However that means all attesters including EDK2 would need to know CBOR in
order to modify the attestation token. If we use a CMW, EDK2 is free to use a
different protocol for attestation.


The verifier receives the log, and attempts to reconstitute RIM and REM
based on image hashes contained in the log. For example the log says "VMM
loaded EDK2 firmware with hash "ABC" at address 0x0. The verifier looks up
hash ABC in its database, and finds a list of hashes corresponding to each
ganule of this image. It replays RMI_DATA_CREATE extension of RIM
(RMM-1.0-rel0 B4.3.1.4) using these hashes.

One crucial step will be caching the measurements, in order to reduce
the number of calculations by the verifier. Rather than calculating all
measurements for each requests, the verifier looks up the measurements
cache to shortcut the verification. Cached entries are invalidated when
reference values are revoked, and can be evicted with a LRU policy to
avoid taking too much space. For cloud workloads it's likely that the
attester will only run with a few dozens different configurations (memory
size, images, features...) so the cache can be quite small (100s entries)


Provisioning
------------

Rather than provisioning the verifier with RIM and REM, we provision with
image hashes. We don't upload the whole image but a list of hashes:

    { image-ref: [H0, H1, ...] }

image-ref is a unique identifier for the image. Something that the VMM and
UEFI can easily get to when generating the event log, ideally a SHA hash,
but could be an UUID. H1-Hn are hashes of each 4kB granule of the image.

Maybe the [CoMID] representation could have 'digests' be the identifier for
the image, and 'integrity-registers' the granule hashes:

    comid.mval = {
      comid.digests = [
        { alg: sha256, val: ID256  },
        { alg: sha512, val: ID512  },
      ],
      comid.integrity-registers = {
        0: [
            { alg: sha256, val: H256_0 },
            { alg: sha512, val: H512_0 }],
        1: [
            { alg: sha256, val: H256_1 },
            { alg: sha512, val: H512_1 }],
        ...
       }
    }

See also [CCA endorsements](https://datatracker.ietf.org/doc/html/draft-ydb-rats-cca-endorsements-00).


What's in the log??
===================

The [TCG2] format is both standard and compact, so I think we should
recommend using this for VMM->EFI->OS interface. As explained above, [CEL]
is a wrapper for TCG2 and others, and converting TCG2 to CEL is easy. But
even CEL-CBOR produces larger log structures, and since EDK2 already knows
TCG2 encoding, it makes sense to reuse it.

REM log
-------

The REM log content is already defined, ad-hoc by EFI and other
components. TCG PC Client Platform Firmware does specify when to use some
events. I don't know if they are used exactly as specified.

* In EDKII searching for EventType and TCG_PCR_EVENT can help. One
  example:

      InstallQemuFwCfgTables()
        TpmMeasureAndLogData(1, EV_PLATFORM_CONFIG_FLAGS, EV_POSTCODE_INFO_ACPI_DATA,...)

  Measures a blob into PCR[1], and, when using the PCR2 format, logs this
  event:

      TCG_PCR_EVENT2 {
        u32 pcrIndex;       // 1
        u32 eventType;      // 0xA (EV_PLATFORM_CONFIG_FLAGS)
        TPML_DIGEST_VALUES {
         u32    count;      // 1
         TPMT_HA {
          u16   hashAlg;    // 0xb (SHA512)
          u8    digest[64]; // blob hash
         }
        }
        u32 eventSize;      // 10
        u8  event[];        // "ACPI DATA"
      }

* Grub verifies files in PCR[9] and strings (kernel cmdline) in PCR[8]. It
  calls EFI with eventType EV_IPL, and data filename or string.

* Linux EFI stub measures initrd and cmdline into PCR[9]. It calls EFI
  with eventType EV_EVENT_TAG, data is

      TCG_PCClientTaggedEvent {
        u32 tag;    // 0x8F3B22EC / 0x8F3B22ED
        u32 size;
        u8  data[]; // "Linux initrd", "LOADED_IMAGE::LoadOptions"
      }

A proper index of all possible events would be nice, because is seems
event producers pick arbitrary values to store in the data. But in most
case the verifier can just look up the hash in its database without caring
about the event data.

PCR numbers are mapped to REM indexes. For example Intel already defines a
mapping ([CC TDX PCR]), and we can just reuse it:

| TPM PCR Index | TDX-measurement register | Arm CCA
|---------------|--------------------------|---------
| 0             |   MRTD                   |  RIM
| 1, 7          |   RTMR[0]                |  REM0
| 2~6           |   RTMR[1]                |  REM1
| 8~15          |   RTMR[2]                |  REM2
| 16-...        |                          |  REM3


RIM log
-------

For the RIM, we could define the following events. All structures are
packed, and I think little-endian. The first entry is required by TCG2:

* Log starts with a Specification ID Event. Describes the protocol version, and
  the supported hash algorithms.

  Standard: see 10.2.1 TCG_PCClientPCREvent Structure

      TCG_PCClientPCREvent {
        u32     pcrIndex;           // 0
        u32     eventType;          // 3 (EV_NO_ACTION)

        // For compatibility, this digest field uses a fixed size (SHA1 log format)
        u8      digest[20];         // 0
        u32     eventDataSize;      // 37 (sizeof spec id event)

        TCG_EfiSpecIdEvent {
         u8     signature[16];      // "Spec ID Event03"  
         u32    platformClass;      // 0 (0 for client, 1 for server)
         u8     familyVersionMinor; // 0
         u8     familyVersionMajor; // 2 (TPM lib version 2.0)
         u8     specRevision;       // 106 (or a newer version, since we have to break some rules)
         u8     uintnSize;          // 2 (size of UINTN, but there are no UINTN in the spec)
         u32    numberOfAlgorithms; // 2
         TCG_EfiSpecIdEventAlgorithmSize {
          u16   algorithmID;
          u16   digestSize;
         } digestSizes[2];          // { 0xb (SHA256), 32 }, { 0xd (SHA512), 64 }
         u8     vendorInfoSize;     // 0
         u8   vendorInfo[0];
        };
      };


  The hash algorithm declaration is awkward. We describe the supported
  algorithm for the whole rest of the log, including what EFI and
  OS/applications will append to the log. An EV_NO_ACTION event has digest
  entries for each recorded hashing algorithm (and the digests are all
  zeroes). This means:

  1. EFI must at least know the size of the digest of each algorithms we
     declare here.

  2. In order to add additional algorithms, EFI would need to rewrite (the
     first entry and) all the EV_NO_ACTION we publish, in order to resize
     them.

  Note that the algorithms used by RMM and those used to describe blob
  hashes are distinct. To ease the work for the reference value provider,
  we could strongly recommend a single algorithm for the blob hashes
  (SHA512). That way the RV provider doesn't need to run multiple hash
  algorithms on an image (that said, we do need to pre-compute both the
  overall image hash, and the granule hashes). Since RIM and REM are
  calculated on the fly, then we don't have to mandate a specific
  algorithm for RMM. Most important is that the VMM uses a single hash
  algorithm, since that's calculated on every run.

  We can however declare multiple supported algo here, which would allow
  lower-level software to pick the one they prefer. EDK2 seems to do a
  comparison between a bit and a bitmask (PcdTpm2HashMask) to pick the
  hash algorithm?  Maybe something sets a single algorithm somewhere.
  In any case, the CC driver can do things differently than the TPM one.

* Option: VM and/or hypervisor model version. A description of the platform
  that could help a verifier figure out the firmware tables to use.

  This event SHOULD be added directly after the Specification ID Event, if any,
  or at the beginning of the log.

  Non-standard: "All EV_NO_ACTION events SHALL set TCG_PCR_EVENT2.event to
  one of the events described in the following sections." But we define
  our own event.

      TCG_PCR_EVENT2 {
        u32 pcrIndex;       // 0
        u32 eventType;      // 3 (EV_NO_ACTION)

        TPML_DIGEST_VALUES {
         u32 count;         // 2
         TPMT_HA {
          u16 hashAlg;      // 0xb (SHA256)
          u8  digest[32];   // 0
         }
         TPMT_HA {
          u16 hashAlg;      // 0xd (SHA512)
          u8  digest[64];   // 0
         }
        }

        u32 eventSize;      // sizeof(the following)

        u8  signature[16];  // "VM VERSION\0\0\0\0\0\0"
        u8  name[32];       // "QEMU virt", "kvmtool", "cloudhv", ...
        u8  version[40];    /* enough for a SHA hash */

        // Provide the address of the log early on, so we can create the DTB
        // immediately after. The DTB contains a pointer to the event log.
        u64 log_start;
        u64 log_size;

        // experimental: info needed for DTB generation on kvmtool, QEMU and cloudhv
        u64 ram_size;
        u32 num_cpus;
      }

  "All EV_NO_ACTION events SHALL set TCG_PCR_EVENT2.digests to all 0x00’s
  for each allocated Hash algorithm. See Section 10.2.2 TCG_PCR_EVENT2
  Structure."


* Option: pass the generated firmware table (DT/ACPI) raw, so the verifier can
  check its content, rather than generate an identical table itself.

  Non-standard: new signature for EV_NO_ACTION.

      TCG_PCR_EVENT2 {
        // ... EV_NO_ACTION header

        u8    signature[16];    // "DTB\0\0\0\0\0\0\0\0\0\0\0\0\0"
        u8    dtb[eventSize - 16];
      }

      // "this specification recommends a maximum value for the
      // TCG_PCR_EVENT2.eventSize field of 1MB." 
      // As an example, QEMU DTB used in verification is 7kB.
      #define MAX_DTB_SIZE        (SZ_1MB - 16)


* RMM parameters:

  Standard, although EV_EVENT_TAG is supposed to be for OS/applications.

      TCG_PCR_EVENT2 {
        u32 pcrIndex;       // 0
        u32 eventType;      // 6 (EV_EVENT_TAG)
        TPML_DIGEST_VALUES {
         u32  count;        // 1
         TPMT_HA {
          u16 hashAlg;      // 0xb (SHA512)
          u8  digest[64];   // 0 (not much point in hashing this)
         }
        }

        u32 eventSize;      // sizeof(the following)

        u32 taggedEventId;
        u32 taggedEventDataSize;
        u8  taggedEventData[taggedEventDataSize];
      }

  The verifier associates the following IDs and data with pcrIndex 0:

      1 : REALM_CREATE {
        u64 flags;      // PMU (4), SVE (2), LPA2 (1)
        u8  s2sz;
        u8  sve_vl;
        u8  num_bps;
        u8  num_wps;
        u8  pmu_num_ctrs;
        u8  hash_algo;
      }
      2: INIT RIPAS {
        u64 base;
        u64 size;
      }
      3: REC_CREATE {
        u64 flags;      /* 1: measured */
        u64 pc;
        u64 gprs[8];
      }

* The log itself is not measured but still loaded into guest memory, resulting
  in RIM extension by RMI_DATA_CREATE.

      TCG_PCR_EVENT2 {
        u32 pcrIndex;       // 0
        u32 eventType;      // 13 (EV_POST_CODE2)
        TPML_DIGEST_VALUES {
         u32 count;         // 1
         TPMT_HA {
          u16 hashAlg;      // 0xb (SHA512)
          u8  digest[64];   // SHA512 hash of the kernel image
         }
        }

        u32 eventSize;      // sizeof(the following)

        UEFI_PLATFORM_FIRMWARE_BLOB2 {
          u8  BlobDescriptionSize;  // 7
          u8  BlobDescription[7];   // "LOG"
          u64 BlobBase;             // base IPA
          u64 BlobSize;             // max log size
        }
      }

* UEFI blob: EV_EFI_PLATFORM_FIRMWARE_BLOB2

  Standard.

      TCG_PCR_EVENT2 {
        u32 pcrIndex;       // 0
        u32 eventType;      // 0x80000000a (EV_EFI_PLATFORM_FIRMWARE_BLOB2)
        TPML_DIGEST_VALUES {
         u32 count;         // 1
         TPMT_HA {
          u16 hashAlg;      // 0xb (SHA512)
          u8  digest[64];   // SHA512 hash of the firmware image
         }
        }

        u32 eventSize;      // sizeof(the following)

        UEFI_PLATFORM_FIRMWARE_BLOB2 {
          u8  BlobDescriptionSize;  // 6
          u8  BlobDescription[6];   // "FIRMWARE" (anything goes, vendor defined)
          u64 BlobBase;             // base IPA
          u64 BlobSize;             // file size
        }
      }


* Kernel blob: EV_POST_CODE2

  Non-standard: we introduce a new blob description string.

      TCG_PCR_EVENT2 {
        // ... EV_POST_CODE2 header

        UEFI_PLATFORM_FIRMWARE_BLOB2 {
          u8  BlobDescriptionSize;  // 7
          u8  BlobDescription[7];   // "KERNEL"
          u64 BlobBase;             // base IPA
          u64 BlobSize;             // Image size (file size)
        }
      }


* Initrd blob: EV_POST_CODE2

  Non-standard: we introduce a new blob description string.

      TCG_PCR_EVENT2 {
        // ... EV_POST_CODE2 header

        UEFI_PLATFORM_FIRMWARE_BLOB2 {
          u8  BlobDescriptionSize;  // 7
          u8  BlobDescription[7];   // "INITRD"
          u64 BlobBase;             // base IPA
          u64 BlobSize;             // initrd size
        }
      }


* DTB if measured: EV_POST_CODE2

  Non-standard: we introduce a new blob description string.

      TCG_PCR_EVENT2 {
        // ... EV_POST_CODE2 header

        UEFI_PLATFORM_FIRMWARE_BLOB2 {
          u8  BlobDescriptionSize;  // 4
          u8  BlobDescription[4];   // "DTB"
          u64 BlobBase;             // base IPA
          u64 BlobSize;             // DTB size
        }
      }


* ACPI if measured: EV_POST_CODE2

  Standard.

      TCG_PCR_EVENT2 {
        // ... EV_POST_CODE2 header

        UEFI_PLATFORM_FIRMWARE_BLOB2 {
          u8  BlobDescriptionSize;  // 10
          u8  BlobDescription[10];  // "ACPI DATA"
          u64 BlobBase;             // base IPA
          u64 BlobSize;             // ACPI tables size
        }
      }



Compatibility with IGVM
-----------------------

[IGVM] provides instructions to a VMM for initializing a VM. Instead of passing
a firmware image to the VMM (with `-bios` on QEMU) you pack it in an IGVM file
and pass that to the VMM (`-object igvm-cfg`). This is useful to create a
predictable initial VM state without a strict VM specification, and for packing
multiple firmware payloads ([coconut-svsm-igvm]).

The IGVM file contains IGVM_VHS_PAGE_DATA instructions for each page to be
loaded into guest memory. As far as I can tell it doesn't delineate the files
themselves, so it would be incompatible with the EV_EFI_PLATFORM_FIRMWARE_BLOB2
event described above, for example. Two solutions:

* the event log only describe granules, like IGVM. The verifier does have a list
  of granules for each file so it can find granule hashes.

* the IGVM format is extended to add file information.

This needs more research but we should aim for compatibility between IGVM and
the RIM log, since both can be useful together.


[CCEL]: https://uefi.org/sites/default/files/resources/ACPI_Spec_6_5_Aug29.pdf#subsection.5.2.34

[ACPI TPM2]: https://trustedcomputinggroup.org/wp-content/uploads/TCG-ACPI-Specification-Version-1.4-Revision-15_pub.pdf#%5B%7B%22num%22%3A70%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C33%2C574%2C0%5D

[devicetree node tpm]: https://www.kernel.org/doc/Documentation/devicetree/bindings/tpm/tpm-common.yaml

[HashLogExtendEvent]: https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#%5B%7B%22num%22%3A64%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C734%2C0%5D

[TCG2]: https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/
[IMA event log]: https://ima-doc.readthedocs.io/en/latest/event-log-format.html#ima-event-log-binary-format

[CEL]: https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_CEL_v1_r0p41_pub.pdf

[CMW]: https://datatracker.ietf.org/doc/html/draft-ietf-rats-msg-wrap/

[RATS-CCA-TOKEN]: https://datatracker.ietf.org/doc/html/draft-ffm-rats-cca-token/

[CoMID]: https://datatracker.ietf.org/doc/html/draft-ietf-rats-corim/

[CC TDX PCR]: https://uefi.org/specs/UEFI/2.10/38_Confidential_Computing.html#intel-trust-domain-extension

[IGVM]: https://github.com/microsoft/igvm
[IGVM-DEFS]: https://docs.rs/igvm_defs/0.3.3/igvm_defs/
[coconut-svsm-igvm]: https://github.com/coconut-svsm/svsm/tree/main/igvmbuilder
