Realm Virtual Machine specification
===================================

Version 0.3

This document specifies the format and construction of a Realm Virtual Machine
(VM) for Arm CCA[^CCA-intro]. The specification only covers aspects of a VM
needed for calculating the Realm Measurements, so that a verifier can
independently reconstruct the Realm Token and attest the initial state of the
Realm.

The hypervisor runs at EL2/EL1 and communicates with RMM[^RMM], while the
Virtual Machine Monitor (VMM) runs at EL0 and communicates with the hypervisor.
Together they prepare and manage the VM. The amount of work done by either
component depends on the hypervisor type, but the combination of the two follows
these rules:

* The hypervisor SHOULD use optimal block sizes when calling RMI_RTT_CREATE and
  RMI_RTT_INIT_RIPAS to initialize the protected IPA space of the Realm. For
  example, part of an IPA range that can be described with a level 2 Block
  descriptor SHOULD NOT be described with level 3 Page descriptors; part of an
  IPA range that can be described with a level 1 Block descriptor SHOULD NOT be
  described with level 2 Block or level 3 Page descriptors.

  Rationale: the number of RMI_RTT_INIT_RIPAS calls needed to cover an IPA
    range depends on the translation table layout.

* The hypervisor SHOULD use the maximum possible number of concatenated tables at
  the RTT starting level.

  Rationale: allows to calculate the number of RTT levels, and predictably
    reconstruct the RMI_RTT_INIT_RIPAS calls.

* The Realm Personalization Value (RPV) is a 512-bit number differentiating VMs
  that otherwise have the same RIM. When the user doesn't provide a RPV, the VMM
  or hypervisor SHOULD write it as zeroes in the RmiRealmParams.rpv buffer.
  Otherwise, they SHOULD write it as provided by the user, most significant byte
  first, and pad it with zeroes on the right if the user provided fewer than 64
  bytes.

* The VMM and hypervisor SHOULD call RMI_RTT_INIT_RIPAS first. They SHOULD set
  the IPA state of all guest RAM as `RAM`.

* RMI_DATA_CREATE calls with flag `measure == RMI_MEASURE_CONTENT` SHOULD follow
  RMI_RTT_INIT_RIPAS. Ranges described by RMI_RTT_INIT_RIPAS and RMI_DATA_CREATE
  MAY overlap.

* The VMM and hypervisor SHOULD issue RMI_DATA_CREATE calls in ascending IPA
  order.

* RMI_REC_CREATE calls SHOULD follow RMI_DATA_CREATE calls whose flag `measure`
  is `RMI_MEASURE_CONTENT`.

* The VMM SHOULD only make the first REC runnable. The other RECs are enabled
  with PSCI and are not part of the initial measurement.

* RMI_DATA_CREATE calls with `flags.measure == RMI_NO_MEASURE_CONTENT`, if any,
  SHOULD follow RMI_REC_CREATE calls.

* The VMM SHOULD set the IPA state of all guest RAM as RIPAS_RAM before
  initializing data granules.

* VMMs create different virtual platforms, whose layout directly affects the
  Realm Measurements. The VMM SHOULD create the VM with one of the following
  platform layouts.


Kvmtool
-------

* The amount of guest RAM MUST be a multiple of 2MB.

  Rationale: simplifies the DTB placement rules.

* The amount of guest RAM and number of vCPUs MUST be given on the
  command-line.

* The IPA size MUST be at least 33 bits. It MUST fit the requested RAM, plus
  one bit for the unprotected IPA space.

* If unspecified, the measurement algorithm SHOULD be SHA256.

* When a kernel is provided, the VMM MUST load it at the base of RAM, plus an
  optional offset that depends on the kernel.

  Note: The offset for a Linux kernel is given in the Image header
    [^Linux-boot].

* When a measurement log is enabled, it must be placed just before address
  0x90000000, or when there is less than 256MB or RAM, at the end of RAM.

* The DTB MUST have a fixed size of 64kB, padded with zeros. When a measurement
  log is enabled, the DTB MUST be placed just before the measurement log, at an
  address aligned on 2MB. Otherwise the DTB MUST be placed at address
  0x8fe00000, or when there is less than 256MB of RAM, at the address 2MB from
  the end of RAM, aligned on 2MB.

* The initrd, when present, MUST be placed before the DTB, at the highest
  possible address aligned on 4 bytes.

* The VMM SHOULD NOT append kernel parameters to those provided by the user.

  Rationale: simpler specification and simpler tools. Since this is
    a "SHOULD NOT", kvmtool can keep doing it but the DTB generator
    doesn't have to, and the user can just provide everything
    (console= and root=) explicitly.

* The memory map SHOULD be:

      Range                       Component               Compatible
      0x00000000 - 0x0000ffff     PCI I/O Port
      0x01000000 - 0x01000007     UART0                   "ns16550a"
      0x01001000 - 0x01001007     UART1
      0x01002000 - 0x01002007     UART2
      0x01003000 - 0x01003007     UART3
      0x01010000 - 0x01010001     RTC                     "motorola,mc14818"
      0x03000000 - 0x030001ff     virtio-mmio
      0x03000200 - 0x030003ff     virtio-mmio
       ...                        virtio-mmio
      A          - B-1            GIC ITS
      B          - 0x3ffeffff     GIC redistributors
      0x3fff0000 - 0x3fffffff     GIC distributor
      0x40000000 - 0x4fffffff     PCI config region       "pci-host-ecam-generic"
      0x50000000 - 0x7fffffff     PCI I/O region
      0x80000000                  RAM

  Notes:
  * A and B depend on the number of vCPUs: there is one 128kB
    redistributor for each vCPU, and the 128kB ITS is placed before the
    redistributors.
  * virtio-mmio devices are instantiated following the user command-line,
    when the selected virtio transport is virtio-mmio instead of
    virtio-pci.

* The interrupt map SHOULD follow these rules:

      PPI number          Component               Triggered
      7                   PMU                     Level   high
      11                  virtual timer           Level   low
      13                  S physical timer        Level   low
      14                  NS physical timer       Level   low

  TODO: fix the timer interrupts to be active high?

      SPI number          Component               Triggered
      0 - 3               UART 0 - 3              Level   high
      4 - 63              virtio-mmio             Edge    low-high
      64 - 95             PCI                     Level   high

  Note: this predictable SPI distribution requires invasive changes in kvmtool,
    but seems necessary. 32 SPIs, one for each slot on a bus. All buses share
    this range, which requires multiplexing interrupts. In practice there is
    never 32 devices in a VM so kvmtool doesn't yet implement multiplexing.
    QEMU does something similar for PCI but only uses 4 SPIs and more devices
    share the same line.


QEMU virt v9.1
--------------

* The IPA size SHOULD be at least 41 bits.

  Rationale: to fit the higher regions in the memory map, plus one
    bit for unprotected IPAs.

* The VM SHOULD have less than 255 GB of RAM.

  Rationale: simplifies the memory map calculation, so that the PCI
    regions have fixed addresses. Shouldn't be too complicated to
    extend later, but it's plenty for now.

* If unspecified, the measurement algorithm SHOULD be SHA512.

* When using direct kernel boot:

  * The kernel SHOULD be placed at the beginning of RAM.

    Note: Linux text_offset is always zero, see cfa7ede20f13 ("arm64: set
      TEXT_OFFSET to 0x0 in preparation for removing it entirely")

    TODO: support other kernels.

  * The initrd, when present, SHOULD be placed after the kernel, at a minimum
    address of 0x48000000, or half the RAM size if there is less than 256MB of
    RAM. The initrd SHOULD be aligned on 4kB.

  * The DTB SHOULD be placed after the initrd, at an address aligned on 2MB. If
    no initrd is present, the address calculation is done with an initrd size
    of 0.

  * The VMM SHOULD point the initial PC at the kernel entry point, instead of
    an intermediate bootloader.

    Rationale: simplify independent RIM calculation.

* When using firmware boot:

  * The DTB MUST be placed at address 0x40000000.

  * The firmware MUST be placed at address 0.

  Note: the fw_cfg device is used to optionally pass kernel and initrd to the
    guest. The firmware measures them and adds them to the REM.

* When a measurement log is enabled, it must be placed 1024 KiB after the
  DTB, with a size of 64KiB.

* The memory map SHOULD be:

      Range                       Component               Compatible
      0x00000000 - 0x07ffffff     Firmware RAM
      0x08000000 - 0x0800ffff     GIC distributor
      0x08080000 - 0x0809ffff     GIC ITS
      0x080a0000 - 0x08ffffff     GIC redistributors
      0x09000000 - 0x09000fff     UART                    "arm,pl011\0arm,primecell"
      0x09010000 - 0x09010fff     RTC                     "arm,pl031\0arm,primecell"
      0x09020000 - 0x09020017     fw-cfg                  "qemu,fw-cfg-mmio"
      0x0a000000 - 0x0a003fff     virtio-mmio (32 devices)
      0x0c000000 - 0x0dffffff     Platform bus            "qemu,platform\0simple-bus"
      0x10000000 - 0x3efeffff     PCI low I/O region
      0x3eff0000 - 0x3effffff     PCI I/O port
      0x40000000                  RAM
      0x4000000000 - 0x4003ffffff GIC additional redistributors
      0x4010000000 - 0x401fffffff PCI config region       "pci-host-ecam-generic"
      0x8000000000 - 0xffffffffff PCI high I/O region

  Notes:
  * The firmware RAM is only present when using firmware boot.
  * Since one redistributor is 128kB for GICv3 and 256kB for GICv4, the high
    redistributor region is only present when there are more than 123 CPUs with
    GICv3, or 61 CPUs with GICv4.

* The interrupt map SHOULD follow these rules:

      PPI number          Component               Triggered
      7                   PMU                     Level   high
      11                  virtual timer           Level   high
      13                  S physical timer        Level   high
      14                  NS physical timer       Level   high

      SPI number          Component               Triggered
      1                   UART                    Level   high
      2                   RTC                     Level   high
      3 - 6               PCI                     Level   high
      16 - 47             virtio-mmio             Edge    low-high

  Note: the PCI line interrupts are distributed according to the device slot
    number and the pin: `line = 3 + ((device + (pin - 1)) & 0x3)`.

* The UART and RTC SHOULD be connected to a 24 MHz clock, compatible
  "fixed-clock".

  TODO: can we remove this?  I think the Linux driver complains/fails when the
  node is missing, but not sure anymore.


[^CCA-intro]:
        Learn the architecture - Introducing Arm Confidential Compute Architecture
        <https://developer.arm.com/documentation/den0125/0300>

[^RMM]:
        Realm Management Monitor specification
        <https://developer.arm.com/documentation/den0137/1-0eac5/>

[^Linux-boot]:
        Booting AArch64 Linux
        <https://docs.kernel.org/arch/arm64/booting.html>
