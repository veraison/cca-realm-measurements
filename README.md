Given a VM configuration and the payload to run in the Realm, this tool
calculates the Realm Initial and Extensible Measurements, needed for CCA
attestation.

Usage
=====

Build with:

    cargo build

Run with:

    target/debug/realm-measurements [options] <VMM> [vmm-args]

In the following example, the realm is started with kvmtool as VMM, using
direct kernel boot. The host is QEMU TCG.

    realm-measurement -c configs/qemu-max-8.2.conf -c configs/kvm.conf      (1)
        -k ~/build/linux-cca/arch/arm64/boot/Image                          (2)
        --output-dtb ~/vm/shr/kvmtool-gen.dtb                               (3)
        kvmtool                                                             (4)
        -c 2 -m 256 --realm --console virtio --irqchip=gicv3-its
        --sve-vl=512 --pmu -k guest_kernel -d disk --9p shr

1. "-c" options provide host capabilities such as SVE vector length. Multiple
   config files can be provided, for example hardware, firmware, hypervisor and
   RMM capabilities. The capabilities can also be overriden with command-line
   arguments.
2. "-k", "-i", "-f" is the payload loaded into Realm memory
3. "--output-dtb" will contain the generated DTB, to be provided to the VMM
4. Arguments that follow the VMM name are those that will be passed to the VMM,
   and describe the VM configuration.

This displays RIM and REM. With the endorsements parameters, it generates a
[CoMID] file containing the reference values ([cca-corim]), that can be sent to a
verifier:

	--endorsements-template samples/comid-cca-realm.json
    --endorsements-output cca-realm-endorsements.json

The reference values are then packed into a CoRIM file and sent to the
verifier, using the [cocli] tool:

	cocli comid create --template=cca-realm-endorsements.json
	cocli corim create --template samples/corim-cca-realm.json
		--comid cca-realm-endorsements.cbor --output cca-realm-corim.cbor

Provisionning a [veraison] verifier running locally can be done with:

	veraison -- cocli corim submit --corim-file cca-realm-corim.cbor
		--api-server=https://provisioning-service:8888/endorsement-provisioning/v1/submit
		--media-type "'application/corim-unsigned+cbor; profile=http://arm.com/cca/realm/1'"

Helper
------

scripts/gen-run-vmm.sh generates a boot script and a DTB for the Realm. In the
host run:

	gen-run-vmm.sh [--kvmtool|--cloudhv]
	./run-qemu.sh OR ./run-kvmtool.sh OR ./run-cloudhv.sh

The relying party or RV provider can run this same script to generate the
Reference Value file (using templates in samples/):

	gen-run-vmm.sh --corim-output cca-realm-corim.cbor

A config file gen-run-vmm.cfg for this script could be:

    REALM_MEASUREMENTS=$HOME/src/realm-measurements/target/debug/realm-measurements
    KERNEL=$HOME/build/linux/arch/arm64/boot/Image
    INITRD=$HOME/build/buildroot/images/rootfs.cpio
    EDK2_DIR=$HOME/src/edk2/
    OUTPUT_SCRIPT_DIR=$HOME/shr/
    OUTPUT_DTB_DIR=$HOME/shr/
    CONFIGS_DIR=$HOME/src/realm-measurements/configs/


Event log
---------

The event_log library parses a TCG event log to construct the reference values.
See [docs/measurement-log.md], examples/ and the rust documentation for this
library.


Realm token
===========

The Realm Token describes the state of the Realm VM at the time it is attested.
It comprises the Realm Initial Measurement (RIM), which includes initial
register and memory state, and Realm Extensible Measurement (REM) computed by the
Realm itself, for example to measure a kernel image obtained from the host at
runtime.

The following example uses language from the Remote Attestation standard [RATS].
A client (the Relying Party) wants to ensure that a remote service provider is
running in a Realm the correct payload, on the correct hardware and firmware.


                     ┌────────┐ ┌──────────┐ ┌────────┐
                     │  EAT   │ │          │ │        │
                     │  (2) ──┼─┼─►      ◄─┼─┼── (1)  │
                     │        │ │          │ │    RV  │
                     │      ◄─┼─┼── (3)    │ │        │
                     │        │ │   EAR    │ │        │
                     └────────┘ └──────────┘ └────────┘
                      Attester    Verifier   RV provider

1. The client initially provisions a trusted third party, the Verifier, with
   Reference Values (RV).

2. The Attester (Realm) establishes a secure connection to the Verifier. The
   Verifier sends a challenge, for example a random number that gets included
   into the realm token to guarantee freshness.

   The Realm asks RMM for an attestation token. RMM produces the Realm token.
   The platform signs the Realm token and the platform token, forming the CCA
   attestation token.

   The Realm sends the result of these calculations to the verifier, in the
   form of an Entity Attestation Token ([EAT]).

3. The verifier checks the signature and compares the returned tokens with
   known reference values, sends back appraisal [EAR]. If everything matches,
   the client can share secrets with the Realm.

This tool helps with calculating a Realm token in order to provision the
verifier at step (1). The easiest way of computing the Realm token would be to
run the payload in the same environment, on a machine that we own and trust.
But neither client nor verifier might afford to own such hardware. In addition,
many changes to VM parameters such as number of vCPUs, amount of memory,
devices, would require running the whole payload again in order to collect the
corresponding token. Here we provide ways to calculate a Realm Token
independently from the Realm environment.


[RATS]: https://datatracker.ietf.org/doc/html/rfc9334
[EAT]: https://datatracker.ietf.org/doc/html/draft-ietf-rats-eat/
[EAR]: https://datatracker.ietf.org/doc/html/draft-fv-rats-ear/

[CoMID]: https://datatracker.ietf.org/doc/draft-ietf-rats-corim/
[cca-corim]: https://datatracker.ietf.org/doc/draft-ydb-rats-cca-endorsements/

[cocli]: https://github.com/veraison/corim/tree/main/cocli
[veraison]: https://github.com/veraison/services
