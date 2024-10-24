//! Compute the Realm Initial and Extensible Measurements for Arm CCA.
//!
//! This project provides tools to compute the measurements of a Realm. Two
//! modes are supported: pre-computation of reference values and runtime
//! computation using an event log.
//!
//! # Reference values provisioning
//!
//! Compute the Realm Initial Measurement (RIM) for a given Virtual
//! Machine Monitor (VMM), in order to provision a verifier with reference
//! values. When receiving an attestation request, the verifier checks the
//! given realm-token for those reference values, and ensures that the Realm
//! is running what you expect.
//!
//! The `realm-token` tool transforms a VMM command-line into the
//! corresponding measurements.
//!
//! Example
//! ```bash
//! realm-token
//!     -c configs/qemu-sbsa-9.1.conf   # Host machine
//!     -c configs/rmm-1.0-rel0.conf    # RMM parameters
//!     -k Image                        # Kernel image
//!     --output-dtb qemu-gen.dtb       # generated DTB
//!     qemu                            # VMM type. Parameters follow
//!     -M virt,confidential-guest-support=rme0
//!     -object rme-guest,id=rme0,measurement-algo=sha512
//!     -cpu host -enable-kvm
//!     ...
//! ```
//!
//! # About RIM and REM
//!
//! A Realm is a confidential computing environment within the Arm Confidential
//! Compute Architecture [CCA]. The Virtual Machine Monitor (VMM) and the
//! hypervisor create a Realm VM by issuing commands to the Realm Management
//! Monitor [RMM]. The initial state of the VM is measured into the Realm
//! Initial Measurements (RIM). At runtime, the realm can add its own
//! measurements to four Realm Extensible Measurements (REM). The RIM and REM,
//! along with a personalization value, form the Realm Token.
//!
//! [CCA]: https://www.arm.com/architecture/security-features/arm-confidential-compute-architecture
//! [RMM]: https://developer.arm.com/documentation/den0137/1-0rel0/

#![warn(missing_docs)]
/// Simulate realm initialization to calculate the reference values
pub mod realm;
/// VMM tools
pub mod vmm;

// mod realm re-exports these
mod realm_comid;
mod realm_config;
mod realm_params;

mod command_line;
mod fdt;
mod utils;

/// Cloud Hypervisor VMM
pub mod cloud_hypervisor;
/// Kvmtool VMM
pub mod kvmtool;
/// QEMU VMM
pub mod qemu;
