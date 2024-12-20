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
//! The `realm-measurements` tool transforms a VMM command-line into the
//! corresponding measurements.
//!
//! Example
//! ```bash
//! realm-measurements
//!     -c configs/qemu-sbsa-9.1.conf   # Host machine
//!     -c configs/rmm-1.0-rel0.conf    # RMM parameters
//!     -k Image                        # Kernel image
//!     --output-dtb qemu-gen.dtb       # generated DTB
//!     qemu                            # VMM type. Parameters follow
//!     -M virt,confidential-guest-support=rme0
//!     -object rme-guest,id=rme0,measurement-algorithm=sha512
//!     -cpu host -enable-kvm
//!     ...
//! ```
//!
//! # Event log parsing
//!
//! Parse an event log describing the different steps taken by the VMM and
//! boot loaders, and reconstruct the RIM and REM. This can be used by a
//! verifier to construct the reference values dynamically.
//!
//! Example
//! ```rust,no_run
//! use std::fs;
//! use cca_realm_measurements::{Realm, EventLogParser, MeasurementImages};
//!
//! // Collect the digests of images loaded into the Realm with:
//! // # sha256sum /path/to/image/dir/* > /tmp/images.digests
//! let images = MeasurementImages::from_checksums("/tmp/images.digests")
//!     .unwrap();
//!
//! // Obtain the raw event log from a running Realm:
//! let raw_tcg_log = fs::read("/sys/kernel/tsm/ccel").unwrap();
//!
//! let mut realm = Realm::new();
//!
//! EventLogParser::new()
//!     .images(images)
//!     .parse_tcg_log(&raw_tcg_log, &mut realm);
//!
//! // If everything went well, display the RIM and REMs:
//! println!("Measurements: {:?}", realm.measurements);
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
/// Parse an event log and construct the reference values
pub mod event_log;
/// Simulate realm initialization to calculate the reference values
pub mod realm;
/// VMM tools
pub mod vmm;

pub use event_log::{DTBTemplates, EventLogParser, MeasurementImages};
pub use realm::Realm;

// mod realm re-exports these
mod realm_comid;
mod realm_config;
mod realm_params;

mod command_line;
/// FDT surgery. Experimental and unstable!
pub mod dtb_surgeon;
mod fdt;
mod utils;

/// Cloud Hypervisor VMM
pub mod cloud_hypervisor;
/// Kvmtool VMM
pub mod kvmtool;
/// QEMU VMM
pub mod qemu;
