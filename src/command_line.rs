/// Parse the main command-line, and provide some helpers for raw VMM
/// command-line parsing.
///
use std::collections::VecDeque;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;

use crate::kvmtool::KvmtoolArgs;
use crate::qemu::QemuArgs;

/// Host capabilities influence the VM configuration. They contain hardware
/// capabilities, restricted by both the non-secure and the Realm hypervisor.
/// For example, if HW and KVM support 10 PMU counters but RMM doesn't then
/// pmu_num_ctrs is 0.
#[derive(Debug, Parser, Default, Deserialize)]
#[command(next_help_heading = "Host capabilities")]
#[serde(deny_unknown_fields)]
pub struct RealmParams {
    /// Number of IPA bits
    #[arg(long, value_name = "N")]
    pub ipa_bits: Option<u8>,

    /// Maximum number of breakpoints (2-16)
    #[arg(long, value_name = "N")]
    pub num_bps: Option<u8>,

    /// Maximum number of watchpoints (2-16)
    #[arg(long, value_name = "N")]
    pub num_wps: Option<u8>,

    /// Maximum SVE vector length (bits, pow of two, 128-2048, 0 disables)
    #[arg(long, value_name = "N")]
    pub sve_vl: Option<u16>,

    /// Maximum number of PMU counters (0-31)
    #[arg(long, value_name = "N")]
    pub pmu_num_ctrs: Option<u8>,

    /// PMU is supported
    #[arg(long)]
    pub pmu: Option<bool>,

    /// LPA2 is supported
    #[arg(long)]
    pub lpa2: Option<bool>,
}

// This is the help blurb:
/// Generate a Realm token corresponding to a given VM configuration and
/// environment. Can also generate firmware tables (DTB, ACPI) to be provided to
/// the VMM.
#[derive(Debug, Parser)]
#[command(version, long_about, verbatim_doc_comment)]
pub struct Args {
    /// Display more information
    #[arg(short, long)]
    pub verbose: bool,

    /// Output file for the generated DTB
    #[arg(long, value_name = "file")]
    pub output_dtb: Option<String>,

    /// Do not generate Realm token (only validate parameters and generate DTB)
    #[arg(long)]
    pub no_token: bool,

    /// Kernel image
    #[arg(short, long, value_name = "file")]
    pub kernel: Option<String>,

    /// Initrd image
    #[arg(short, long, value_name = "file")]
    pub initrd: Option<String>,

    /// Firmware image
    #[arg(short, long, value_name = "file")]
    pub firmware: Option<String>,

    /// Config file. Can be specified multiple times to provide overlays.
    /// For example: -c hardware.conf -c firmware.conf -c hypervisor.conf
    #[arg(short, long, verbatim_doc_comment, value_name = "file")]
    pub config: Vec<String>,

    #[command(flatten)]
    pub host: RealmParams,

    #[command(subcommand)]
    pub vmm: VmmType,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum VmmType {
    /// Use the QEMU VMM
    Qemu(QemuArgs),
    /// Use the kvmtool VMM
    Kvmtool(KvmtoolArgs),
}

/// VMM arguments
pub type RawArgs = VecDeque<String>;

// Maybe add a clap parser for this?
pub fn raw_args_from_vec(v: &[String]) -> RawArgs {
    RawArgs::from(v.to_owned())
}

/// Return the next argument or an error
pub fn pop_arg(raw_args: &mut RawArgs, arg: &str) -> Result<String> {
    raw_args
        .pop_front()
        .ok_or_else(|| anyhow!("{arg} needs a value"))
}

/// Split the given argument at the first '=', re-inserting the value into raw_args.
/// Returns a copy of the argument
pub fn split_arg_eq(raw_args: &mut RawArgs, arg: &String) -> String {
    match arg.split_once('=') {
        None => String::from(arg),
        Some((a, v)) => {
            raw_args.push_front(String::from(v));
            String::from(a)
        }
    }
}
