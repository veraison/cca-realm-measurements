/// Parse the main command-line, and provide some helpers for raw VMM
/// command-line parsing.
///
use std::collections::VecDeque;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

use crate::cloud_hypervisor::CloudHVArgs;
use crate::kvmtool::KvmtoolArgs;
use crate::qemu::QemuArgs;
use crate::realm_params::RealmParams;

// This is the help blurb:
/// Generate Realm measurements corresponding to a given VM configuration and
/// environment. Can also generate firmware tables (DTB, ACPI) to be provided to
/// the VMM.
#[derive(Debug, Parser)]
#[command(version, long_about, verbatim_doc_comment)]
pub struct Args {
    /// Display more information (use multiple times to increase verbosity)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Output file for the generated DTB
    #[arg(long, value_name = "file")]
    pub output_dtb: Option<String>,

    /// Input DTB template
    #[arg(long, value_name = "file")]
    pub input_dtb: Option<String>,

    /// Do not generate Realm measurements (only validate parameters and
    /// generate DTB)
    #[arg(long)]
    pub no_measurements: bool,

    /// Display measurement encoded in base64, instead of raw hex
    #[arg(long)]
    pub print_b64: bool,

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

    /// Input file containing CoMID endorsements in JSON
    #[arg(long, value_name = "file")]
    pub endorsements_template: Option<String>,

    /// Output file containing CoMID endorsements in JSON
    #[arg(long, value_name = "file")]
    pub endorsements_output: Option<String>,

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
    /// Use the cloud-hypervisor VMM
    CloudHV(CloudHVArgs),
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
