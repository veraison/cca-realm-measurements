/// Parse a DTB and outtput it, ensuring that input and output are identical
use std::process::ExitCode;

use clap::Parser;
use std::fs;
use vm_fdt::FdtWriter;

use cca_realm_measurements::dtb_surgeon::{DTBResult, DTBSurgeon};

#[derive(Debug, Parser)]
/// Parse a DTB and output it
struct Args {
    /// Input file
    input_dtb: String,

    /// Output file
    output_dtb: Option<String>,

    /// Display trace
    #[arg(short)]
    verbose: bool,
}

/// NOP implementation of the DTB surgeon
#[derive(Debug)]
pub struct DefaultDTBSurgeon {}
impl DTBSurgeon for DefaultDTBSurgeon {
    fn mem(&self) -> (u64, u64) {
        panic!()
    }

    /// Base guest-physical address and size of initrd, if enabled.
    fn initrd(&self) -> Option<(u64, u64)> {
        None
    }

    /// Kernel parameters, if any
    fn bootargs(&self) -> Option<&str> {
        None
    }

    fn handle_property(
        &self,
        _fdt: &mut FdtWriter,
        _node_name: &str,
        _property_name: &str,
        _property_val: &[u8],
    ) -> DTBResult<bool> {
        Ok(false)
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    let verbose = if args.verbose {
        stderrlog::LogLevelNum::Trace
    } else {
        stderrlog::LogLevelNum::Info
    };
    stderrlog::new().verbosity(verbose).init().unwrap();

    let surgeon = DefaultDTBSurgeon {};

    let input = fs::read(args.input_dtb).unwrap();
    let mut output = surgeon.update_dtb(&input).unwrap();

    // VMMs may pad the DTB with zeroes at the end to fill a fixed-size buffer.
    // They may set the header totalsize (QEMU) or not (kvmtool). If they do,
    // then the surgeon itself updates the totalsize. Otherwise we pad it
    // ourselves:
    if output.len() < input.len() {
        output.resize(input.len(), 0);
    }

    if let Some(output_file) = args.output_dtb {
        fs::write(output_file, &output).unwrap();
    }
    if output != input {
        log::error!("output differs");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
