use std::process;

use clap::Parser;

mod cloud_hypervisor;
mod command_line;
mod dtb_surgeon;
mod fdt;
mod kvmtool;
mod qemu;
mod realm;
mod realm_comid;
mod realm_config;
mod realm_params;
mod utils;
mod vmm;

use command_line::*;

fn main() {
    let args = Args::parse();

    stderrlog::new()
        .verbosity(2 + args.verbose as usize)
        .init()
        .unwrap();

    let params = match args.vmm {
        VmmType::Qemu(ref a) => qemu::build_params(&args, a),
        VmmType::Kvmtool(ref a) => kvmtool::build_params(&args, a),
        VmmType::CloudHV(ref a) => cloud_hypervisor::build_params(&args, a),
    };

    let mut params = params.unwrap_or_else(|e| {
        log::error!("Cannot build parameters: {e:#}");
        process::exit(1);
    });

    if args.no_measurements {
        return;
    }

    if let Err(e) = params.compute_measurements() {
        log::error!("Failed to compute measurements: {e:#}");
        process::exit(1);
    }
}
