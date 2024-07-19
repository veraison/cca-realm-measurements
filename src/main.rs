use std::process;

use clap::Parser;

mod cloud_hypervisor;
mod command_line;
mod fdt;
mod kvmtool;
mod qemu;
mod realm;
mod realm_comid;
mod utils;
mod vmm;

use command_line::*;

fn main() {
    let args = Args::parse();

    let params = match args.vmm {
        VmmType::Qemu(ref a) => qemu::build_params(&args, a),
        VmmType::Kvmtool(ref a) => kvmtool::build_params(&args, a),
        VmmType::CloudHV(ref a) => cloud_hypervisor::build_params(&args, a),
    };

    let mut params = params.unwrap_or_else(|e| {
        eprintln!("Cannot build parameters: {e:#}");
        process::exit(1);
    });

    if args.no_token {
        return;
    }

    if let Err(e) = params.compute_token() {
        eprintln!("Failed to compute token: {e:#}");
        process::exit(1);
    }
}
