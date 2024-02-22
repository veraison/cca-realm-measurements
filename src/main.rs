use std::process;

use clap::Parser;

mod command_line;
mod realm;
mod utils;
mod vmm;

use command_line::*;

fn main() {
    let args = Args::parse();

    let params = match args.vmm {
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
