use std::process;

use clap::Parser;

mod command_line;
mod utils;

use command_line::*;

fn main() {
    let args = Args::parse();
}
