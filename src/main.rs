use std::process;

use clap::Parser;

mod command_line;

use command_line::*;

fn main() {
    let args = Args::parse();
}
