use clap::Parser;
use std::fs;

use realm_token::event_log::{EventLogParser, MeasurementImages};
use realm_token::realm::Realm;

#[derive(Debug, Parser)]
/// Parse an event log, try to construct the reference values
struct Args {
    /// Log file in the TCG2 format
    log_file: String,

    /// Checksums file
    checksums_file: Option<String>,
}

fn main() {
    stderrlog::new().verbosity(5).init().unwrap();
    let args = Args::parse();

    let mut parser = EventLogParser::new();
    if let Some(f) = args.checksums_file {
        parser.images(MeasurementImages::from_checksums(&f).unwrap());
    }

    let mut realm = Realm::new();
    let log = fs::read(args.log_file).unwrap();
    parser.parse_tcg_log(&log, &mut realm).unwrap();
    println!("{:?}", realm.measurements);
}
