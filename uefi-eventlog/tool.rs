use fallible_iterator::FallibleIterator;
use serde::Serialize;
use std::{env, fs::File};
use thiserror::Error;
use tpmless_tpm2::PcrExtender;

use uefi_eventlog::{Event, Parser, ParseSettings, DigestVerificationStatus};

#[derive(Debug, Error)]
enum ToolError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Error parsing event log: {0}")]
    EventLog(#[from] uefi_eventlog::Error),
    #[error("YAML Error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

#[derive(Debug, Serialize)]
struct Results {
    events: Vec<Event>,
    pcrs: PcrExtender,
}

fn main() -> Result<(), ToolError> {
    pretty_env_logger::init();

    let mut args = env::args();
    // Ignore our binary name
    args.next();
    let mut any_failures = false;
    let mut settings = ParseSettings::new();

    let mut print_output_yaml = true;
    let mut get_failed_events = false;

    for filename in args {
        if filename == "--workaround-shim-00af" {
            settings.set_workaround_string_00af(true);
            continue;
        }
        if filename == "--get-failed-events" {
            get_failed_events = true;
            print_output_yaml = false;
            continue;
        }
        let file = File::open(&filename)?;
        let mut parser = Parser::new(file, &settings);
        let mut events: Vec<Event> = Vec::new();

        while let Some(event) = parser.next()? {
            if get_failed_events {
                if let Some(Err(_)) = event.parsed_data {
                    panic!("FAiled");
                }
                if let DigestVerificationStatus::Invalid = event.digest_verification_status {
                    /*serde_yaml::to_writer(
                        std::io::stdout(),
                        &event,
                    )?;*/
                }
            } else {
                events.push(event);
            }
        }

        let any_invalid = parser.any_invalid();

        if print_output_yaml {
            serde_yaml::to_writer(
                std::io::stdout(),
                &Results {
                    events,
                    pcrs: parser.pcrs(),
                },
            )?;
        }

        if any_invalid {
            eprintln!("CAUTION: Invalid PCR values encountered!");
            any_failures = true;
        }

    }

    if any_failures {
        std::process::exit(1);
    }

    Ok(())
}
