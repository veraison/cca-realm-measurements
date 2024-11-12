#![allow(non_camel_case_types)]
use bincode::serialize;
/// Build a fake event log to perform tests
use cca_realm_measurements::{EventLogParser, Realm};
use serde::ser::SerializeTuple;
use serde::{Serialize, Serializer};
use uefi_eventlog::EventType;

#[derive(Serialize, Debug)]
struct tcg_algo_desc {
    algo_id: u16,
    digest_size: u16,
}

#[derive(Serialize, Debug)]
struct tcg_pc_client_pcr_event {
    index: u32,
    event_type: u32,
    digest: [u8; 20],
    data_size: u32,
    signature: [u8; 16],
    platform_class: u32,
    family_version_minor: u8,
    family_version_major: u8,
    spec_revision: u8,
    uintn_size: u8,
    number_of_algo: u32, // 2
    algo_desc: [tcg_algo_desc; 2],
    vendor_info_size: u8, // 0
}

#[derive(Serialize)]
struct tcg_pcr_event_2_head {
    index: u32,
    event_type: u32,
    digest_count: u32, // 1
}

#[derive(Serialize)]
struct digest_sha256 {
    hash_algo: u16,
    digest: [u8; 32],
}

#[derive(Serialize)]
struct cca_vmm_version {
    signature: [u8; 16],
    name: [u8; 32],
    #[serde(serialize_with = "serialize_array")]
    version: [u8; 40],

    log_start: u64,
    log_size: u64,
    ram_size: u64,
    num_cpus: u32,
}

#[derive(Serialize)]
struct cca_realm_create {
    flags: u64,
    s2sz: u8,
    sve_vl: u8,
    num_bps: u8,
    num_wps: u8,
    pmu_num_ctrs: u8,
    hash_algo: u8,
}

fn serialize_array<S: Serializer, const N: usize>(
    t: &[u8; N],
    serializer: S,
) -> core::result::Result<S::Ok, S::Error> {
    let mut ser_tuple = serializer.serialize_tuple(N)?;
    for e in t {
        ser_tuple.serialize_element(e)?;
    }
    ser_tuple.end()
}

fn init_str(dst: &mut [u8], src: &str) {
    let len = src.len();
    dst[..len].copy_from_slice(&src.as_bytes()[..len]);
}

enum HashAlgo {
    Sha256 = 0xB,
    Sha512 = 0xD,
}

#[test]
fn main() {
    //stderrlog::new().verbosity(5).init().unwrap();
    let mut parser = EventLogParser::new();
    parser.fatal(true);

    let mut log = vec![];

    let mut e = tcg_pc_client_pcr_event {
        index: 0,
        event_type: EventType::NoAction.into(),
        digest: [0; 20],
        data_size: 37, // remainder of this struct
        signature: [0; 16],
        platform_class: 0, // client
        family_version_minor: 0,
        family_version_major: 2, // TPM lib version 2.0
        spec_revision: 106,
        uintn_size: 2,
        number_of_algo: 2,
        algo_desc: [
            tcg_algo_desc {
                algo_id: HashAlgo::Sha256 as u16,
                digest_size: 32,
            },
            tcg_algo_desc {
                algo_id: HashAlgo::Sha512 as u16,
                digest_size: 64,
            },
        ],
        vendor_info_size: 0,
    };
    init_str(&mut e.signature, "Spec ID Event03");
    log.extend(serialize(&e).unwrap());

    // Test the log without events
    let mut realm = Realm::new();
    parser.parse_tcg_log(&log, &mut realm).unwrap();

    let no_action = tcg_pcr_event_2_head {
        index: 0,
        event_type: EventType::NoAction.into(),
        digest_count: 1,
    };
    log.extend(serialize(&no_action).unwrap());
    let empty_digest = digest_sha256 {
        hash_algo: HashAlgo::Sha256 as u16,
        digest: [0; 32],
    };
    log.extend(serialize(&empty_digest).unwrap());

    // Test an incomplete log: the uefi_eventlog lib should discard the partial
    // event without throwing an error.
    realm = Realm::new();
    parser.parse_tcg_log(&log, &mut realm).unwrap();

    let mut e = cca_vmm_version {
        signature: [0; 16],
        name: [0; 32],
        version: [0; 40],
        log_start: 2 << 20,
        log_size: 1 << 10,
        ram_size: 1 << 30,
        num_cpus: 128,
    };
    init_str(&mut e.signature, "VM VERSION");
    init_str(&mut e.name, "kvmtool");
    let b = serialize(&e).unwrap();
    log.extend(serialize(&(b.len() as u32)).unwrap());
    log.extend(b);

    // Test the log with one event
    realm = Realm::new();
    parser.parse_tcg_log(&log, &mut realm).unwrap();

    // Add Realm Params event
    let tag = tcg_pcr_event_2_head {
        index: 0,
        event_type: EventType::EventTag.into(),
        digest_count: 1,
    };
    log.extend(serialize(&tag).unwrap());
    log.extend(serialize(&empty_digest).unwrap());

    let e = cca_realm_create {
        flags: 0,
        s2sz: 48,
        sve_vl: 0,
        num_bps: 5,
        num_wps: 3,
        pmu_num_ctrs: 0,
        hash_algo: 0,
    };
    let b = serialize(&e).unwrap();
    log.extend(serialize(&(2 * 4 + b.len() as u32)).unwrap()); // event size
    log.extend(serialize(&1u32).unwrap()); // ID
    log.extend(serialize(&(b.len() as u32)).unwrap()); // data size
    log.extend(b);

    // Test the log with one event
    realm = Realm::new();
    parser.parse_tcg_log(&log, &mut realm).unwrap();
    //println!("{:?}", realm.measurements.to_base64_array());
    let m = realm.measurements.to_base64_array();
    assert_eq!(
        m,
        [
            "iWDVaCY3CqpvybOgQdQkBolYK6QeKti7j5rfbSoM1ec=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        ]
    );
}
