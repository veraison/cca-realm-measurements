use std::io::Read;

use byteorder::{LittleEndian, ReadBytesExt};
use fallible_iterator::FallibleIterator;
use log::{info, trace};
use num_enum::{FromPrimitive, IntoPrimitive};
use openssl::{hash::hash, memcmp};
use serde::Serialize;
use thiserror::Error;
use tpmless_tpm2::{DigestAlgorithm, PcrExtender, PcrExtenderBuilder};

pub mod parsed;

fn serialize_as_base64<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::encode(bytes))
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Previous iteration failed")]
    PreviousIteration,
    #[error("End of file reached")]
    Eof,
    #[error("Error parsing event: {0}")]
    EventParse(#[from] parsed::EventParseError),
    #[error("Unsupported digest method {0:x} used")]
    UnsupportedDigestMethod(u16),
    #[error("TPMless error")]
    Tpmless(#[from] tpmless_tpm2::Error),
    #[error("Event had invalid digest value")]
    InvalidEventDigest,
    #[error("Cryptographic error occured")]
    Crypto(#[from] openssl::error::ErrorStack),
    #[error("Error decoding utf8 string")]
    StrUtf8(#[from] std::str::Utf8Error),
}

/// Transform an std::io Eof into Error::Eof
fn map_eof(error: Error) -> Error {
    match error {
        Error::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Error::Eof,
        _ => error,
    }
}

#[derive(Debug)]
enum LogType {
    PcrEvent,
    Event2,
}

const EFI_EVENT_BASE: u32 = 0x80000000;
#[derive(Debug, PartialEq, Copy, Clone, Serialize, IntoPrimitive, FromPrimitive)]
#[repr(u32)]
#[allow(clippy::upper_case_acronyms)]
pub enum EventType {
    // TCG PC Client Platform Firmware Profile Version 1.06 revision 52
    // Table 27 Events
    PrebootCert = 0x0,
    PostCode = 0x1,
    Unused = 0x2,
    NoAction = 0x3,
    Separator = 0x4,
    Action = 0x5,
    EventTag = 0x6,
    CrtmContents = 0x7,
    CrtmVersion = 0x8,
    CpuMicrocode = 0x9,
    PlatformConfigFlags = 0xA,
    TableOfDevices = 0xB,
    CompactHash = 0xC,
    IPL = 0xD,
    IPLPartitionData = 0xE,
    NonhostCode = 0xF,
    NonhostConfig = 0x10,
    NonhostInfo = 0x11,
    OmitbootDeviceEvents = 0x12,
    PostCode2 = 0x13,

    EFIVariableDriverConfig = EFI_EVENT_BASE + 0x1,
    EFIVariableBoot = EFI_EVENT_BASE + 0x2,
    EFIBootServicesApplication = EFI_EVENT_BASE + 0x3,
    EFIBootServicesDriver = EFI_EVENT_BASE + 0x4,
    EFIRuntimeServicesDriver = EFI_EVENT_BASE + 0x5,
    EFIGptEvent = EFI_EVENT_BASE + 0x6,
    EFIAction = EFI_EVENT_BASE + 0x7,
    EFIPlatformFirmwareBlob = EFI_EVENT_BASE + 0x8,
    EFIHandoffTables = EFI_EVENT_BASE + 0x9,
    EFIPlatformFirmwareBlob2 = EFI_EVENT_BASE + 0xA,
    EFIHandoffTables2 = EFI_EVENT_BASE + 0xB,
    EFIVariableBoot2 = EFI_EVENT_BASE + 0xC,
    EFIGptEvent2 = EFI_EVENT_BASE + 0xD,
    EFIHcrtmEvent = EFI_EVENT_BASE + 0x10,
    EFIVariableAuthority = EFI_EVENT_BASE + 0xE0,
    EFISpdmFirmwareBlob = EFI_EVENT_BASE + 0xE1,
    EFISpdmFirmwareConfig = EFI_EVENT_BASE + 0xE2,
    EFISpdmDevicePolicy = EFI_EVENT_BASE + 0xE3,
    EFISpdmDeviceAuthority = EFI_EVENT_BASE + 0xE4,

    #[default]
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct Digest {
    method: DigestAlgorithm,
    #[serde(serialize_with = "serialize_as_base64")]
    digest: Vec<u8>,
}

impl Digest {
    /// hash the data using the digest's method, and check that they match.
    pub fn verify(&self, data: &[u8]) -> Result<(), Error> {
        let computed = hash(self.method.openssl_md(), data)?;

        if memcmp::eq(&self.digest, &computed) {
            Ok(())
        } else {
            Err(Error::InvalidEventDigest)
        }
    }

    /// obtain the digest's algorithm
    pub fn method(&self) -> DigestAlgorithm {
        self.method
    }

    /// obtain the digest's value
    pub fn digest(&self) -> &Vec<u8> {
        &self.digest
    }
}

#[derive(Debug, Serialize)]
pub struct Event {
    pub pcr_index: u32,
    pub event: EventType,
    pub digests: Vec<Digest>,
    pub digest_verification_status: DigestVerificationStatus,
    #[serde(serialize_with = "serialize_as_base64")]
    pub data: Vec<u8>,
    pub parsed_data: Option<Result<parsed::ParsedEventData, parsed::EventParseError>>,
}

impl Event {
    fn strip_grub_prefix(&self) -> Result<&[u8], Error> {
        let data = std::str::from_utf8(&self.data)?;
        match data.find(": ") {
            None => Ok(data.as_bytes()),
            Some(pos) => Ok(&data.as_bytes()[(pos + 2)..data.len()]),
        }
    }

    fn confirm_digests(&mut self) -> Result<(), Error> {
        // For some types of data, we can't even verify
        let data_to_confirm: Option<&[u8]> = match self.event {
            // NoAction is explicitly not measured or verified
            EventType::NoAction => None,

            // These EFI values we are unable to verify as the event doesn't contain all data
            EventType::EFIPlatformFirmwareBlob
            | EventType::EFIPlatformFirmwareBlob2
            | EventType::EFIBootServicesApplication
            | EventType::EFIGptEvent2 => None,

            // These EFI values we don't verify but TODO
            EventType::EFIHandoffTables
            | EventType::EFIHandoffTables2
            | EventType::EFIVariableBoot
            | EventType::EFISpdmFirmwareBlob
            | EventType::EFISpdmFirmwareConfig
            | EventType::EFISpdmDevicePolicy
            | EventType::EFISpdmDeviceAuthority => None,

            // Grub
            EventType::IPL => {
                // 8 is the GRUB_STRING_PCR
                if self.pcr_index == 8 {
                    Some(self.strip_grub_prefix()?)
                } else {
                    None
                }
            }

            // For these events, we reconstruct the pcr_event structure
            EventType::PostCode | EventType::PostCode2 => None,

            // Everything else, assume it's the full data blob
            _ => Some(&self.data),
        };

        if let Some(data_to_confirm) = data_to_confirm {
            for dig in &self.digests {
                match dig.verify(data_to_confirm) {
                    Ok(()) => {}
                    Err(_) => {
                        self.digest_verification_status =
                            DigestVerificationStatus::Invalid;
                        break;
                    }
                }
            }
            if let DigestVerificationStatus::Unattempted = self.digest_verification_status
            {
                self.digest_verification_status = DigestVerificationStatus::Verified;
            }
        }

        Ok(())
    }

    fn extend(&self, ext: &mut PcrExtender) -> Result<(), Error> {
        if self.event != EventType::NoAction {
            for dig in &self.digests {
                ext.extend_digest(self.pcr_index, dig.method, &dig.digest)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct ParseSettings {
    // Workarounds for broken logs
    workaround_string_00af: bool,
}

impl ParseSettings {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn set_workaround_string_00af(&mut self, enabled: bool) {
        self.workaround_string_00af = enabled;
    }
}

#[derive(Debug)]
pub struct Parser<'set, R: Read> {
    reader: R,
    logtype: Option<LogType>,
    log_info: Option<parsed::EfiSpecId>,
    pcr_extender: PcrExtender,
    any_invalid: bool,

    // Settings
    settings: &'set ParseSettings,
}

impl<'set, R: Read> Parser<'set, R> {
    pub fn new(reader: R, settings: &'set ParseSettings) -> Self {
        Parser {
            reader,
            logtype: None,
            log_info: None,
            any_invalid: false,
            pcr_extender: PcrExtenderBuilder::new()
                .add_digest_method(DigestAlgorithm::Sha1)
                .add_digest_method(DigestAlgorithm::Sha256)
                .add_digest_method(DigestAlgorithm::Sha384)
                .add_digest_method(DigestAlgorithm::Sha512)
                .build(),

            settings,
        }
    }

    pub fn pcrs(self) -> PcrExtender {
        self.pcr_extender
    }

    pub fn any_invalid(&self) -> bool {
        self.any_invalid
    }
}

fn zeroed_vec(len: usize) -> Vec<u8> {
    vec![0; len]
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DigestVerificationStatus {
    Unattempted,
    Invalid,
    Verified,
}

fn invert_opt_res<T, E>(input: Result<Option<T>, E>) -> Option<Result<T, E>> {
    match input {
        Ok(None) => None,
        Ok(Some(val)) => Some(Ok(val)),
        Err(e) => Some(Err(e)),
    }
}

impl<R: Read> Parser<'_, R> {
    fn parse_pcr_event(&mut self) -> Result<Event, Error> {
        // PCR Index
        let pcr_index = self.reader.read_u32::<LittleEndian>()?;
        // Event Type
        let event_type = self.reader.read_u32::<LittleEndian>()?;
        let event_type = EventType::from(event_type);
        // 20-byte sha1 digest
        let mut digestbuf = zeroed_vec(20);
        self.reader.read_exact(&mut digestbuf)?;
        // Event size
        let event_size = self.reader.read_u32::<LittleEndian>()?;
        // Event contents
        let mut eventbuf = zeroed_vec(event_size as usize);
        self.reader.read_exact(&mut eventbuf)?;

        // Possibly parse
        let parsed_data =
            parsed::ParsedEventData::parse(event_type, &eventbuf, self.settings);
        let parsed_data = invert_opt_res(parsed_data);

        // Build up event structure
        let digests = vec![Digest {
            method: DigestAlgorithm::Sha1,
            digest: digestbuf,
        }];

        Ok(Event {
            pcr_index,
            event: event_type,
            digests,
            digest_verification_status: DigestVerificationStatus::Unattempted,
            data: eventbuf,
            parsed_data,
        })
    }

    fn parse_event2(&mut self) -> Result<Event, Error> {
        // PCR Index
        let pcr_index = self.reader.read_u32::<LittleEndian>()?;

        // Event Type
        let event_type = self.reader.read_u32::<LittleEndian>()?;
        let event_type = EventType::from(event_type);

        // Digests
        let mut digest_count = self.reader.read_u32::<LittleEndian>()?;

        let log_info = self.log_info.as_ref().unwrap();
        if event_type == EventType::NoAction
            && digest_count as usize == log_info.algo_sizes.len()
        {
            // For EV_NO_ACTION: "The digests field MUST contain all 0x00’s for
            // each allocated Hash algorithm." Sum all the known digest
            // sizes, and skip the field.
            let algo_sizes = log_info.algo_sizes.values().map(|v| 2 + *v as usize).sum();
            let mut digbuf = zeroed_vec(algo_sizes);
            self.reader.read_exact(&mut digbuf)?;
            digest_count = 0;
        };

        let mut digests = Vec::with_capacity(digest_count as usize);
        for _ in 0..digest_count {
            let raw_algo = self.reader.read_u16::<LittleEndian>()?;
            let algo = match DigestAlgorithm::from_tpm_alg_id(raw_algo) {
                None => return Err(Error::UnsupportedDigestMethod(raw_algo)),
                Some(v) => v,
            };
            let algo_size = match log_info.algo_sizes.get(&raw_algo) {
                None => return Err(Error::UnsupportedDigestMethod(raw_algo)),
                Some(v) => v,
            };
            let mut digbuf = zeroed_vec(*algo_size as usize);
            self.reader.read_exact(&mut digbuf)?;

            digests.push(Digest {
                method: algo,
                digest: digbuf,
            })
        }

        // Event size
        let event_size = self.reader.read_u32::<LittleEndian>()?;
        // Event contents
        let mut eventbuf = zeroed_vec(event_size as usize);
        self.reader.read_exact(&mut eventbuf)?;

        trace!(
            "Parsing event of type {:?}, size {:?}, PCR {}",
            event_type,
            event_size,
            pcr_index
        );

        // Possibly parse
        let parsed_data =
            parsed::ParsedEventData::parse(event_type, &eventbuf, self.settings);
        let parsed_data = invert_opt_res(parsed_data);

        // Build up Event structure
        Ok(Event {
            pcr_index,
            event: event_type,
            digests,
            digest_verification_status: DigestVerificationStatus::Unattempted,
            data: eventbuf,
            parsed_data,
        })
    }
}

impl<R: Read> FallibleIterator for Parser<'_, R> {
    type Item = Event;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Event>, Error> {
        if self.logtype.is_none() {
            let mut firstevent = match self.parse_pcr_event().map_err(map_eof) {
                Err(Error::Eof) => return Ok(None),
                Err(e) => return Err(e),
                Ok(val) => val,
            };

            firstevent.confirm_digests()?;
            firstevent.extend(&mut self.pcr_extender)?;

            trace!("First event: {:?}", firstevent);

            if firstevent.event == EventType::NoAction {
                info!("Log type: event2");
                let spec_id = parsed::EfiSpecId::parse(&firstevent.data)?;
                trace!("Parsed first event: {:?}", spec_id);
                if spec_id.uintn_size != 2 {
                    return Err(Error::EventParse(
                        parsed::EventParseError::UnsupportedLog,
                    ));
                }
                self.log_info = Some(spec_id);
                self.logtype = Some(LogType::Event2);
            // In this case, we explicitly fall through, to not return this marker event
            } else {
                info!("Log type: PcrEvent");
                self.logtype = Some(LogType::PcrEvent);
                return Ok(Some(firstevent));
            }
        }

        let new_event = match self.logtype.as_ref().unwrap() {
            // The None case is already captured above
            LogType::PcrEvent => self.parse_pcr_event(),
            LogType::Event2 => self.parse_event2(),
        };

        match new_event.map_err(map_eof) {
            Err(Error::Eof) => Ok(None),
            Err(e) => Err(e),
            Ok(mut val) => {
                val.confirm_digests()?;
                if val.digest_verification_status == DigestVerificationStatus::Invalid {
                    self.any_invalid = true;
                }
                val.extend(&mut self.pcr_extender)?;
                Ok(Some(val))
            }
        }
    }
}
