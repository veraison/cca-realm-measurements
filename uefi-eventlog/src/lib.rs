use std::io::Read;

use byteorder::{LittleEndian, ReadBytesExt};
use fallible_iterator::FallibleIterator;
use log::{info, trace};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
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

fn map_eof(e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Eof
    } else {
        Error::Io(e)
    }
}

#[derive(Debug)]
enum LogType {
    PcrEvent,
    Event2,
}

const EFI_EVENT_BASE: u32 = 0x80000000;
#[derive(Debug, PartialEq, FromPrimitive, Copy, Clone)]
#[repr(u32)]
enum KnownEventType {
    // TCG PC Client Specific Implementation Specification for Conventional BIOS
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

    // TCG EFI Platform Specification For TPM Family 1.1 or 1.2, table 7-1
    EFIVariableDriverConfig = EFI_EVENT_BASE + 0x1,
    EFIVariableBoot = EFI_EVENT_BASE + 0x2,
    EFIBootServicesApplication = EFI_EVENT_BASE + 0x3,
    EFIBootServicesDriver = EFI_EVENT_BASE + 0x4,
    EFIRuntimeServicesDriver = EFI_EVENT_BASE + 0x5,
    EFIGptEvent = EFI_EVENT_BASE + 0x6,
    EFIAction = EFI_EVENT_BASE + 0x7,
    EFIPlatformFirmwareBlob = EFI_EVENT_BASE + 0x8,
    EFIHandoffTables = EFI_EVENT_BASE + 0x9,
    EFIVariableAuthority = EFI_EVENT_BASE + 0xE0,
}

#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum EventType {
    // TCG PC Client Specific Implementation Specification for Conventional BIOS
    PrebootCert,
    PostCode,
    Unused,
    NoAction,
    Separator,
    Action,
    EventTag,
    CrtmContents,
    CrtmVersion,
    CpuMicrocode,
    PlatformConfigFlags,
    TableOfDevices,
    CompactHash,
    IPL,
    IPLPartitionData,
    NonhostCode,
    NonhostConfig,
    NonhostInfo,
    OmitbootDeviceEvents,

    // TCG EFI Platform Specification For TPM Family 1.1 or 1.2, table 7-1
    EFIVariableDriverConfig,
    EFIVariableBoot,
    EFIBootServicesApplication,
    EFIBootServicesDriver,
    EFIRuntimeServicesDriver,
    EFIGptEvent,
    EFIAction,
    EFIPlatformFirmwareBlob,
    EFIHandoffTables,
    EFIVariableAuthority,

    // Others
    Unknown(u32),
}

impl From<u32> for EventType {
    fn from(raw: u32) -> Self {
        match KnownEventType::from_u32(raw) {
            Some(val) => val.into(),
            None => EventType::Unknown(raw),
        }
    }
}

impl From<EventType> for u32 {
    fn from(et: EventType) -> Self {
        match et {
            EventType::Unknown(v) => v,
            _ => et.to_known().unwrap() as u32,
        }
    }
}

impl EventType {
    fn to_known(&self) -> Option<KnownEventType> {
        Some(match self {
            EventType::PrebootCert => KnownEventType::PrebootCert,
            EventType::PostCode => KnownEventType::PostCode,
            EventType::Unused => KnownEventType::Unused,
            EventType::NoAction => KnownEventType::NoAction,
            EventType::Separator => KnownEventType::Separator,
            EventType::Action => KnownEventType::Action,
            EventType::EventTag => KnownEventType::EventTag,
            EventType::CrtmContents => KnownEventType::CrtmContents,
            EventType::CrtmVersion => KnownEventType::CrtmVersion,
            EventType::CpuMicrocode => KnownEventType::CpuMicrocode,
            EventType::PlatformConfigFlags => KnownEventType::PlatformConfigFlags,
            EventType::TableOfDevices => KnownEventType::TableOfDevices,
            EventType::CompactHash => KnownEventType::CompactHash,
            EventType::IPL => KnownEventType::IPL,
            EventType::IPLPartitionData => KnownEventType::IPLPartitionData,
            EventType::NonhostCode => KnownEventType::NonhostCode,
            EventType::NonhostConfig => KnownEventType::NonhostConfig,
            EventType::NonhostInfo => KnownEventType::NonhostInfo,
            EventType::OmitbootDeviceEvents => KnownEventType::OmitbootDeviceEvents,
            EventType::EFIVariableDriverConfig => KnownEventType::EFIVariableDriverConfig,
            EventType::EFIVariableBoot => KnownEventType::EFIVariableBoot,
            EventType::EFIBootServicesApplication => KnownEventType::EFIBootServicesApplication,
            EventType::EFIBootServicesDriver => KnownEventType::EFIBootServicesDriver,
            EventType::EFIRuntimeServicesDriver => KnownEventType::EFIRuntimeServicesDriver,
            EventType::EFIGptEvent => KnownEventType::EFIGptEvent,
            EventType::EFIAction => KnownEventType::EFIAction,
            EventType::EFIPlatformFirmwareBlob => KnownEventType::EFIPlatformFirmwareBlob,
            EventType::EFIHandoffTables => KnownEventType::EFIHandoffTables,
            EventType::EFIVariableAuthority => KnownEventType::EFIVariableAuthority,
            EventType::Unknown(_) => return None,
        })
    }
}

impl From<KnownEventType> for EventType {
    fn from(ket: KnownEventType) -> Self {
        match ket {
            KnownEventType::PrebootCert => EventType::PrebootCert,
            KnownEventType::PostCode => EventType::PostCode,
            KnownEventType::Unused => EventType::Unused,
            KnownEventType::NoAction => EventType::NoAction,
            KnownEventType::Separator => EventType::Separator,
            KnownEventType::Action => EventType::Action,
            KnownEventType::EventTag => EventType::EventTag,
            KnownEventType::CrtmContents => EventType::CrtmContents,
            KnownEventType::CrtmVersion => EventType::CrtmVersion,
            KnownEventType::CpuMicrocode => EventType::CpuMicrocode,
            KnownEventType::PlatformConfigFlags => EventType::PlatformConfigFlags,
            KnownEventType::TableOfDevices => EventType::TableOfDevices,
            KnownEventType::CompactHash => EventType::CompactHash,
            KnownEventType::IPL => EventType::IPL,
            KnownEventType::IPLPartitionData => EventType::IPLPartitionData,
            KnownEventType::NonhostCode => EventType::NonhostCode,
            KnownEventType::NonhostConfig => EventType::NonhostConfig,
            KnownEventType::NonhostInfo => EventType::NonhostInfo,
            KnownEventType::OmitbootDeviceEvents => EventType::OmitbootDeviceEvents,
            KnownEventType::EFIVariableDriverConfig => EventType::EFIVariableDriverConfig,
            KnownEventType::EFIVariableBoot => EventType::EFIVariableBoot,
            KnownEventType::EFIBootServicesApplication => EventType::EFIBootServicesApplication,
            KnownEventType::EFIBootServicesDriver => EventType::EFIBootServicesDriver,
            KnownEventType::EFIRuntimeServicesDriver => EventType::EFIRuntimeServicesDriver,
            KnownEventType::EFIGptEvent => EventType::EFIGptEvent,
            KnownEventType::EFIAction => EventType::EFIAction,
            KnownEventType::EFIPlatformFirmwareBlob => EventType::EFIPlatformFirmwareBlob,
            KnownEventType::EFIHandoffTables => EventType::EFIHandoffTables,
            KnownEventType::EFIVariableAuthority => EventType::EFIVariableAuthority,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Digest {
    method: DigestAlgorithm,
    #[serde(serialize_with = "serialize_as_base64")]
    digest: Vec<u8>,
}

impl Digest {
    fn verify(&self, data: &[u8]) -> Result<(), Error> {
        let computed = hash(self.method.openssl_md(), data)?;

        if memcmp::eq(&self.digest, &computed) {
            Ok(())
        } else {
            Err(Error::InvalidEventDigest)
        }
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
            Some(pos) => Ok(data[(pos + 2)..data.len() - 1].as_bytes()),
        }
    }

    fn confirm_digests(&mut self) -> Result<(), Error> {
        // For some types of data, we can't even verify
        let data_to_confirm: Option<&[u8]> = match self.event {
            // NoAction is explicitly not measured or verified
            EventType::NoAction => None,

            // These EFI values we are unable to verify as the event doesn't contain all data
            EventType::EFIPlatformFirmwareBlob => None,
            EventType::EFIBootServicesApplication => None,

            // These EFI values we don't verify but TODO
            EventType::EFIHandoffTables => None,
            EventType::EFIVariableBoot => None,

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
            EventType::PostCode => None,

            // Everything else, assume it's the full data blob
            _ => Some(&self.data),
        };

        if let Some(data_to_confirm) = data_to_confirm {
            for dig in &self.digests {
                match dig.verify(&data_to_confirm) {
                    Ok(()) => {}
                    Err(_) => {
                        self.digest_verification_status = DigestVerificationStatus::Invalid;
                        break;
                    }
                }
            }
            if let DigestVerificationStatus::Unattempted = self.digest_verification_status {
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

#[derive(Debug)]
pub struct ParseSettings {
    // Workarounds for broken logs
    workaround_string_00af: bool,
}

impl Default for ParseSettings {
    fn default() -> ParseSettings {
        ParseSettings {
            workaround_string_00af: false,

        }
    }
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
    last_error: Option<Error>,
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
            last_error: None,
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
        let pcr_index = self.reader.read_u32::<LittleEndian>().map_err(map_eof)?;
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
        let parsed_data = parsed::ParsedEventData::parse(event_type, &eventbuf, self.settings);
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
        let pcr_index = self.reader.read_u32::<LittleEndian>().map_err(map_eof)?;

        // Event Type
        let event_type = self.reader.read_u32::<LittleEndian>()?;
        let event_type = EventType::from(event_type);

        // Digests
        let digest_count = self.reader.read_u32::<LittleEndian>()?;
        let mut digests = Vec::with_capacity(digest_count as usize);
        for _ in 0..digest_count {
            let raw_algo = self.reader.read_u16::<LittleEndian>()?;
            let algo = match DigestAlgorithm::from_tpm_alg_id(raw_algo) {
                None => return Err(Error::UnsupportedDigestMethod(raw_algo)),
                Some(v) => v,
            };
            let log_info = self.log_info.as_ref().unwrap();
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
        let parsed_data = parsed::ParsedEventData::parse(event_type, &eventbuf, self.settings);
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
            let mut firstevent = match self.parse_pcr_event() {
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
                    return Err(Error::EventParse(parsed::EventParseError::UnsupportedLog));
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

        match new_event {
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

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::Path;

    use fallible_iterator::FallibleIterator;
    use tpmless_tpm2::DigestAlgorithm;

    use crate::{DigestVerificationStatus, Parser};

    #[test]
    fn parse_bootlog() {
        let dirname = Path::new(env!("CARGO_MANIFEST_DIR"));
        let fname = dirname.join("test_assets/bootlog");
        let file = File::open(&fname).expect("Test asset opening failed");
        let settings = Default::default();

        let mut parser = Parser::new(file, &settings);

        while let Some(event) = parser.next().expect("Failed to parse event") {
            assert!(event.digest_verification_status != DigestVerificationStatus::Invalid);

            // All grub string events are validated
            if event.pcr_index == 8 {
                assert_eq!(
                    event.digest_verification_status,
                    DigestVerificationStatus::Verified
                );
            }
        }

        assert!(!parser.any_invalid());

        let pcrvals = parser.pcrs();

        // Sha1 bank
        assert_eq!(
            pcrvals.pcr_algo_value(0, DigestAlgorithm::Sha1).unwrap(),
            hex::decode("F080580492B92735CA943D0F58DA3BAE4DCCDD23").unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(1, DigestAlgorithm::Sha1).unwrap(),
            hex::decode("0319C44D0BA23140F64E1FCF5CAB2136EEC45DC8").unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(2, DigestAlgorithm::Sha1).unwrap(),
            hex::decode("B2A83B0EBF2F8374299A5B2BDFC31EA955AD7236").unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(3, DigestAlgorithm::Sha1).unwrap(),
            hex::decode("B2A83B0EBF2F8374299A5B2BDFC31EA955AD7236").unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(4, DigestAlgorithm::Sha1).unwrap(),
            hex::decode("6938A4AA133B3F2CEAED34C5D69957A77CB615E8").unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(5, DigestAlgorithm::Sha1).unwrap(),
            hex::decode("6E3958C581B8999ED37C6A7D4EE9B0CED4E1FF0E").unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(6, DigestAlgorithm::Sha1).unwrap(),
            hex::decode("B2A83B0EBF2F8374299A5B2BDFC31EA955AD7236").unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(7, DigestAlgorithm::Sha1).unwrap(),
            hex::decode("6D7206871C9C6F38AD3997BACEEBEE95DADEC04D").unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(8, DigestAlgorithm::Sha1).unwrap(),
            hex::decode("8C882017B021990D5D1EB3F71D9020C21605439B").unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(9, DigestAlgorithm::Sha1).unwrap(),
            hex::decode("80BB2AF0DFD10FECE3AFB74A8BE8DB590A95322D").unwrap(),
        );

        // Sha256 bank
        assert_eq!(
            pcrvals.pcr_algo_value(0, DigestAlgorithm::Sha256).unwrap(),
            hex::decode("DE5BAE1801B1055914582F526FEA0AA68E7DFACB4A5AD6CE55F8B2B6287C475C")
                .unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(1, DigestAlgorithm::Sha256).unwrap(),
            hex::decode("3D086AEE80EFF0B9D930CE43EC0D3ECBE73EA2F188E545FECC8D97E9ACF9F61F")
                .unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(2, DigestAlgorithm::Sha256).unwrap(),
            hex::decode("3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969")
                .unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(3, DigestAlgorithm::Sha256).unwrap(),
            hex::decode("3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969")
                .unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(4, DigestAlgorithm::Sha256).unwrap(),
            hex::decode("E79EBF94D2013D91808B2B250FCFB08260F73E6FD636704C0783EDB641BAECDD")
                .unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(5, DigestAlgorithm::Sha256).unwrap(),
            hex::decode("405F63FB377A6992CE75213C5D4E847BDFDBF2523DF3774573DE4E07C656A143")
                .unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(6, DigestAlgorithm::Sha256).unwrap(),
            hex::decode("3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969")
                .unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(7, DigestAlgorithm::Sha256).unwrap(),
            hex::decode("730777CFA2B4C2CF67A54CE7C80D7D15CEBD0A443D1BC320E43FE338812EA67B")
                .unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(8, DigestAlgorithm::Sha256).unwrap(),
            hex::decode("4788238034043585FD5254CD186D90ECA91D9911E2D7B1BDDE9EEE81704306DB")
                .unwrap(),
        );
        assert_eq!(
            pcrvals.pcr_algo_value(9, DigestAlgorithm::Sha256).unwrap(),
            hex::decode("6E22C7993F14C2313665A86EDC9998EAD5361D95C841DACCCEF6A52BDB4BF935")
                .unwrap(),
        );
    }
}
