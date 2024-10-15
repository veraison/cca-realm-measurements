///
/// Parse a TCG event log to reconstruct Arm CCA Realm Measurements
///
use byteorder::{LittleEndian, ReadBytesExt};
use fallible_iterator::FallibleIterator; // for uefi_eventlog
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use uefi_eventlog::{parsed::ParsedEventData, Event, EventType, ParseSettings, Parser};

use rmm::{RmiHashAlgorithm, RmiRealmFlags, RmiRecCreateFlags, RmiRecParams, RmmError};

use crate::kvmtool;
use crate::qemu;
use crate::realm::{Realm, RealmError};
use crate::realm_params::RealmParams;
use crate::utils::buf_to_hex_str;
use crate::vmm::{BlobStorage, DTBGenerator, VmmError};

#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum EventLogError {
    #[error("event log was already parsed")]
    EventLogAlreadyParsed,

    #[error("log parse error")]
    Parse(#[from] uefi_eventlog::Error),

    #[error("event parse error: {0}")]
    ParseEvent(String),

    #[error("invalid image {0}")]
    InvalidImage(String),

    #[error("cannot parse checksum line '{0}'")]
    ParseChecksum(String),

    #[error("cannot parse DTB list line '{0}'")]
    ParseDTBList(String),

    #[error("invalid hash algorithm '{0}'")]
    InvalidHashAlgo(u8),

    #[error("image not found")]
    ImageNotFound,

    #[error("VMM")]
    Vmm(#[from] VmmError),

    #[error("RMM")]
    Rmm(#[from] RmmError),

    #[error("Realm")]
    Realm(#[from] RealmError),

    #[error("Unknown Relam flags {0:?}")]
    UnknownRealmFlags(u64),

    #[error("Unknown REC flags {0:?}")]
    UnknownRecFlags(u64),

    #[error("cannot generate DTB: {0}")]
    GenDTB(String),

    #[error("I/O")]
    IO(#[from] std::io::Error),

    #[error("UTF-8 encoding")]
    Encoding(#[from] std::str::Utf8Error),

    #[error("invalid filename encoding")]
    FilenameEncoding,
}
type Result<T> = core::result::Result<T, EventLogError>;

// Defined in docs/measurement-log.md
#[derive(FromPrimitive, PartialEq)]
enum RealmLogEvent {
    RealmCreate = 1,
    InitRipas,
    RecCreate,
}

#[derive(PartialEq)]
enum MeasurementIndex {
    Rim,
    Rem(u8),
}

const REALM_CREATE_LEN: usize = 8 + 6;
const INIT_RIPAS_LEN: usize = 2 * 8;
const REC_CREATE_LEN: usize = 10 * 8;

const VM_VERSION_SIGNATURE: &[u8] = "VM VERSION\0\0\0\0\0\0".as_bytes();
const KVMTOOL_NAME: &[u8] = "kvmtool".as_bytes();
const QEMU_NAME: &[u8] = "QEMU".as_bytes();

// Return the file content as String, and its absolute dirname
fn file_content_and_parent(filename: &str) -> Result<(String, PathBuf)> {
    let path = Path::new(filename);

    let dirname = if let Some(p) = path.parent() {
        if p == Path::new("") {
            std::env::current_dir()?
        } else {
            p.canonicalize()?
        }
    } else {
        std::env::current_dir()?
    };
    let content = std::fs::read_to_string(path)?;
    Ok((content, dirname))
}

// Transform a relative path to an absolute one, based on the directory
// base_path. Do not canonicalize. If path is already absolute, do nothing.
fn path_to_absolute(path: &str, base_path: &Path) -> Result<String> {
    let filename = Path::new(path);
    let mut path = base_path.to_path_buf();
    // if filename is absolute, it replaces base_path
    path.push(filename);
    path.canonicalize()?
        .into_os_string()
        .into_string()
        .map_err(|_| EventLogError::FilenameEncoding)
}

/// Images measured into the measurement registers. A hash map of the
/// <identifier, filepath>, where identifier is typically a hash of the image
/// and filepath the local path to the corresponding file.
///
/// An event log describes where these images were loaded into the Realm, or
/// what was measured by UEFI. We then check that the log entries correspond to
/// our local images by recreating the measurements.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct MeasurementImages {
    images: HashMap<String, BlobStorage>,
}

impl MeasurementImages {
    /// Create MeasurementImages from a checksum file, for example one generated
    /// by the sha256sum(1) tool. Each line of the file contains: a checksum, a
    /// space, a character indicating input mode ('*' for binary, ' ' for text
    /// or where binary is insignificant), and a filename.
    pub fn from_checksums(filename: &str) -> Result<Self> {
        let mut m = Self::default();

        let (checksums, dirname) = file_content_and_parent(filename)?;
        for l in checksums.lines() {
            let items: Vec<&str> = l.split(&[' ', '*']).collect();

            if items.len() != 3 {
                return Err(EventLogError::ParseChecksum(l.to_string()));
            }
            let path = path_to_absolute(items[2], &dirname)?;
            m.images
                .insert(items[0].to_string(), BlobStorage::from_file(&path));
        }
        Ok(m)
    }
}

/// MeasurementImages that can be shared between threads
type SharedMeasurementImages = Arc<RwLock<MeasurementImages>>;

#[derive(Debug)]
struct TcgEventLog<'a> {
    raw_log: &'a [u8],
    images: &'a SharedMeasurementImages,
    realm: &'a mut Realm,
    second_pass: bool,

    realm_params: Option<RealmParams>,
    dtb_generator: Option<Box<dyn DTBGenerator>>,

    missing_dtb: Option<Vec<u8>>,
    initrd: Option<(u64, u64)>,
    log: Option<(u64, u64)>,

    fatal: bool,
}

impl<'a> TcgEventLog<'a> {
    fn new(config: &'a EventLogParser, raw_log: &'a [u8], realm: &'a mut Realm) -> Self {
        Self {
            raw_log,
            images: &config.images,
            second_pass: false,
            realm,
            realm_params: None,
            dtb_generator: None,
            missing_dtb: None,
            initrd: None,
            log: None,
            fatal: config.fatal,
        }
    }

    /// Convert a PCR index to a CCA measurement register (RIM or REM*). The
    /// mapping is defined by UEFI:
    /// https://uefi.org/specs/UEFI/2.10/38_Confidential_Computing.html#vendor-specific-information
    fn pcr_to_measurement(&self, pcr_index: u32) -> MeasurementIndex {
        match pcr_index {
            0 => MeasurementIndex::Rim,
            1 | 7 => MeasurementIndex::Rem(0),
            2..=6 => MeasurementIndex::Rem(1),
            8..=15 => MeasurementIndex::Rem(2),
            _ => MeasurementIndex::Rem(3),
        }
    }

    // On the first pass, take note of the image if it can be useful for
    // generating firmware tables
    fn register_image(
        &mut self,
        event: &Event,
        description: &str,
        base: u64,
        length: u64,
    ) -> Result<()> {
        let index = self.pcr_to_measurement(event.pcr_index);
        if index != MeasurementIndex::Rim {
            return Ok(());
        }

        if description == "INITRD" {
            self.initrd = Some((base, length));
        } else if description == "LOG" {
            self.log = Some((base, length));
        } else if description == "DTB" {
            if event.digests.is_empty() {
                return Err(EventLogError::GenDTB("no digest for DTB".to_string()));
            }
            for digest in &event.digests {
                let hex_digest = buf_to_hex_str(digest.digest());
                if self.images.read().unwrap().images.contains_key(&hex_digest) {
                    return Ok(());
                }
            }

            self.missing_dtb = Some(event.digests[0].digest().clone());
        }
        Ok(())
    }

    fn measure_image(
        &mut self,
        event: &Event,
        _description: &str,
        base: u64,
        length: u64,
    ) -> Result<()> {
        let index = self.pcr_to_measurement(event.pcr_index);

        // No hash means the image is unmeasured.
        if event.digests.is_empty() && index == MeasurementIndex::Rim {
            self.realm.rim_data_create_unmeasured(base, length)?;
            return Ok(());
        }

        // If we have the image corresponding to the given digest, use it to
        // extend RIM or REM.
        for digest in &event.digests {
            let hex_digest = buf_to_hex_str(digest.digest());
            match &index {
                MeasurementIndex::Rim => {
                    if let Some(storage) =
                        self.images.write().unwrap().images.get_mut(&hex_digest)
                    {
                        self.realm.rim_data_create(base, storage)?;
                        return Ok(());
                    }
                }
                MeasurementIndex::Rem(rem_index) => {
                    // If the digest is present in self.images, it's good
                    // enough. We don't trust the log but self.images is
                    // genuine, so no need to re-verify the hash.
                    if self.images.read().unwrap().images.contains_key(&hex_digest) {
                        self.realm
                            .rem_extend(*rem_index as usize, digest.digest())?;
                        return Ok(());
                    }
                }
            }
        }

        Err(EventLogError::ImageNotFound)
    }

    fn parse_image_event(&mut self, event: &Event) -> Result<()> {
        match &event.parsed_data {
            Some(Ok(ParsedEventData::FirmwareBlobLocation2 {
                description,
                base,
                length,
            })) => {
                if self.second_pass {
                    self.measure_image(event, description, *base, *length)
                } else {
                    self.register_image(event, description, *base, *length)
                }
            }
            _ => Err(EventLogError::ParseEvent(format!(
                "invalid event data for {0:?}",
                event.event
            ))),
        }
    }

    fn parse_tag_event_first_pass(
        &mut self,
        id: RealmLogEvent,
        size: usize,
        data: &[u8],
    ) -> Result<()> {
        let mut data = data;
        if id == RealmLogEvent::RealmCreate {
            if size < REALM_CREATE_LEN {
                return Err(EventLogError::ParseEvent(format!(
                    "realm create length {0} < {REALM_CREATE_LEN}",
                    size
                )));
            }
            let mut params = RealmParams::default();

            let flags = data.read_u64::<LittleEndian>()?;
            let flags = RmiRealmFlags::from_bits(flags)
                .ok_or(EventLogError::UnknownRealmFlags(flags))?;
            let s2sz = data.read_u8()?;
            let sve_vl = data.read_u8()?;
            let num_bps = data.read_u8()?;
            let num_wps = data.read_u8()?;
            let pmu_num_ctrs = data.read_u8()?;
            let hash_algo = data.read_u8()?;

            params.set_ipa_bits(s2sz)?;
            if flags.contains(RmiRealmFlags::SVE) {
                params.set_sve_vl((sve_vl as u16 + 1) * 128)?;
            }
            params.set_num_bps(num_bps + 1)?;
            params.set_num_wps(num_wps + 1)?;
            if flags.contains(RmiRealmFlags::PMU) {
                params.set_pmu(true);
                params.set_pmu_num_ctrs(pmu_num_ctrs)?;
            }

            params.hash_algo = Some(RmiHashAlgorithm::try_from(hash_algo)?);
            self.realm_params = Some(params);
        }
        Ok(())
    }

    fn parse_tag_event_second_pass(
        &mut self,
        id: RealmLogEvent,
        size: usize,
        data: &[u8],
    ) -> Result<()> {
        let mut data = data;
        match id {
            RealmLogEvent::RealmCreate => {
                if let Some(params) = &self.realm_params {
                    self.realm.rim_realm_create(params)?;
                }
            }
            RealmLogEvent::InitRipas => {
                if size < INIT_RIPAS_LEN {
                    return Err(EventLogError::ParseEvent(format!(
                        "init ripas length {0} < {INIT_RIPAS_LEN}",
                        size
                    )));
                }
                let base = data.read_u64::<LittleEndian>()?;
                let size = data.read_u64::<LittleEndian>()?;
                let top = base + size;
                self.realm.rim_init_ripas(base, top)?;
            }
            RealmLogEvent::RecCreate => {
                if size < REC_CREATE_LEN {
                    return Err(EventLogError::ParseEvent(format!(
                        "rec create length {0} < {REC_CREATE_LEN}",
                        size
                    )));
                }
                let mut gprs: [u64; 8] = [0; 8];
                let flags = data.read_u64::<LittleEndian>()?;
                let flags = RmiRecCreateFlags::from_bits(flags)
                    .ok_or(EventLogError::UnknownRecFlags(flags))?;
                let pc = data.read_u64::<LittleEndian>()?;
                for gpr in &mut gprs {
                    *gpr = data.read_u64::<LittleEndian>()?;
                }

                let rec = RmiRecParams::new(flags, pc, gprs);
                self.realm.rim_rec_create(&rec)?;
            }
        }
        Ok(())
    }

    fn parse_tag_event(&mut self, event: &Event) -> Result<()> {
        let mut data = &event.data[..];

        let id = data.read_u32::<LittleEndian>()?;
        let id = FromPrimitive::from_u32(id)
            .ok_or(EventLogError::ParseEvent(format!("unknown tag {id}")))?;
        let size = data.read_u32::<LittleEndian>()? as usize;

        if self.second_pass {
            self.parse_tag_event_second_pass(id, size, data)
        } else {
            self.parse_tag_event_first_pass(id, size, data)
        }
    }

    fn parse_vmm_info(
        &mut self,
        name: [u8; 32],
        version: [u8; 40],
        data: &[u8],
    ) -> Result<()> {
        let mut data = data;
        // Extract chars up to the first NUL byte (or the whole field)
        let name = name.split(|c| *c == 0).next();
        let version = version.split(|c| *c == 0).next().unwrap_or(&[]);

        let mut gen: Box<dyn DTBGenerator> = match name {
            Some(KVMTOOL_NAME) => Box::new(kvmtool::KvmtoolParams::new()),
            Some(QEMU_NAME) => Box::new(qemu::QemuParams::new()),
            _ => {
                return Err(EventLogError::ParseEvent(format!("unhandled VMM {name:?}")))
            }
        };

        /*
         * For the moment the following fields are the same for all VMMs, but
         * VMMs can define their own structures later.
         */
        let ram_size = data.read_u64::<LittleEndian>()?;
        let num_cpus = data.read_u32::<LittleEndian>()?;

        /*
         * Limit the number of CPUs to avoid generating very large DTBs (from
         * CPU nodes) if the log contains invalid information.
         */
        if num_cpus > 0x10000 {
            return Err(EventLogError::ParseEvent(
                "invalid number of CPUs".to_string(),
            ));
        }
        gen.set_num_cpus(num_cpus as usize);
        gen.set_mem_size(ram_size);
        gen.set_its(true); // TODO
        gen.set_bootargs("console=hvc0"); // TODO

        self.dtb_generator = Some(gen);
        Ok(())
    }

    fn parse_no_action_event(&mut self, event: &Event) -> Result<()> {
        if self.second_pass {
            return Ok(());
        }
        let mut data = &event.data[..];

        let mut signature = [0; 16];
        data.read_exact(&mut signature)?;
        match &signature[..] {
            VM_VERSION_SIGNATURE => {
                let mut name = [0; 32];
                data.read_exact(&mut name)?;
                let mut version = [0; 40];
                data.read_exact(&mut version)?;

                self.parse_vmm_info(name, version, data)
            }
            _ => Err(EventLogError::ParseEvent(format!(
                "unknown signature {signature:?}"
            ))),
        }
    }

    /// Returns Ok(true) when encountering a NUL event, Ok(false) for other
    /// events, Err(e) on error.
    fn handle_event(&mut self, event: &Event) -> Result<bool> {
        match event.event {
            EventType::EFIPlatformFirmwareBlob2 | EventType::PostCode2 => {
                self.parse_image_event(event)?
            }
            EventType::EventTag => self.parse_tag_event(event)?,
            EventType::NoAction => self.parse_no_action_event(event)?,
            EventType::PrebootCert => return Ok(true), // 0: Reserved by TCG
            _ => {
                return Err(EventLogError::ParseEvent(format!(
                    "unexpected event type {0:?}",
                    event.event
                )))
            }
        }
        Ok(false)
    }

    // If the DTB isn't present, try to generate it
    fn generate_dtb(&mut self) -> Result<()> {
        let Some(missing_dtb) = &self.missing_dtb else {
            return Ok(());
        };

        let Some(gen) = &mut self.dtb_generator else {
            return Ok(());
        };

        if let Some((base, size)) = self.initrd {
            gen.set_initrd(base, size);
        }
        if let Some((base, size)) = self.log {
            gen.set_log_location(base, size);
        }
        if let Some(params) = &self.realm_params {
            gen.set_pmu(params.pmu.unwrap_or(false));
        }

        let dtb = gen.gen_dtb()?;

        // Now add this file to the images
        self.images
            .write()
            .unwrap()
            .images
            .insert(buf_to_hex_str(missing_dtb), BlobStorage::Bytes(dtb));

        Ok(())
    }

    /// Parse the TCG event log and extend measurements
    pub fn parse(&mut self) -> Result<()> {
        let settings = ParseSettings::new();
        let mut parser = Parser::new(self.raw_log, &settings);
        let mut events = vec![];

        if self.second_pass {
            return Err(EventLogError::EventLogAlreadyParsed);
        }

        // First pass to create the DTB if necessary
        while let Some(event) = parser.next()? {
            match self.handle_event(&event) {
                Ok(true) => break,
                Ok(false) => (),
                Err(e) => {
                    if self.fatal {
                        return Err(e);
                    } else {
                        log::debug!("error while handling event {event:?}: {e}")
                    }
                }
            }
            events.push(event);
        }

        self.generate_dtb()?;

        self.second_pass = true;
        // Second pass to build the measurements
        for event in &events {
            if let Err(e) = self.handle_event(event) {
                if self.fatal {
                    return Err(e);
                } else {
                    log::debug!("error while handling event {event:?}: {e}")
                }
            }
        }

        Ok(())
    }
}

/// Parse event logs and compute the measurements.
///
/// # Examples
///
/// To simply parse one log, see the main library example.
///
/// For verifiers, the recommended usage is to create one EventLogParser
/// instance containing reference images. Then for each verification create a
/// Realm and parse one or more logs. The EventLogParser can be shared between
/// threads using an Arc.
///
/// ```
/// use std::thread;
/// use std::sync::Arc;
/// use realm_token::realm::Realm;
/// use realm_token::event_log::{MeasurementImages, EventLogParser};
///
/// let mut parser = EventLogParser::new();
/// // [...setup parser config...]
/// let shared_parser = Arc::new(parser);
///
/// let mut threads = vec![];
/// for i in 1..10 {
///     let p = Arc::clone(&shared_parser);
///     threads.push(thread::spawn(move || {
///         let mut realm = Realm::new();
///         p.parse_tcg_log(&[], &mut realm).unwrap();
///         println!("{:?}", realm.measurements);
///     }));
/// }
/// for t in threads {
///     t.join().unwrap();
/// }
/// ```
///
/// Internally it uses RwLock to maintain the images and dtbs, so multiple
/// threads can call parse_tcg_logs(). At the moment the RwLock is taken for
/// writing when accessing the content of an image or a DTB, because BlobStorage
/// is accessed lazily (mmapped on the first access). The RwLock is taken for
/// reading when we only need to check the existence of an image, during REM
/// calculation.
#[derive(Debug, Default)]
pub struct EventLogParser {
    images: SharedMeasurementImages,

    fatal: bool,
}

impl EventLogParser {
    /// Create a new event log parser.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable aborting after an event error. When true, all errors
    /// are fatal. When false, an error encountered while parsing an event is
    /// ignored (logged as debug) and the next event is parsed.
    pub fn fatal(&mut self, v: bool) -> &mut Self {
        self.fatal = v;
        self
    }

    /// Set image files loaded into the Realm.
    pub fn images(&mut self, images: MeasurementImages) -> &mut Self {
        self.images = Arc::new(RwLock::new(images));
        self
    }

    /// Parse the given log in TCG TPM2 format, and update the Realm state.
    /// When this returns successfully, the realm contains updated measurements.
    pub fn parse_tcg_log(&self, raw_log: &[u8], realm: &mut Realm) -> Result<()> {
        TcgEventLog::new(self, raw_log, realm).parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let parser = EventLogParser::new();
        let log = [0; 0];
        let mut realm = Realm::new();
        parser.parse_tcg_log(&log, &mut realm).unwrap();
        assert!(realm.measurements.rim == [0; 64]);

        let log = include_bytes!("../testdata/realm-bootlog.bin");
        assert!(parser.parse_tcg_log(log, &mut realm).is_ok());
    }

    #[test]
    fn test_path() {
        let current_path = std::env::current_dir().unwrap();
        let testdata_path = std::fs::canonicalize("testdata/").unwrap();
        let path = path_to_absolute("../", &testdata_path).unwrap();
        let path2 = path_to_absolute("../", &PathBuf::from("testdata/")).unwrap();
        assert_eq!(current_path, PathBuf::from(&path));
        assert_eq!(PathBuf::from(&path), PathBuf::from(&path2));

        let path = path_to_absolute("some-file.txt", &testdata_path).unwrap();
        assert_eq!(
            PathBuf::from(&path),
            std::fs::canonicalize("testdata/some-file.txt").unwrap()
        );

        assert!(file_content_and_parent("testdata/nonexistent-file.txt").is_err());

        let (_, path) = file_content_and_parent("Cargo.toml").unwrap();
        assert_eq!(path, current_path);

        let (_, path) = file_content_and_parent("testdata/some-file.txt").unwrap();
        assert_eq!(path, testdata_path);
    }
}
