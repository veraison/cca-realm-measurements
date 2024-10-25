///
/// Provides tools to build realm measurements, a little more high-level than
/// the Realm crate.
///
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::Write;

use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};

use crate::command_line::Args;
use crate::realm::*;
use crate::realm_params::RealmParams;
use crate::utils::*;
use crate::vmm::{GuestAddress, VmmBlob};
use rmm::{self, RmiHashAlgorithm, RmmRealmMeasurement, RMM_GRANULE};

use crate::realm_comid::RealmEndorsementsComid;

type Result<T> = core::result::Result<T, RealmError>;

/// High level configuration of the Realm. Compared to the low-level [Realm]
/// state, this adds some restrictions on the way the Realm is constructed, in
/// order to follow a strict VMM specification (`docs/realm-vm.md`).
#[derive(Default)]
pub struct RealmConfig {
    // Sorted list of blobs measured into the RIM
    rim_blobs: BTreeMap<GuestAddress, VmmBlob>,
    // List of unmeasured data regions (address, size)
    rim_unmeasured: Vec<(GuestAddress, u64)>,
    // List of (REM index, blobs) measured into the REM
    rem_blobs: Vec<(usize, VmmBlob)>,
    // RAM areas in the guest initialized with INIT_RIPAS
    ram_ranges: BTreeMap<GuestAddress, u64>,
    // The primary REC. We assume only the primary vCPU is runnable and the
    // others are booted with PSCI.
    rec: Option<rmm::RmiRecParams>,
    print_b64: bool,

    /// The Realm Personalization Value.
    pub personalization_value: PersonalizationValue,
    /// Realm parameters.
    pub params: RealmParams,

    endorsements_template: Option<String>,
    endorsements_output: Option<String>,
}

impl RealmConfig {
    /// Create a Realm configuration from command-line arguments, checking their
    /// validity
    pub fn from_args(args: &Args) -> Result<RealmConfig> {
        let mut config = RealmConfig::default();

        for filename in &args.config {
            config.load_config(filename)?;
        }

        config.print_b64 = args.print_b64;

        config.params.udpate(&args.host)?;
        log::debug!("Host config: {:?}", config.params);

        config
            .endorsements_template
            .clone_from(&args.endorsements_template);
        config
            .endorsements_output
            .clone_from(&args.endorsements_output);

        Ok(config)
    }

    fn load_config(&mut self, filename: &str) -> Result<()> {
        let content = fs::read_to_string(filename).map_err(|e| RealmError::File {
            filename: filename.to_string(),
            e,
        })?;
        let caps: RealmParams = toml::from_str(&content)
            .map_err(|e| RealmError::Config(format!("cannot parse {filename}: {e}")))?;

        // Capabilities that are already set by a previous config file can only
        // be lowered.
        self.params.restrict(&caps)?;

        Ok(())
    }

    /// Set algo used for all measurements
    ///
    /// # Arguments:
    ///
    /// * `s`: "sha256" or "sha512"
    pub fn set_measurement_algo(&mut self, s: &str) -> Result<()> {
        self.params.hash_algo = Some(s.parse::<RmiHashAlgorithm>()?);
        Ok(())
    }

    /// Add a range of RAM, to be initialized with INIT_RIPAS
    pub fn add_ram(&mut self, base: GuestAddress, size: u64) -> Result<()> {
        if self.ram_ranges.insert(base, size).is_some() {
            return Err(RealmError::Config(format!("duplicate RAM range at {base}")));
        }
        Ok(())
    }

    /// Add binary file to be measured as part of the Realm Initial Measurement.
    /// The VMM loads it into guest memory before boot.
    pub fn add_rim_blob(&mut self, blob: VmmBlob) -> Result<()> {
        let address = blob.guest_start;
        if self.rim_blobs.insert(address, blob).is_some() {
            return Err(RealmError::Config(format!("duplicate blob at {address}")));
        }
        Ok(())
    }

    /// Add a DATA region, whose creations is measured into the Realm Initial
    /// Measurement, but whose content isn't.
    pub fn add_rim_unmeasured(&mut self, base: GuestAddress, size: u64) -> Result<()> {
        self.rim_unmeasured.push((base, size));
        Ok(())
    }

    /// Add binary file to be measured as part of the Realm Extensible
    /// Measurement.
    pub fn add_rem_blob(&mut self, index: usize, blob: VmmBlob) -> Result<()> {
        self.rem_blobs.push((index, blob));
        Ok(())
    }

    /// Add primary RECs, with the given PC and parameters. The other RECs are
    /// not runnable and thus not measured.
    pub fn add_rec(&mut self, pc: u64, gprs: [u64; 8]) -> Result<()> {
        if self.rec.is_some() {
            return Err(RealmError::Config("only one REC is supported".to_string()));
        }

        self.rec = Some(rmm::RmiRecParams::new(
            rmm::RMI_REC_CREATE_F_RUNNABLE,
            pc,
            gprs,
        ));
        Ok(())
    }

    /// Compute the RIM using a predefined order: first init RIPAS of the whole
    /// guest RAM, then data granules in ascending order, then the RECs, then
    /// unmeasured data (log).
    fn compute_rim(&mut self) -> Result<Realm> {
        let mut realm = Realm::default();

        realm.rim_realm_create(&self.params)?;

        for (addr, size) in &self.ram_ranges {
            let base = align_down(*addr, RMM_GRANULE);
            let end = align_up(base + *size - 1, RMM_GRANULE);
            realm.rim_init_ripas(base, end)?;
        }

        for (addr, blob) in &mut self.rim_blobs {
            realm.rim_data_create(*addr, &mut blob.storage)?;
        }

        if let Some(rec) = &self.rec {
            realm.rim_rec_create(rec)?;
        } else {
            log::debug!("Missing REC");
        }

        for (addr, size) in &self.rim_unmeasured {
            realm.rim_data_create_unmeasured(*addr, *size)?;
        }

        Ok(realm)
    }

    /// Create a JSON file containing realm endorsements in the CoMID format
    fn publish_endorsements(&self, realm: &Realm) -> Result<()> {
        let mut endorsements: RealmEndorsementsComid = if let Some(filename) =
            &self.endorsements_template
        {
            let content = fs::read_to_string(filename).map_err(|e| RealmError::File {
                filename: filename.to_string(),
                e,
            })?;
            serde_json::from_str(&content).map_err(|e| {
                RealmError::Config(format!("cannot parse {filename}: {e}"))
            })?
        } else {
            RealmEndorsementsComid::new()
        };

        endorsements.init_refval();

        let hash_algo = match self.params.hash_algo {
            None => return Err(RealmError::Uninitialized("hash algorithm".to_string())),
            Some(RmiHashAlgorithm::RmiHashSha256) => "sha-256",
            Some(RmiHashAlgorithm::RmiHashSha512) => "sha-512",
        };

        fn encode_rm(algo: &str, rm: RmmRealmMeasurement) -> String {
            algo.to_owned() + ";" + &base64_standard.encode(rm)
        }

        let m = &mut endorsements.triples.reference_values[0].measurement.value;
        m.raw_value.vtype = "bytes".to_string();
        m.raw_value.value = self.personalization_value.as_base64();
        m.integrity_registers.rim.key_type = "text".to_string();
        m.integrity_registers.rem0.key_type = "text".to_string();
        m.integrity_registers.rem1.key_type = "text".to_string();
        m.integrity_registers.rem2.key_type = "text".to_string();
        m.integrity_registers.rem3.key_type = "text".to_string();
        m.integrity_registers.rim.value =
            vec![encode_rm(hash_algo, realm.measurements.rim)];
        m.integrity_registers.rem0.value =
            vec![encode_rm(hash_algo, realm.measurements.rem[0])];
        m.integrity_registers.rem1.value =
            vec![encode_rm(hash_algo, realm.measurements.rem[1])];
        m.integrity_registers.rem2.value =
            vec![encode_rm(hash_algo, realm.measurements.rem[2])];
        m.integrity_registers.rem3.value =
            vec![encode_rm(hash_algo, realm.measurements.rem[3])];

        let json_output = serde_json::to_string_pretty(&endorsements).map_err(|e| {
            RealmError::Config(format!("cannot encode endorsements: {e}"))
        })?;
        if let Some(filename) = &self.endorsements_output {
            let mut file = File::create(filename).map_err(|e| RealmError::File {
                filename: filename.to_string(),
                e,
            })?;
            write!(file, "{}", json_output).map_err(|e| RealmError::File {
                filename: filename.to_string(),
                e,
            })?;
        }
        Ok(())
    }

    /// Compute Realm Initial Measurement (RIM) and Realm Extensible
    /// Measurements (REM) of the VM. Display or export them.
    pub fn compute_token(&mut self) -> Result<()> {
        let mut realm = self.compute_rim()?;

        for (index, blob) in &mut self.rem_blobs {
            let content = blob.read()?;
            let hash = realm.measure_bytes(content)?;
            realm.rem_extend(*index, &hash)?;
        }

        if self.endorsements_output.is_none() {
            println!(
                "RIM: {}",
                realm.dump_measurement(&realm.measurements.rim, self.print_b64)
            );
            for i in 0..4 {
                println!(
                    "REM{i}: {}",
                    realm.dump_measurement(&realm.measurements.rem[i], self.print_b64)
                );
            }
        } else {
            self.publish_endorsements(&realm)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rim() {
        let mut config = RealmConfig::default();
        // Uninitialized realm
        assert!(config.compute_rim().is_err());

        assert!(config.params.set_ipa_bits(48).is_ok());
        assert!(config.params.set_num_wps(2).is_ok());
        assert!(config.params.set_num_bps(2).is_ok());
        assert!(config.params.set_sve_vl(0).is_ok());
        assert!(config.params.set_pmu_num_ctrs(0).is_ok());
        // Uninitialized hash algo
        assert!(config.compute_rim().is_err());

        config.params.hash_algo = Some(RmiHashAlgorithm::RmiHashSha256);
        let realm = config.compute_rim().unwrap();
        // Recompute hashes with println!("{h:?}"); and cargo test -- --nocapture
        assert_eq!(
            realm.measurements.rim,
            [
                103, 57, 223, 178, 43, 117, 238, 18, 104, 208, 141, 250, 131, 105, 245,
                1, 188, 11, 6, 98, 67, 85, 63, 6, 159, 86, 13, 31, 161, 23, 41, 115, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0
            ]
        );

        config.params.hash_algo = Some(RmiHashAlgorithm::RmiHashSha512);
        let realm = config.compute_rim().unwrap();
        assert_eq!(
            realm.measurements.rim,
            [
                121, 158, 67, 64, 72, 251, 87, 235, 157, 79, 14, 42, 43, 152, 21, 135,
                32, 55, 114, 82, 222, 171, 43, 223, 205, 105, 181, 168, 248, 34, 55, 244,
                52, 189, 107, 177, 199, 91, 241, 96, 162, 212, 147, 130, 247, 51, 179,
                67, 154, 63, 247, 105, 228, 234, 93, 217, 166, 247, 34, 57, 212, 75, 187,
                171
            ]
        );
    }
}
