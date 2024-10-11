use log;
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use openssl::sha;

use crate::command_line::Args;
use crate::realm_params::RealmParams;
use crate::utils::*;
use crate::vmm::{BlobStorage, GuestAddress, VmmBlob};
use rmm::{self, RmiHashAlgorithm, RmmRealmMeasurement, RMM_GRANULE};

use crate::realm_comid::RealmEndorsementsComid;

pub struct PersonalizationValue([u8; 64]);

impl Default for PersonalizationValue {
    fn default() -> Self {
        Self([0; 64])
    }
}

impl PersonalizationValue {
    /// Import a hex string, with no prefix. Stored in the same order,
    /// zero-padded on the right.
    pub fn parse(&mut self, rpv_str: &str) -> Result<()> {
        if rpv_str.len() > 2 * 64 {
            bail!("invalid RPV len");
        }

        let rpv_chars: Vec<char> = rpv_str.chars().collect();
        let mut rpv_iter = rpv_chars.rchunks(2).rev();
        for i in 0..64 {
            self.0[i] = match rpv_iter.next() {
                Some(s) => {
                    // u8::from_str_radix() accepts '+', we don't.
                    for &c in s {
                        if c == '+' {
                            bail!("invalid RPV");
                        }
                    }
                    u8::from_str_radix(&String::from_iter(s), 16)?
                }
                None => 0,
            }
        }
        Ok(())
    }

    /// Import raw bytes
    pub fn copy(&mut self, rpv_str: &str) -> Result<()> {
        if rpv_str.len() > self.0.len() {
            bail!("invalid RPV len");
        }

        let mut rpv_chars = rpv_str.chars();
        for i in 0..64 {
            self.0[i] = match rpv_chars.next() {
                Some(c) => c as u8,
                None => 0,
            }
        }
        Ok(())
    }

    pub fn as_base64(&self) -> String {
        base64_standard.encode(self.0)
    }
}

#[derive(Debug)]
pub struct Measurements {
    pub rim: RmmRealmMeasurement,
    pub rem: [RmmRealmMeasurement; 4],
}

impl Default for Measurements {
    fn default() -> Self {
        Self {
            rim: [0; 64],
            rem: [[0; 64], [0; 64], [0; 64], [0; 64]],
        }
    }
}

#[derive(Default)]
pub struct Realm {
    pub hash_algo: Option<RmiHashAlgorithm>,
    // The RIPAS calls depend on the mapping block sizes, which depend on
    // the number of translation table levels.
    block_sizes: u64,
    pub measurements: Measurements,
}

impl Realm {
    fn dump_measurement(&self, m: &RmmRealmMeasurement, print_b64: bool) -> String {
        if print_b64 {
            base64_standard.encode(m)
        } else {
            // Dump big-endian hex
            buf_to_hex_str(m).to_string()
        }
    }

    fn debug_rim(&self) {
        log::debug!(
            "RIM: {}",
            self.dump_measurement(&self.measurements.rim, false)
        );
    }

    fn measure_bytes(&self, data: &[u8]) -> Result<RmmRealmMeasurement> {
        match self.hash_algo {
            None => bail!("hash algorithm is not known"),
            Some(RmiHashAlgorithm::RmiHashSha256) => {
                let h = sha::sha256(data);
                let mut measurement = [0; rmm::RMM_REALM_MEASUREMENT_SIZE];
                measurement[..32].copy_from_slice(&h);
                Ok(measurement)
            }
            Some(RmiHashAlgorithm::RmiHashSha512) => Ok(sha::sha512(data)),
        }
    }

    ///
    /// Initialize the Realm state. Corresponds to RMI_REALM_CREATE
    ///
    pub fn rim_init(
        &mut self,
        params: &RealmParams,
        hash_algo: &RmiHashAlgorithm,
    ) -> Result<()> {
        let mut flags = 0;
        let mut sve_vl = 0;
        let hash_algo = hash_algo.clone();

        log::debug!("Measuring {:#?}", params);

        if self.measurements.rim != [0; 64] {
            log::warn!("reinitializing RIM");
        }

        let Some(s2sz) = params.ipa_bits else {
            bail!("parameter ipa_bits is not known");
        };
        let Some(num_wps) = params.num_wps else {
            bail!("parameter num_wps is not known");
        };
        let Some(num_bps) = params.num_bps else {
            bail!("parameter num_bps is not known");
        };
        let Some(pmu_num_ctrs) = params.pmu_num_ctrs else {
            bail!("parameter pmu_num_ctrs is not known");
        };

        if let Some(v) = params.sve_vl {
            if v > 0 {
                flags |= rmm::RMI_REALM_F_SVE;
                sve_vl = sve_vl_to_vq(v);
            }
        }
        if params.lpa2.is_some() && params.lpa2.unwrap() {
            flags |= rmm::RMI_REALM_F_LPA2;
        }
        if params.pmu.is_some() && params.pmu.unwrap() {
            flags |= rmm::RMI_REALM_F_PMU;
        }
        assert!(num_bps > 1 && num_wps > 1);
        let params = rmm::RmiRealmParams::new(
            flags,
            s2sz,
            num_wps - 1,
            num_bps - 1,
            pmu_num_ctrs,
            sve_vl,
            hash_algo,
        );

        self.hash_algo = Some(hash_algo);

        // Since we know the IPA size, we can initialize the block size.
        self.block_sizes = translation_block_sizes(s2sz);

        let bytes = params.as_bytes()?;
        self.measurements.rim = self.measure_bytes(&bytes)?;
        self.debug_rim();

        Ok(())
    }

    ///
    /// Measure one blob, add it to the RIM. Corresponds to one or more calls to
    /// RMI_DATA_CREATE: one for each granule in the blob.
    ///
    pub fn rim_add_data(&mut self, addr: u64, blob: &VmmBlob) -> Result<u64> {
        const GRANULE: usize = RMM_GRANULE as usize;
        let mut data_size;
        let mut content;
        match &blob.data {
            BlobStorage::File(f) => {
                // TODO: optimize this, because some of those files
                // could be several GBs. memmap is an option, though we need
                // to resize it below in order to measure at page granule.
                let mut f = f;
                content = vec![];
                data_size = f
                    .read_to_end(&mut content)
                    .with_context(|| blob.filename.as_ref().unwrap().to_string())?;
            }
            BlobStorage::Bytes(b) => {
                data_size = b.len();
                content = b.to_vec();
            }
        };

        // Align to granule size
        let aligned_addr = align_down(addr, GRANULE as u64);
        let fill_size = (addr - aligned_addr) as usize;
        data_size += fill_size;
        content.resize(data_size, 0);
        content.rotate_right(fill_size);

        // Fill up to granule size
        data_size = align_up(data_size as u64, GRANULE as u64) as usize;
        content.resize(data_size, 0);

        log::debug!(
            "Measuring data 0x{:x} - 0x{:x}",
            aligned_addr,
            aligned_addr + content.len() as u64 - 1
        );

        // Measure each page
        for off in (0..content.len()).step_by(GRANULE) {
            let page: &[u8; GRANULE] = &content[off..off + GRANULE]
                .try_into()
                .expect("aligned data");

            let content_hash = self.measure_bytes(page)?;

            let measurement_desc = rmm::RmmMeasurementDescriptorData::new(
                &self.measurements.rim,
                aligned_addr + off as u64,
                rmm::RMM_DATA_F_MEASURE, // flags
                &content_hash,
            );
            let bytes = measurement_desc.as_bytes()?;
            self.measurements.rim = self.measure_bytes(&bytes)?;
        }

        self.debug_rim();
        Ok(data_size as u64)
    }

    ///
    /// Measure one RIPAS range, add it to the RIM. This corresponds to multiple
    /// calls to RMI_RTT_INIT_RIPAS: for one IPA range submitted by the VMM, RMM
    /// performs a measurement for each RTT entry in the range.
    ///
    fn rim_add_ripas(&mut self, base: u64, top: u64) -> Result<()> {
        if top <= base || !is_aligned(top | base, RMM_GRANULE) {
            bail!("invalid RIPAS parameters");
        }

        if self.block_sizes == 0 {
            // Need to call rim_init() first!
            bail!("block sizes are not known");
        }

        log::debug!("Measuring RIPAS 0x{:x} - 0x{:x}", base, top - 1);

        let mut cur = base;
        while cur < top {
            // Find the largest block size that fits this range
            let block_size = find_block_size(cur, top, self.block_sizes);
            assert!(block_size >= RMM_GRANULE && is_aligned(block_size, RMM_GRANULE));
            let measurement_desc = rmm::RmmMeasurementDescriptorRipas::new(
                &self.measurements.rim,
                cur,
                cur + block_size,
            );
            let bytes = measurement_desc.as_bytes()?;
            self.measurements.rim = self.measure_bytes(&bytes)?;

            cur += block_size;
        }

        self.debug_rim();
        Ok(())
    }

    ///
    /// Measure one REC structure, add it to the RIM. This corresponds to a call
    /// to RMI_REC_CREATE.
    ///
    pub fn rim_add_rec(&mut self, rec: &rmm::RmiRecParams) -> Result<()> {
        let bytes = rec.as_bytes()?;
        let content_hash = self.measure_bytes(&bytes)?;

        log::debug!("Measuring REC");

        let measurement_desc =
            rmm::RmmMeasurementDescriptorRec::new(&self.measurements.rim, &content_hash);
        let bytes = measurement_desc.as_bytes()?;
        self.measurements.rim = self.measure_bytes(&bytes)?;

        self.debug_rim();
        Ok(())
    }
}

// Compute the supported block size in the translation table, as a bitmask
fn translation_block_sizes(ipa_bits: u8) -> u64 {
    let page_bits = RMM_GRANULE.ilog2() as u8;
    let table_bits = ipa_bits - page_bits;
    let bits_per_level = page_bits - 3;

    let mut num_levels = table_bits.div_ceil(bits_per_level);
    // The hypervisor uses concatenated tables when the initial lookup level
    // contains 16 or fewer entries
    if table_bits - bits_per_level * (num_levels - 1) <= 4 {
        num_levels -= 1;
    }
    // With 49-52 IPA bits, the initial table is always concatenated so we never
    // use level -1.
    assert!(num_levels <= 4);
    let start_level = 4 - num_levels;
    let mut block_sizes = 0;
    for l in start_level..4 {
        let block_size = RMM_GRANULE << (bits_per_level * (3 - l));
        block_sizes |= block_size;
    }

    block_sizes
}

// Find the largest block size that can map the beginning of this range
// For example @sizes is 0x40201000, meaning available block sizes are 1GB, 2MB
// and 4kB. With @start = 0x400000 and @top = 0x800000, return 0x200000. With
// @start = 0x400000 and @top = 0x500000, return 0x1000.
fn find_block_size(start: u64, top: u64, sizes: u64) -> u64 {
    assert!(start < top);
    assert!(is_aligned(start | top | sizes, RMM_GRANULE));
    let mut sizes = sizes;
    if start != 0 {
        assert!(start < 1u64 << 63);
        // start must be aligned on the block size
        sizes &= (1u64 << (start.trailing_zeros() + 1)) - 1;
    }

    let mut block_size;
    loop {
        assert!(sizes != 0);
        block_size = 1u64 << (63 - sizes.leading_zeros());

        if (top - start) >= block_size {
            break;
        }
        assert!((sizes & block_size) != 0);
        sizes &= !block_size;
    }

    block_size
}

#[derive(Default)]
pub struct RealmConfig {
    // Use a btree so that blobs are sorted
    pub rim_blobs: BTreeMap<GuestAddress, VmmBlob>,
    pub rem_blobs: Vec<VmmBlob>,
    pub ram_ranges: BTreeMap<GuestAddress, u64>,
    pub rec: Option<rmm::RmiRecParams>,
    pub hash_algo: Option<RmiHashAlgorithm>,
    pub personalization_value: PersonalizationValue,
    pub print_b64: bool,

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
            config
                .load_config(filename)
                .with_context(|| filename.to_string())?;
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
        let content =
            fs::read_to_string(filename).with_context(|| filename.to_string())?;
        let caps: RealmParams = toml::from_str(&content)?;

        // Capabilities that are already set by a previous config file can only
        // be lowered.
        self.params.restrict(&caps)?;

        Ok(())
    }

    pub fn set_measurement_algo(&mut self, s: &str) -> Result<()> {
        self.hash_algo = Some(match s {
            "sha256" => RmiHashAlgorithm::RmiHashSha256,
            "sha512" => RmiHashAlgorithm::RmiHashSha512,
            _ => bail!("unsupported hash algorithm '{s}'"),
        });
        Ok(())
    }

    /// Add a range of RAM
    pub fn add_ram(&mut self, base: GuestAddress, size: u64) -> Result<()> {
        if self.ram_ranges.insert(base, size).is_some() {
            bail!("duplicate RAM range at {base}");
        }
        Ok(())
    }

    /// Add binary file to be measured as part of the Realm Initial Measurement.
    /// The VMM loads it into guest memory before boot.
    ///
    pub fn add_rim_blob(&mut self, blob: VmmBlob) -> Result<()> {
        let address = blob.guest_start;
        if self.rim_blobs.insert(address, blob).is_some() {
            bail!("duplicate blob at {address}");
        }
        Ok(())
    }

    /// Add binary file to be measured as part of the Realm Extended
    /// Measurement.
    ///
    pub fn add_rem_blob(&mut self, blob: VmmBlob) -> Result<()> {
        // TODO: Define an order for the REM
        self.rem_blobs.push(blob);
        Ok(())
    }

    /// Add primary RECs, with the given PC and parameters. The other RECs are
    /// not runnable and thus not measured.
    pub fn add_rec(&mut self, pc: u64, gprs: [u64; 8]) -> Result<()> {
        if self.rec.is_some() {
            bail!("only one REC is supported");
        }

        self.rec = Some(rmm::RmiRecParams::new(
            rmm::RMI_REC_CREATE_F_RUNNABLE,
            pc,
            gprs,
        ));
        Ok(())
    }

    fn compute_rim(&self) -> Result<Realm> {
        let mut realm = Realm::default();

        let Some(hash_algo) = self.hash_algo else {
            bail!("hash algorithm is not known");
        };

        realm.rim_init(&self.params, &hash_algo)?;

        // The order is: first init RIPAS of the whole guest RAM, then data
        // granules in ascending order, then the RECs.

        for (addr, size) in &self.ram_ranges {
            let base = align_down(*addr, RMM_GRANULE);
            let end = align_up(base + *size - 1, RMM_GRANULE);
            realm.rim_add_ripas(base, end)?;
        }

        for (addr, blob) in &self.rim_blobs {
            realm.rim_add_data(*addr, &blob)?;
        }

        if let Some(rec) = &self.rec {
            realm.rim_add_rec(rec)?;
        } else {
            log::debug!("Missing REC");
        }

        Ok(realm)
    }

    /// Create a JSON file containing realm endorsements in the CoMID format
    fn publish_endorsements(&self, realm: &Realm) -> Result<()> {
        let mut endorsements: RealmEndorsementsComid =
            if let Some(filename) = &self.endorsements_template {
                let content =
                    fs::read_to_string(filename).with_context(|| filename.to_string())?;
                serde_json::from_str(&content).with_context(|| filename.to_string())?
            } else {
                RealmEndorsementsComid::new()
            };

        endorsements.init_refval();

        let hash_algo = match self.hash_algo {
            None => bail!("hash algorithm is not known"),
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

        let json_output = serde_json::to_string_pretty(&endorsements)?;
        if let Some(filename) = &self.endorsements_output {
            let mut file =
                File::create(filename).with_context(|| filename.to_string())?;
            write!(file, "{}", json_output)?;
        }
        Ok(())
    }

    /// Compute Realm Initial Measurement (RIM) and Realm Extended Measurements
    /// (REM) of the VM. Display or export them.
    pub fn compute_token(&self) -> Result<()> {
        let realm = self.compute_rim()?;

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

        config.hash_algo = Some(RmiHashAlgorithm::RmiHashSha256);
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

        config.hash_algo = Some(RmiHashAlgorithm::RmiHashSha512);
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

    #[test]
    fn test_rpv() -> Result<()> {
        let mut rpv = PersonalizationValue::default();
        assert_eq!(
            rpv.0,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        let s = "1";
        rpv.parse(s)?;
        assert_eq!(
            rpv.0,
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        let s = "abc";
        rpv.parse(s)?;
        assert_eq!(
            rpv.0,
            [
                0xa, 0xbc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        let s = "";
        rpv.parse(s)?;
        assert_eq!(
            rpv.0,
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        let s = "0201010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010A";
        rpv.parse(s)?;
        assert_eq!(
            rpv.0,
            [
                2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0xa
            ]
        );

        let s = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; // 129 chars
        assert!(rpv.parse(s).is_err());

        let s = "hello";
        assert!(rpv.parse(s).is_err());

        let s = "0x00";
        assert!(rpv.parse(s).is_err());

        let s = "+2";
        assert!(rpv.parse(s).is_err());

        Ok(())
    }

    #[test]
    fn test_block_sizes() {
        assert_eq!(translation_block_sizes(52), 0x8040201000);
        assert_eq!(translation_block_sizes(49), 0x8040201000);
        assert_eq!(translation_block_sizes(48), 0x8040201000);
        assert_eq!(translation_block_sizes(44), 0x8040201000);
        assert_eq!(translation_block_sizes(43), 0x0040201000); // concat
        assert_eq!(translation_block_sizes(40), 0x0040201000); // concat
        assert_eq!(translation_block_sizes(39), 0x0040201000);
        assert_eq!(translation_block_sizes(35), 0x0040201000);
        assert_eq!(translation_block_sizes(34), 0x0000201000); // concat
        assert_eq!(translation_block_sizes(31), 0x0000201000); // concat
        assert_eq!(translation_block_sizes(30), 0x0000201000);
        assert_eq!(translation_block_sizes(26), 0x0000201000);
        assert_eq!(translation_block_sizes(25), 0x0000001000); // concat
        assert_eq!(translation_block_sizes(21), 0x0000001000); // concat
        assert_eq!(translation_block_sizes(20), 0x0000001000);

        assert_eq!(find_block_size(0, 0x1000, 0x40201000), 0x1000);
        assert_eq!(find_block_size(0x1000, 0x2000, 0x1000), 0x1000);
        assert_eq!(find_block_size(0, 0x40000000, 0x40201000), 0x40000000);
        assert_eq!(
            find_block_size(0x40000000, 0x80000000, 0x40201000),
            0x40000000
        );
        assert_eq!(find_block_size(0x40000000, 0x80000000, 0x201000), 0x200000);
        assert_eq!(
            find_block_size(0x1_00000000, 0x1_40000000, 0x40201000),
            0x40000000
        );
        assert_eq!(
            find_block_size(0x10_00000000, 0x11_00000000, 0x40201000),
            0x40000000
        );
        assert_eq!(
            find_block_size(0x80000000, 0x80200000, 0x40201000),
            0x200000
        );
        assert_eq!(find_block_size(0x80001000, 0x80200000, 0x40201000), 0x1000);
        assert_eq!(find_block_size(0x6200000, 0x70000000, 0x40201000), 0x200000);
        assert_eq!(find_block_size(0x6300000, 0x70000000, 0x40201000), 0x1000);
        assert_eq!(find_block_size(0x6400000, 0x70000000, 0x40201000), 0x200000);
        assert_eq!(find_block_size(0x400000, 0x800000, 0x40201000), 0x200000);
        assert_eq!(find_block_size(0x400000, 0x500000, 0x40201000), 0x1000);
    }
}
