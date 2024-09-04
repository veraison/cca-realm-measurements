use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use openssl::sha;

use crate::command_line::{Args, RealmParams};
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

#[derive(Default)]
pub struct Realm {
    // Use a btree so that blobs are sorted
    pub rim_blobs: BTreeMap<GuestAddress, VmmBlob>,
    pub rem_blobs: Vec<VmmBlob>,
    pub rec: Option<rmm::RmiRecParams>,
    pub hash_algo: Option<RmiHashAlgorithm>,
    pub personalization_value: PersonalizationValue,
    pub verbose: bool,

    pub params: RealmParams,

    endorsements_template: Option<String>,
    endorsements_output: Option<String>,
}

fn check_ipa_bits(v: u8) -> Result<u8> {
    Ok(v)
}

fn check_num_bps(v: u8) -> Result<u8> {
    if v < 2 || v > 64 {
        bail!("invalid number of breakpoints");
    }
    Ok(v)
}

fn check_num_wps(v: u8) -> Result<u8> {
    if v < 2 || v > 64 {
        bail!("invalid number of watchpoints");
    }
    Ok(v)
}

fn check_pmu_ctrs(v: u8) -> Result<u8> {
    if v > 31 {
        bail!("invalid number of PMU counters");
    }
    Ok(v)
}

fn check_sve_vl(v: u16) -> Result<u16> {
    if v != 0 && !sve_vl_is_valid(v) {
        bail!("invalid vector length");
    }
    Ok(v)
}

// Update @old in place if @new is lower than @old, or if @old was None
fn restrict_val<T: Copy + std::cmp::PartialOrd>(old: &mut Option<T>, new: T) {
    let old_val = old.unwrap_or(new);
    if new <= old_val {
        *old = Some(new);
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

impl Realm {
    /// Create a Realm object from command-line arguments, checking their
    /// validity
    pub fn from_args(args: &Args) -> Result<Realm> {
        let mut realm = Realm {
            ..Default::default()
        };

        for filename in &args.config {
            realm
                .load_config(filename)
                .with_context(|| filename.to_string())?;
        }

        // Override config
        if let Some(v) = args.host.ipa_bits {
            realm.set_ipa_bits(v)?;
        }
        if let Some(v) = args.host.num_bps {
            realm.set_num_bps(v)?;
        }
        if let Some(v) = args.host.num_wps {
            realm.set_num_wps(v)?;
        }
        if let Some(v) = args.host.pmu_num_ctrs {
            realm.set_pmu_num_ctrs(v)?;
        }
        if let Some(v) = args.host.sve_vl {
            realm.set_sve_vl(v)?;
        }
        if let Some(v) = args.host.pmu {
            realm.set_pmu(v);
        }
        if let Some(v) = args.host.lpa2 {
            realm.set_lpa2(v);
        }

        realm.verbose = args.verbose;
        if args.verbose {
            eprintln!("Host config: {:?}", realm.params);
        }

        realm
            .endorsements_template
            .clone_from(&args.endorsements_template);
        realm
            .endorsements_output
            .clone_from(&args.endorsements_output);

        Ok(realm)
    }

    fn load_config(&mut self, filename: &str) -> Result<()> {
        let content =
            fs::read_to_string(filename).with_context(|| filename.to_string())?;
        let caps: RealmParams = toml::from_str(&content)?;

        // Capabilities that are already set by a previous config file can only
        // be lowered.

        if let Some(v) = caps.ipa_bits {
            self.restrict_ipa_bits(v)?;
        }
        if let Some(v) = caps.num_bps {
            self.restrict_num_bps(v)?;
        }
        if let Some(v) = caps.num_wps {
            self.restrict_num_wps(v)?;
        }
        if let Some(v) = caps.pmu_num_ctrs {
            self.restrict_pmu_num_ctrs(v)?;
        }
        if let Some(v) = caps.sve_vl {
            self.restrict_sve_vl(v)?;
        }
        if let Some(v) = caps.pmu {
            self.restrict_pmu(v);
        }
        if let Some(v) = caps.lpa2 {
            self.restrict_lpa2(v);
        }

        Ok(())
    }

    pub fn set_ipa_bits(&mut self, v: u8) -> Result<()> {
        self.params.ipa_bits = Some(check_ipa_bits(v)?);
        Ok(())
    }

    pub fn restrict_ipa_bits(&mut self, v: u8) -> Result<()> {
        restrict_val(&mut self.params.ipa_bits, check_ipa_bits(v)?);
        Ok(())
    }

    pub fn set_num_bps(&mut self, v: u8) -> Result<()> {
        self.params.num_bps = Some(check_num_bps(v)?);
        Ok(())
    }

    pub fn restrict_num_bps(&mut self, v: u8) -> Result<()> {
        restrict_val(&mut self.params.num_bps, check_num_bps(v)?);
        Ok(())
    }

    pub fn set_num_wps(&mut self, v: u8) -> Result<()> {
        self.params.num_wps = Some(check_num_wps(v)?);
        Ok(())
    }

    pub fn restrict_num_wps(&mut self, v: u8) -> Result<()> {
        restrict_val(&mut self.params.num_wps, check_num_wps(v)?);
        Ok(())
    }

    pub fn set_pmu(&mut self, pmu: bool) {
        self.params.pmu = Some(pmu);
    }

    pub fn restrict_pmu(&mut self, pmu: bool) {
        restrict_val(&mut self.params.pmu, pmu);
    }

    pub fn set_pmu_num_ctrs(&mut self, num_ctrs: u8) -> Result<()> {
        self.params.pmu_num_ctrs = Some(check_pmu_ctrs(num_ctrs)?);
        Ok(())
    }

    pub fn restrict_pmu_num_ctrs(&mut self, v: u8) -> Result<()> {
        restrict_val(&mut self.params.pmu_num_ctrs, check_pmu_ctrs(v)?);
        Ok(())
    }

    /// Set SVE vector length in bits.
    pub fn set_sve_vl(&mut self, v: u16) -> Result<()> {
        self.params.sve_vl = Some(check_sve_vl(v)?);
        Ok(())
    }

    /// Set SVE vector length in bits, but not if the current value is lower.
    pub fn restrict_sve_vl(&mut self, v: u16) -> Result<()> {
        restrict_val(&mut self.params.sve_vl, check_sve_vl(v)?);
        Ok(())
    }

    pub fn set_lpa2(&mut self, lpa2: bool) {
        self.params.lpa2 = Some(lpa2);
    }

    pub fn restrict_lpa2(&mut self, lpa2: bool) {
        restrict_val(&mut self.params.lpa2, lpa2);
    }

    pub fn set_measurement_algo(&mut self, s: &str) -> Result<()> {
        self.hash_algo = Some(match s {
            "sha256" => RmiHashAlgorithm::RmiHashSha256,
            "sha512" => RmiHashAlgorithm::RmiHashSha512,
            _ => bail!("unsupported hash algorithm '{s}'"),
        });
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

    fn dump_measurement(&self, prefix: &str, m: &RmmRealmMeasurement) {
        // Dump big-endian hex
        let s = m.map(|b| format!("{b:02x}")).join("");
        println!("{prefix}: {s}");
    }

    fn rim_init(&self) -> Result<RmmRealmMeasurement> {
        let mut flags = 0;
        let mut sve_vl = 0;

        if self.verbose {
            eprintln!("Measuring {:#?}", self.params);
        }

        let Some(s2sz) = self.params.ipa_bits else {
            bail!("parameter ipa_bits is not known");
        };
        let Some(num_wps) = self.params.num_wps else {
            bail!("parameter num_wps is not known");
        };
        let Some(num_bps) = self.params.num_bps else {
            bail!("parameter num_bps is not known");
        };
        let Some(pmu_num_ctrs) = self.params.pmu_num_ctrs else {
            bail!("parameter pmu_num_ctrs is not known");
        };
        let Some(hash_algo) = self.hash_algo else {
            bail!("hash algorithm is not known");
        };

        if let Some(v) = self.params.sve_vl {
            if v > 0 {
                flags |= rmm::RMI_REALM_F_SVE;
                sve_vl = sve_vl_to_vq(v);
            }
        }
        if self.params.lpa2.is_some() && self.params.lpa2.unwrap() {
            flags |= rmm::RMI_REALM_F_LPA2;
        }
        if self.params.pmu.is_some() && self.params.pmu.unwrap() {
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

        let bytes = params.as_bytes()?;
        self.measure_bytes(&bytes)
    }

    // Measure one blob, add it to the RIM
    fn rim_add_data(
        &self,
        addr: u64,
        blob: &VmmBlob,
        rim: &mut RmmRealmMeasurement,
    ) -> Result<u64> {
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

        if self.verbose {
            let last = aligned_addr + content.len() as u64 - 1;
            eprintln!("Measuring data 0x{:x} - 0x{:x}", aligned_addr, last);
        }

        // Measure each page
        for off in (0..content.len()).step_by(GRANULE) {
            let page: &[u8; GRANULE] = &content[off..off + GRANULE]
                .try_into()
                .expect("aligned data");

            let content_hash = self.measure_bytes(page)?;

            let measurement_desc = rmm::RmmMeasurementDescriptorData::new(
                rim,
                aligned_addr + off as u64,
                rmm::RMM_DATA_F_MEASURE, // flags
                &content_hash,
            );
            let bytes = measurement_desc.as_bytes()?;
            *rim = self.measure_bytes(&bytes)?;
        }

        if self.verbose {
            self.dump_measurement("RIM", rim);
        }

        Ok(data_size as u64)
    }

    // Measure one RIPAS range, add it to the RIM. For one IPA range submitted
    // by the VMM, RMM performs a measurement for each RTT entry in the range.
    fn rim_add_ripas(
        &self,
        base: u64,
        top: u64,
        block_sizes: u64,
        rim: &mut RmmRealmMeasurement,
    ) -> Result<()> {
        assert!(top > base);
        assert!(is_aligned(top | base, RMM_GRANULE));

        if self.verbose {
            eprintln!("Measuring RIPAS 0x{:x} - 0x{:x}", base, top - 1);
        }

        let mut cur = base;
        while cur < top {
            // Find the largest block size that fits this range
            let block_size = find_block_size(cur, top, block_sizes);
            assert!(block_size >= RMM_GRANULE && is_aligned(block_size, RMM_GRANULE));
            let measurement_desc =
                rmm::RmmMeasurementDescriptorRipas::new(rim, cur, cur + block_size);
            let bytes = measurement_desc.as_bytes()?;
            *rim = self.measure_bytes(&bytes)?;

            cur += block_size;
        }

        if self.verbose {
            self.dump_measurement("RIM", rim);
        }

        Ok(())
    }

    fn rim_add_rec(
        &self,
        rec: &rmm::RmiRecParams,
        rim: &mut RmmRealmMeasurement,
    ) -> Result<()> {
        let bytes = rec.as_bytes()?;
        let content_hash = self.measure_bytes(&bytes)?;

        if self.verbose {
            eprintln!("Measuring REC");
        }

        let measurement_desc = rmm::RmmMeasurementDescriptorRec::new(rim, &content_hash);
        let bytes = measurement_desc.as_bytes()?;
        *rim = self.measure_bytes(&bytes)?;

        Ok(())
    }

    fn compute_rim(&mut self) -> Result<RmmRealmMeasurement> {
        let Some(ipa_bits) = self.params.ipa_bits else {
            bail!("IPA size is not known");
        };
        // The RIPAS calls depend on the mapping block sizes, which depend on
        // the number of translation table levels.
        let block_sizes = translation_block_sizes(ipa_bits);

        let mut rim = self.rim_init()?;

        if self.verbose {
            self.dump_measurement("RIM", &rim);
        }

        // The order is: first the guest RAM in ascending order, including both
        // DATA and RIPAS initialization, then the RECs.
        for (addr, blob) in &self.rim_blobs {
            let data_size = self.rim_add_data(*addr, blob, &mut rim)?;
            assert!(is_aligned(data_size, RMM_GRANULE));

            // Add measurement for IPAs that are allocated but don't contain
            // data, for example kernel BSS
            let Some(load_size) = blob.load_size else {
                continue;
            };
            if load_size <= data_size {
                continue;
            }

            let base = *addr + data_size;
            let top = align_up(*addr + load_size, RMM_GRANULE);
            self.rim_add_ripas(base, top, block_sizes, &mut rim)?;
        }

        if let Some(rec) = &self.rec {
            self.rim_add_rec(rec, &mut rim)?;
        } else {
            eprintln!("Missing REC");
        }

        Ok(rim)
    }

    pub fn compute_rem(&self, n: usize) -> Result<RmmRealmMeasurement> {
        assert!(n < 4);
        // TODO: we know what goes there, but in which order and into which REM?
        // That will likely come with a TPM log telling us in which order to
        // measure the REM blobs.
        Ok([0; 64])
    }

    /// Create a JSON file containing realm endorsements in the CoMID format
    fn publish_endorsements(
        &mut self,
        rim: RmmRealmMeasurement,
        rems: Vec<RmmRealmMeasurement>,
    ) -> Result<()> {
        if self.endorsements_output.is_none() {
            return Ok(());
        }

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
        m.integrity_registers.rim.value = vec![encode_rm(hash_algo, rim)];
        m.integrity_registers.rem0.value = vec![encode_rm(hash_algo, rems[0])];
        m.integrity_registers.rem1.value = vec![encode_rm(hash_algo, rems[1])];
        m.integrity_registers.rem2.value = vec![encode_rm(hash_algo, rems[2])];
        m.integrity_registers.rem3.value = vec![encode_rm(hash_algo, rems[3])];

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
    pub fn compute_token(&mut self) -> Result<()> {
        let rim = self.compute_rim()?;

        if self.endorsements_output.is_none() || self.verbose {
            self.dump_measurement("RIM", &rim);
        }

        let mut rems = vec![];
        for i in 0..4 {
            let rem = self.compute_rem(i)?;
            rems.push(rem);

            if self.endorsements_output.is_none() || self.verbose {
                self.dump_measurement(&format!("REM{i}"), &rem);
            }
        }

        self.publish_endorsements(rim, rems)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Realm has some setters that check input values. Test them.
    fn test_args() {
        let mut realm = Realm {
            ..Default::default()
        };

        assert!(realm.set_sve_vl(272).is_err());
        assert!(realm.set_sve_vl(4096).is_err());
        assert!(realm.params.sve_vl.is_none());
        assert!(realm.set_sve_vl(128).is_ok());
        assert_eq!(realm.params.sve_vl, Some(128));
        assert_eq!(sve_vl_to_vq(128), 0);
        assert!(realm.set_sve_vl(2048).is_ok());
        assert_eq!(realm.params.sve_vl, Some(2048));
        assert_eq!(sve_vl_to_vq(2048), 15);
        assert!(realm.set_sve_vl(0).is_ok());
        assert_eq!(realm.params.sve_vl, Some(0));

        assert!(realm.set_num_bps(1).is_err());
        assert!(realm.set_num_bps(65).is_err());
        assert!(realm.set_num_bps(2).is_ok());
        assert_eq!(realm.params.num_bps, Some(2));
        assert!(realm.set_num_bps(16).is_ok());
        assert_eq!(realm.params.num_bps, Some(16));

        assert!(realm.set_num_wps(1).is_err());
        assert!(realm.set_num_wps(65).is_err());
        assert!(realm.set_num_wps(2).is_ok());
        assert_eq!(realm.params.num_wps, Some(2));
        assert!(realm.set_num_wps(16).is_ok());
        assert_eq!(realm.params.num_wps, Some(16));

        assert_eq!(realm.params.pmu_num_ctrs, None);
        assert!(realm.set_pmu_num_ctrs(32).is_err());
        assert!(realm.set_pmu_num_ctrs(0).is_ok());
        assert_eq!(realm.params.pmu_num_ctrs, Some(0));
        assert!(realm.set_pmu_num_ctrs(31).is_ok());
        assert_eq!(realm.params.pmu_num_ctrs, Some(31));

        assert!(realm.set_ipa_bits(48).is_ok());
        assert_eq!(realm.params.ipa_bits, Some(48));
    }

    #[test]
    fn test_rim() {
        let mut realm = Realm {
            ..Default::default()
        };
        // Uninitialized realm
        assert!(realm.compute_rim().is_err());

        assert!(realm.set_ipa_bits(48).is_ok());
        assert!(realm.set_num_wps(2).is_ok());
        assert!(realm.set_num_bps(2).is_ok());
        assert!(realm.set_sve_vl(0).is_ok());
        assert!(realm.set_pmu_num_ctrs(0).is_ok());
        // Uninitialized hash algo
        assert!(realm.compute_rim().is_err());

        realm.hash_algo = Some(RmiHashAlgorithm::RmiHashSha256);
        let h = realm.compute_rim().unwrap();
        // Recompute hashes with println!("{h:?}"); and cargo test -- --nocapture
        assert_eq!(
            h,
            [
                103, 57, 223, 178, 43, 117, 238, 18, 104, 208, 141, 250, 131, 105, 245,
                1, 188, 11, 6, 98, 67, 85, 63, 6, 159, 86, 13, 31, 161, 23, 41, 115, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0
            ]
        );

        realm.hash_algo = Some(RmiHashAlgorithm::RmiHashSha512);
        let h = realm.compute_rim().unwrap();
        assert_eq!(
            h,
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
