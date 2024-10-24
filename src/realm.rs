///
/// Provides tools to compute Realm Measurements, by performing the same
/// operations as the RMM.
///
use base64::{engine::general_purpose::STANDARD as base64_standard, Engine as _};
use openssl::sha;

use crate::utils::*;
use crate::vmm::{VmmBlob, VmmError};
use rmm::{self, RmiHashAlgorithm, RmmError, RmmRealmMeasurement, RMM_GRANULE};

pub use crate::realm_config::RealmConfig;
pub use crate::realm_params::RealmParams;

#[derive(Debug, thiserror::Error)]
pub enum RealmError {
    #[error("invalid Realm Personalization Value")]
    InvalidRPV,

    #[error("{0} is not known")]
    Uninitialized(String),

    #[error("RMM")]
    Rmm(#[from] RmmError),

    #[error("VMM")]
    Vmm(#[from] VmmError),

    #[error("invalid parameter {0}")]
    Parameter(String),

    #[error("file {filename} error: {e}")]
    File { e: std::io::Error, filename: String },

    #[error("invalid VM configuration: {0}")]
    Config(String),
}
type Result<T> = core::result::Result<T, RealmError>;

///
/// Realm Personalization Value: a 64-byte value representing a specific Realm
/// instance. Multiple instances with the same measurements can optionally be
/// distinguished by a personalization value.
///
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
            return Err(RealmError::InvalidRPV);
        }

        let rpv_chars: Vec<char> = rpv_str.chars().collect();
        let mut rpv_iter = rpv_chars.rchunks(2).rev();
        for i in 0..64 {
            self.0[i] = match rpv_iter.next() {
                Some(s) => {
                    // u8::from_str_radix() accepts '+', we don't.
                    for &c in s {
                        if c == '+' {
                            return Err(RealmError::InvalidRPV);
                        }
                    }
                    u8::from_str_radix(&String::from_iter(s), 16)
                        .map_err(|_| RealmError::InvalidRPV)?
                }
                None => 0,
            }
        }
        Ok(())
    }

    /// Import raw bytes
    pub fn copy(&mut self, rpv_str: &str) -> Result<()> {
        if rpv_str.len() > self.0.len() {
            return Err(RealmError::InvalidRPV);
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

///
/// The Realm measurements: one Realm Initial Measurement representing the
/// initial VM state, and four Realm Extensible Measurements extended at
/// runtime.
///
#[derive(Debug)]
pub struct Measurements {
    pub rim: RmmRealmMeasurement,
    pub rem: [RmmRealmMeasurement; 4],
    /// measurement length: 32 or 64 bytes
    length: usize,
}

impl Measurements {
    /// Return an array of five reference values encoded in base64 strings. The
    /// values are truncated in function of the hash algorithm.
    #[allow(dead_code)]
    pub fn as_base64_array(&self) -> [String; 5] {
        assert!(self.length == 32 || self.length == 64);
        [
            base64_standard.encode(&self.rim[..self.length]),
            base64_standard.encode(&self.rem[0][..self.length]),
            base64_standard.encode(&self.rem[1][..self.length]),
            base64_standard.encode(&self.rem[2][..self.length]),
            base64_standard.encode(&self.rem[3][..self.length]),
        ]
    }
}

impl Default for Measurements {
    fn default() -> Self {
        Self {
            rim: [0; 64],
            rem: [[0; 64], [0; 64], [0; 64], [0; 64]],
            length: 64,
        }
    }
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

// Compute the supported block size in the translation table, as a bitmask.
// This assumes the hypervisor uses concatenated tables at the initial level
// whenever possible, which is an optional feature. It works for KVM but perhaps
// not all hypervisors. TODO: implement different hypervisor behaviors?
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

///
/// Represents the Realm state during and after initialization
///
#[derive(Default)]
pub struct Realm {
    hash_algo: Option<RmiHashAlgorithm>,
    // The RIPAS calls depend on the mapping block sizes, which depend on
    // the number of translation table levels.
    block_sizes: u64,
    pub measurements: Measurements,
}

impl Realm {
    pub fn dump_measurement(&self, m: &RmmRealmMeasurement, print_b64: bool) -> String {
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

    /// Set the hash algorithm used for all measurements.
    pub fn set_hash_algo(&mut self, algo: RmiHashAlgorithm) -> &mut Self {
        self.hash_algo = Some(algo);
        self.measurements.length = match algo {
            RmiHashAlgorithm::RmiHashSha256 => 32,
            RmiHashAlgorithm::RmiHashSha512 => 64,
        };
        self
    }

    /// Compute the hash of the provided buffer, using the Realm hash algorithm
    pub fn measure_bytes(&self, data: &[u8]) -> Result<RmmRealmMeasurement> {
        match self.hash_algo {
            None => Err(RealmError::Uninitialized("hash algorithm".to_string())),
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
    /// Initialize the Realm state. Corresponds to RMI_REALM_CREATE.
    ///
    pub fn rim_realm_create(&mut self, params: &RealmParams) -> Result<()> {
        let mut flags = 0;
        let mut sve_vl = 0;

        log::debug!("Measuring {:#?}", params);

        if self.measurements.rim != [0; 64] {
            log::warn!("reinitializing RIM");
        }

        let Some(hash_algo) = params.hash_algo else {
            return Err(RealmError::Uninitialized("hash algorithm".to_string()));
        };
        let Some(s2sz) = params.ipa_bits else {
            return Err(RealmError::Uninitialized("ipa_bits".to_string()));
        };
        let Some(num_wps) = params.num_wps else {
            return Err(RealmError::Uninitialized("num_wps".to_string()));
        };
        let Some(num_bps) = params.num_bps else {
            return Err(RealmError::Uninitialized("num_bps".to_string()));
        };
        if let Some(v) = params.sve_vl {
            if v > 0 {
                flags |= rmm::RMI_REALM_F_SVE;
                sve_vl = sve_vl_to_vq(v);
            }
        }
        if params.lpa2.unwrap_or(false) {
            flags |= rmm::RMI_REALM_F_LPA2;
        }
        let pmu_num_ctrs = if params.pmu.unwrap_or(false) {
            flags |= rmm::RMI_REALM_F_PMU;
            params
                .pmu_num_ctrs
                .ok_or(RealmError::Uninitialized("pmu_num_ctrs".to_string()))?
        } else {
            0
        };

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

        self.set_hash_algo(hash_algo);

        // Since we know the IPA size, we can initialize the block size.
        self.block_sizes = translation_block_sizes(s2sz);

        let bytes = params.as_bytes()?;
        self.measurements.rim = self.measure_bytes(&bytes)?;
        self.debug_rim();

        Ok(())
    }

    ///
    /// Measure one blob, add it to the RIM. Corresponds to one or more calls to
    /// RMI_DATA_CREATE with the RMI_MEASURE_CONTENT flag set: one for each
    /// granule in the blob.
    ///
    pub fn rim_data_create(&mut self, addr: u64, blob: &mut VmmBlob) -> Result<u64> {
        const GRANULE: usize = RMM_GRANULE as usize;
        let mut content = vec![];
        let mut data_size = blob.read_to_end_ctx(&mut content)?;

        // Align to granule size
        let aligned_addr = align_down(addr, RMM_GRANULE);
        let fill_size = (addr - aligned_addr) as usize;
        data_size += fill_size;
        content.resize(data_size, 0);
        content.rotate_right(fill_size);

        // Fill up to granule size
        data_size = align_up(data_size as u64, RMM_GRANULE) as usize;
        content.resize(data_size, 0);

        log::debug!(
            "Measuring data 0x{:x} - 0x{:x}",
            aligned_addr,
            aligned_addr + data_size as u64 - 1
        );

        // Measure each page
        for off in (0..data_size).step_by(GRANULE) {
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
    /// Add one unmeasured data descriptor to the RIM. Corresponds to one or
    /// more calls to RMI_DATA_CREATE with the RMI_MEASURE_CONTENT flag clear:
    /// one for each granule in the range.
    ///
    #[allow(dead_code)]
    pub fn rim_data_create_unmeasured(&mut self, addr: u64, size: u64) -> Result<()> {
        const GRANULE: usize = RMM_GRANULE as usize;

        let aligned_addr = align_down(addr, RMM_GRANULE);
        let size = align_up(addr + size, RMM_GRANULE) - aligned_addr;

        log::debug!(
            "Unmeasured data 0x{:x} - 0x{:x}",
            aligned_addr,
            aligned_addr + size - 1
        );

        for off in (0..size).step_by(GRANULE) {
            let measurement_desc = rmm::RmmMeasurementDescriptorData::new(
                &self.measurements.rim,
                aligned_addr + off,
                0,        // flags
                &[0; 64], // content_hash
            );
            let bytes = measurement_desc.as_bytes()?;
            self.measurements.rim = self.measure_bytes(&bytes)?;
        }

        self.debug_rim();
        Ok(())
    }

    ///
    /// Measure one RIPAS range, add it to the RIM. This corresponds to multiple
    /// calls to RMI_RTT_INIT_RIPAS: for one IPA range submitted by the VMM, RMM
    /// performs a measurement for each RTT entry in the range.
    ///
    /// @base: the base IPA of the range, inclusive.
    /// @top: the top IPA, exclusive (size = top - base).
    ///
    pub fn rim_init_ripas(&mut self, base: u64, top: u64) -> Result<()> {
        if top <= base || !is_aligned(top | base, RMM_GRANULE) {
            return Err(RealmError::Parameter(format!("RIPAS({base:x}, {top:x})")));
        }

        if self.block_sizes == 0 {
            // Need to call rim_init() first!
            return Err(RealmError::Uninitialized("block sizes".to_string()));
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
    pub fn rim_rec_create(&mut self, rec: &rmm::RmiRecParams) -> Result<()> {
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

    ///
    /// Measure buffer into the Realm Extensible Measurement (REM). This
    /// corresponds to RSI_MEASUREMENT_EXTEND.
    ///
    pub fn rem_extend(&mut self, index: usize, buf: &[u8]) -> Result<()> {
        if index > 3 {
            return Err(RealmError::Parameter(format!("REM {index}")));
        }

        const REM_DATA_SIZE: usize = rmm::RMM_REALM_MEASUREMENT_SIZE;
        if buf.len() > REM_DATA_SIZE {
            return Err(RealmError::Parameter(format!(
                "REM measurement value size {} > REM_DATA_SIZE",
                buf.len()
            )));
        }

        let mut bytes: Vec<u8> = buf.to_vec();
        bytes.resize(REM_DATA_SIZE, 0);
        self.measurements.rem[index] =
            self.measure_bytes(&self.measurements.rem[index])?;
        self.measurements.rem[index] = self.measure_bytes(&bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
