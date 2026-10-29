//! Structures and values defined by the Realm Management Monitor
//!
//! This library provides structure and value definitions from the RMM
//! specification v1.0-rel0. For the moment it only provides the definitions
//! needed for Realm Initial Measurement calculation.
#![warn(missing_docs)]
use bitflags::bitflags;
use std::str::FromStr;

use serde::Deserialize;

/// Size of one Realm measurement, in bytes
pub const RMM_REALM_MEASUREMENT_WIDTH: usize = 64;
/// One Realm Measurement (initial or extensible)
pub type RmmRealmMeasurement = [u8; RMM_REALM_MEASUREMENT_WIDTH];

bitflags! {
/// Flags provided by the host during Realm creation
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RmiRealmFlags: u64 {
    /// Enable Large Physical Addresses
    const LPA2 = 1 << 0;
    /// Enable Scalable Vector Extension
    const SVE = 1 << 1;
    /// Enable Power Management Unit
    const PMU = 1 << 2;
}
}

bitflags! {
/// Flags provided by the Host during REC creation
pub struct RmiRecCreateFlags: u64 {
    /// The REC is run at reset
    const RUNNABLE = 1 << 0;
}
}

bitflags! {
/// Flags provided by the Host during DATA Granule creation
pub struct RmmDataFlags: u64 {
    /// Measure the content of the DATA granule
    const MEASURE = 1 << 0;
}
}

/// Size of a granule
pub const RMM_GRANULE: u64 = 0x1000;

/// Error from the RMM library
#[derive(Debug, thiserror::Error)]
pub enum RmmError {
    /// Unknown hash algorithm
    #[error("unknown hash algorithm `{0}`")]
    UnknownHashAlgorithm(String),
}
type Result<T> = core::result::Result<T, RmmError>;

/// Hash algorithm used for measurements
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Default)]
pub enum RmiHashAlgorithm {
    /// The SHA-256 algorithm
    #[default]
    RmiHashSha256 = 0,
    /// The SHA-512 algorithm
    RmiHashSha512 = 1,
}

impl TryFrom<u8> for RmiHashAlgorithm {
    type Error = RmmError;
    fn try_from(algo: u8) -> Result<Self> {
        match algo {
            0 => Ok(RmiHashAlgorithm::RmiHashSha256),
            1 => Ok(RmiHashAlgorithm::RmiHashSha512),
            _ => Err(RmmError::UnknownHashAlgorithm("{algo}".to_string())),
        }
    }
}

impl FromStr for RmiHashAlgorithm {
    type Err = RmmError;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "sha256" => Ok(RmiHashAlgorithm::RmiHashSha256),
            "sha512" => Ok(RmiHashAlgorithm::RmiHashSha512),
            _ => Err(RmmError::UnknownHashAlgorithm(String::from(s))),
        }
    }
}

// Write a 64-bit little-endian number to @buf at @offset
fn set_le64(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

// Write a measurement to @buf at @offset
fn set_measurement(buf: &mut [u8], offset: usize, val: &RmmRealmMeasurement) {
    buf[offset..offset + RMM_REALM_MEASUREMENT_WIDTH].copy_from_slice(val);
}

/// RmiRealmParams with only the fields that are measured for the RIM. The rest
/// is set to zero (DEN0137 1.0-rel0 B4.3.9.4 RMI_REALM_CREATE initialization of
/// RIM)
#[derive(Clone, Debug, PartialEq, Default)]
pub struct RmiRealmParams {
    flags: u64,
    s2sz: u8,
    sve_vl: u8,
    num_bps: u8,
    num_wps: u8,
    pmu_num_ctrs: u8,
    hash_algo: u8,
}
const RMI_REALM_PARAMS_SIZE: usize = 0x1000;

impl RmiRealmParams {
    /// Create a new RmiRealmParams instance
    pub fn new(
        flags: RmiRealmFlags,
        s2sz: u8,
        num_wps: u8,
        num_bps: u8,
        pmu_num_ctrs: u8,
        sve_vl: u8,
        hash_algo: RmiHashAlgorithm,
    ) -> RmiRealmParams {
        RmiRealmParams {
            flags: flags.bits(),
            s2sz,
            num_wps,
            num_bps,
            pmu_num_ctrs,
            sve_vl,
            hash_algo: hash_algo as u8,
        }
    }

    /// Encode a RmiRealmParams struct
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0; RMI_REALM_PARAMS_SIZE];
        set_le64(&mut bytes, 0x0, self.flags);
        bytes[0x8] = self.s2sz;
        bytes[0x10] = self.sve_vl;
        bytes[0x18] = self.num_bps;
        bytes[0x20] = self.num_wps;
        bytes[0x28] = self.pmu_num_ctrs;
        bytes[0x30] = self.hash_algo;
        Ok(bytes)
    }
}

/// RmiRecParams with only the fields that are measured for the RIM. The rest is
/// set to zero (DEN0137 1.0-rel0 B4.3.12.4 RMI_REC_CREATE extension of RIM)
#[derive(Clone, Debug, PartialEq)]
pub struct RmiRecParams {
    flags: u64,
    pc: u64,
    gprs: [u64; 8],
}
const RMI_REC_PARAMS_SIZE: usize = 0x1000;

impl RmiRecParams {
    /// Create a new RmiRecParams instance
    pub fn new(flags: RmiRecCreateFlags, pc: u64, gprs: [u64; 8]) -> RmiRecParams {
        RmiRecParams {
            flags: flags.bits(),
            pc,
            gprs,
        }
    }

    /// Encode a RmiRecParams struct
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0; RMI_REC_PARAMS_SIZE];
        set_le64(&mut bytes, 0x0, self.flags);
        set_le64(&mut bytes, 0x200, self.pc);
        for i in 0..8 {
            set_le64(&mut bytes, 0x300 + 8 * i, self.gprs[i]);
        }
        Ok(bytes)
    }
}

/// Structure used to calculate the contribution to the RIM of a data granule
#[derive(Clone, Debug, PartialEq)]
pub struct RmmMeasurementDescriptorData {
    rim: RmmRealmMeasurement,
    ipa: u64,
    flags: u64,
    content: RmmRealmMeasurement,
}
const RMM_MEASUREMENT_DESCRIPTOR_DATA_SIZE: usize = 0x100;

impl RmmMeasurementDescriptorData {
    /// Create a new instance of RmmMeasurementDescriptorData
    pub fn new(
        rim: &RmmRealmMeasurement,
        ipa: u64,
        flags: RmmDataFlags,
        content: &RmmRealmMeasurement,
    ) -> RmmMeasurementDescriptorData {
        RmmMeasurementDescriptorData {
            rim: *rim,
            ipa,
            flags: flags.bits(),
            content: *content,
        }
    }

    /// Encode a RmmMeasurementDescriptorData struct
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0; RMM_MEASUREMENT_DESCRIPTOR_DATA_SIZE];
        bytes[0x0] = 0;
        set_le64(&mut bytes, 0x8, RMM_MEASUREMENT_DESCRIPTOR_DATA_SIZE as u64);
        set_measurement(&mut bytes, 0x10, &self.rim);
        set_le64(&mut bytes, 0x50, self.ipa);
        set_le64(&mut bytes, 0x58, self.flags);
        set_measurement(&mut bytes, 0x60, &self.content);
        Ok(bytes)
    }
}

/// Structure used to calculate the contribution to the RIM of a REC
#[derive(Clone, Debug, PartialEq)]
pub struct RmmMeasurementDescriptorRec {
    rim: RmmRealmMeasurement,
    content: RmmRealmMeasurement,
}
const RMM_MEASUREMENT_DESCRIPTOR_REC_SIZE: usize = 0x100;

impl RmmMeasurementDescriptorRec {
    /// Create a new instance of RmmMeasurementDescriptorRec
    pub fn new(
        rim: &RmmRealmMeasurement,
        content: &RmmRealmMeasurement,
    ) -> RmmMeasurementDescriptorRec {
        RmmMeasurementDescriptorRec {
            rim: *rim,
            content: *content,
        }
    }

    /// Encode a RmmMeasurementDescriptorRec struct
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0; RMM_MEASUREMENT_DESCRIPTOR_REC_SIZE];
        bytes[0x0] = 1;
        set_le64(&mut bytes, 0x8, RMM_MEASUREMENT_DESCRIPTOR_REC_SIZE as u64);
        set_measurement(&mut bytes, 0x10, &self.rim);
        set_measurement(&mut bytes, 0x50, &self.content);
        Ok(bytes)
    }
}

/// Structure used to calculate the contribution to the RIM of a RIPAS change
#[derive(Clone, Debug, PartialEq)]
pub struct RmmMeasurementDescriptorRipas {
    rim: RmmRealmMeasurement,
    base: u64,
    top: u64,
}
const RMM_MEASUREMENT_DESCRIPTOR_RIPAS_SIZE: usize = 0x100;

impl RmmMeasurementDescriptorRipas {
    /// Create a new instance of RmmMeasurementDescriptorRipas
    pub fn new(
        rim: &RmmRealmMeasurement,
        base: u64,
        top: u64,
    ) -> RmmMeasurementDescriptorRipas {
        RmmMeasurementDescriptorRipas {
            rim: *rim,
            base,
            top,
        }
    }

    /// Encode a RmmMeasurementDescriptorRipas struct
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0; RMM_MEASUREMENT_DESCRIPTOR_RIPAS_SIZE];
        bytes[0x0] = 2;
        set_le64(
            &mut bytes,
            0x8,
            RMM_MEASUREMENT_DESCRIPTOR_RIPAS_SIZE as u64,
        );
        set_measurement(&mut bytes, 0x10, &self.rim);
        set_le64(&mut bytes, 0x50, self.base);
        set_le64(&mut bytes, 0x58, self.top);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // echo hello | sha256sum
    fn test_measurement() -> RmmRealmMeasurement {
        [
            0x58, 0x91, 0xb5, 0xb5, 0x22, 0xd5, 0xdf, 0x08, 0x6d, 0x0f, 0xf0, 0xb1, 0x10,
            0xfb, 0xd9, 0xd2, 0x1b, 0xb4, 0xfc, 0x71, 0x63, 0xaf, 0x34, 0xd0, 0x82, 0x86,
            0xa2, 0xe8, 0x46, 0xf6, 0xbe, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    }

    #[test]
    fn test_hash_algo() {
        assert_eq!(
            RmiHashAlgorithm::try_from(0).unwrap(),
            RmiHashAlgorithm::RmiHashSha256
        );
        assert_eq!(
            RmiHashAlgorithm::try_from(1).unwrap(),
            RmiHashAlgorithm::RmiHashSha512
        );
        assert!(RmiHashAlgorithm::try_from(2).is_err());
        let h: RmiHashAlgorithm = "sha256".parse().unwrap();
        assert_eq!(h, RmiHashAlgorithm::RmiHashSha256);
        assert_eq!(
            "sha256".parse::<RmiHashAlgorithm>().unwrap(),
            RmiHashAlgorithm::RmiHashSha256
        );
        assert_eq!(
            "sha512".parse::<RmiHashAlgorithm>().unwrap(),
            RmiHashAlgorithm::RmiHashSha512
        );
        assert!("hello".parse::<RmiHashAlgorithm>().is_err());
    }

    #[test]
    fn test_rmi_realm_params() {
        let params = RmiRealmParams::new(
            RmiRealmFlags::LPA2 | RmiRealmFlags::SVE | RmiRealmFlags::PMU,
            48,
            2,
            3,
            4,
            5,
            RmiHashAlgorithm::RmiHashSha512,
        );

        let mut expected = [0; RMI_REALM_PARAMS_SIZE];

        expected[0x0] = 0x7; // flags
        expected[0x8] = 48; // s2sz
        expected[0x10] = 5; // sve_vl
        expected[0x18] = 3; // num_bps
        expected[0x20] = 2; // num_wps
        expected[0x28] = 4; // pmu_num_ctrs
        expected[0x30] = 1; // hash_algo

        assert_eq!(params.to_bytes().unwrap(), expected);
    }

    #[test]
    fn test_rmi_rec_params() {
        let params = RmiRecParams::new(
            RmiRecCreateFlags::RUNNABLE,
            0xfffff8,
            [0xabcd, 0, 0, 0, 0, 0, 0, 0xdef0],
        );

        let bytes = params.to_bytes().unwrap();

        let mut expected = [0; RMI_REC_PARAMS_SIZE];
        expected[0] = 1;
        expected[0x100] = 0;
        // pc; u64 fields are little-endian
        expected[0x200] = 0xf8;
        expected[0x201] = 0xff;
        expected[0x202] = 0xff;
        expected[0x204] = 0x0;
        // x0
        expected[0x300] = 0xcd;
        expected[0x301] = 0xab;
        expected[0x307] = 0x0;
        // x7
        expected[0x338] = 0xf0;
        expected[0x339] = 0xde;
        expected[0x340] = 0x0;

        expected[0xfff] = 0x0;

        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_rmm_measurement_data() {
        let desc = RmmMeasurementDescriptorData::new(
            &[0; RMM_REALM_MEASUREMENT_WIDTH],
            0xffff0000,
            RmmDataFlags::MEASURE,
            &test_measurement(),
        );

        let bytes = desc.to_bytes().unwrap();

        let mut expected = [0; RMM_MEASUREMENT_DESCRIPTOR_DATA_SIZE];
        // type
        expected[0x0] = 0x0;
        // len
        expected[0x8] = 0x0;
        expected[0x9] = 0x1;
        expected[0xf] = 0x0;
        // rim
        expected[0x10] = 0x0;
        // ipa
        expected[0x50] = 0x0;
        expected[0x52] = 0xff;
        expected[0x53] = 0xff;
        expected[0x57] = 0x0;
        // flags
        expected[0x58] = 0x1;
        expected[0x5f] = 0x0;
        // content
        expected[0x60..0xa0].copy_from_slice(&test_measurement());
        expected[0x60] = 0x58;
        expected[0x7f] = 0x03;
        expected[0x80] = 0x0;

        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_rmm_measurement_rec() {
        let desc = RmmMeasurementDescriptorRec::new(
            &[0; RMM_REALM_MEASUREMENT_WIDTH],
            &test_measurement(),
        );

        let bytes = desc.to_bytes().unwrap();

        let mut expected = [0; RMM_MEASUREMENT_DESCRIPTOR_REC_SIZE];
        // type
        expected[0x0] = 0x1;
        // len
        expected[0x8] = 0x0;
        expected[0x9] = 0x1;
        expected[0xf] = 0x0;
        // rim
        expected[0x10] = 0x0;
        // content
        expected[0x50..0x90].copy_from_slice(&test_measurement());
        expected[0x50] = 0x58;
        expected[0x6f] = 0x03;

        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_rmm_measurement_ripas() {
        let desc = RmmMeasurementDescriptorRipas::new(
            &[0; RMM_REALM_MEASUREMENT_WIDTH],
            0x8090f0000,
            0x80b0f0000,
        );

        let bytes = desc.to_bytes().unwrap();

        let mut expected = [0; RMM_MEASUREMENT_DESCRIPTOR_RIPAS_SIZE];
        // type
        expected[0x0] = 0x2;
        // len
        expected[0x8] = 0x0;
        expected[0x9] = 0x1;
        expected[0xf] = 0x0;
        // rim
        expected[0x10] = 0x0;
        // base
        expected[0x50] = 0x0;
        expected[0x51] = 0x0;
        expected[0x52] = 0xf;
        expected[0x53] = 0x9;
        expected[0x54] = 0x8;
        expected[0x57] = 0x0;
        // top
        expected[0x58] = 0x0;
        expected[0x59] = 0x0;
        expected[0x5a] = 0xf;
        expected[0x5b] = 0xb;
        expected[0x5c] = 0x8;
        expected[0x5e] = 0x0;

        assert_eq!(bytes, expected);
    }
}
