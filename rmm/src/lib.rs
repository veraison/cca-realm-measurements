//! Structures and values defined by the Realm Management Monitor
//!
//! This library provides structure and value definitions from the RMM
//! specification v1.0-rel0. For the moment it only provides the definitions
//! needed for Realm Initial Measurement calculation.
//!
//! References:
//! - DEN0137 1.0-rel0  Realm Management Specification
//!   - B4.3.9.4   RMI_REALM_CREATE initialization of RIM
//!   - B4.3.12.4  RMI_REC_CREATE extension of RIM
//!
//! - DEN0137 2.0-bet3  Realm Management Specification
//!   - B4.5.43.4  RMI_REC_CREATE extension of RIM
//!   - B4.5.62.4  RMI_RTT_DATA_MAP_INIT extension of RIM
//!
#![warn(missing_docs)]
use bitflags::bitflags;
use core::mem;
use std::str::FromStr;

use serde::ser::SerializeTuple;
use serde::{Deserialize, Serialize, Serializer};

/// Size of one Realm measurement, in bytes
pub const RMM_REALM_MEASUREMENT_WIDTH: usize = 64;
/// One Realm Measurement (initial or extensible)
pub type RmmRealmMeasurement = [u8; RMM_REALM_MEASUREMENT_WIDTH];

bitflags! {
/// In v1.0-rel0, RmiRealmFlags that are measured into the RIM
#[derive(Default, Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
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
/// RmiRecCreateFlags measured into the RIM.
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
    /// Error while encoding into binary
    #[error("encoding error")]
    EncodeError(#[from] bincode::Error),

    /// Unknown hash algorithm
    #[error("unknown hash algorithm `{0}`")]
    UnknownHashAlgorithm(String),
}
type Result<T> = core::result::Result<T, RmmError>;

/// Hash algorithm used for measurements
///
/// RMM v1.0-rel0 does not support RmiHashSha384.
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Default)]
pub enum RmiHashAlgorithm {
    /// SHA-256
    #[default]
    RmiHashSha256 = 0,
    /// SHA-512
    RmiHashSha512 = 1,
    /// SHA-384
    RmiHashSha384 = 2,
}

impl TryFrom<u8> for RmiHashAlgorithm {
    type Error = RmmError;
    fn try_from(algo: u8) -> Result<Self> {
        match algo {
            0 => Ok(RmiHashAlgorithm::RmiHashSha256),
            1 => Ok(RmiHashAlgorithm::RmiHashSha512),
            2 => Ok(RmiHashAlgorithm::RmiHashSha384),
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
            "sha384" => Ok(RmiHashAlgorithm::RmiHashSha384),
            _ => Err(RmmError::UnknownHashAlgorithm(String::from(s))),
        }
    }
}

// serde doesn't support serializing large arrays at the moment, so we need to
// do it manually: https://github.com/serde-rs/serde/issues/1937
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

/// In v1.0-rel0, the following RmiRealmParams are measured into the RIM.
///
/// In v2.0-bet3, the realm parameters are not part of the RIM. They are
/// provided to a verifier in the Realm claims, part of the Realm attestation
/// token.
///
#[derive(Clone, Debug, Serialize, PartialEq, Default)]
#[repr(C, packed)]
pub struct RmiRealmParams {
    flags: u64,
    s2sz: u8,
    _empty1: [u8; 7],
    sve_vl: u8,
    _empty2: [u8; 7],
    num_bps: u8,
    _empty3: [u8; 7],
    num_wps: u8,
    _empty4: [u8; 7],
    pmu_num_ctrs: u8,
    _empty5: [u8; 7],
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
            ..Default::default()
        }
    }
    /// Convert the packed struct to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = bincode::serialize(self)?;
        assert!(bytes.len() == mem::size_of::<RmiRealmParams>());
        bytes.resize(RMI_REALM_PARAMS_SIZE, 0);
        Ok(bytes)
    }
}

/// RmiRecParams that are measured into the RIM. The rest is set to zero.
#[derive(Clone, Debug, Serialize, PartialEq)]
#[repr(C, packed)]
pub struct RmiRecParams {
    flags: u64,
    #[serde(serialize_with = "serialize_array")]
    _empty1: [u8; 0x200 - 8],
    pc: u64,
    #[serde(serialize_with = "serialize_array")]
    _empty2: [u8; 0x100 - 8],
    gprs: [u64; 8],
}
const RMI_REC_PARAMS_SIZE: usize = 0x1000;

impl RmiRecParams {
    /// Create a new RmiRecParams instance
    pub fn new(flags: RmiRecCreateFlags, pc: u64, gprs: [u64; 8]) -> RmiRecParams {
        RmiRecParams {
            flags: flags.bits(),
            // Can't use default() because it doesn't work with large arrays.
            _empty1: [0; 0x200 - 8],
            pc,
            _empty2: [0; 0x100 - 8],
            gprs,
        }
    }

    /// Convert the packed struct to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = bincode::serialize(self)?;
        assert!(bytes.len() == mem::size_of::<RmiRecParams>());
        bytes.resize(RMI_REC_PARAMS_SIZE, 0);
        Ok(bytes)
    }
}

/// RmmMeasurementDescriptorData
///
/// RmmMeasurementDescriptorData fields that contribute to the RIM, in RMM
/// v1.0-rel0 and v2.0-bet3
///
#[derive(Clone, Debug, Serialize, PartialEq)]
#[repr(C, packed)]
pub struct RmmMeasurementDescriptorData {
    desc_type: u8,
    unused1: [u8; 7],
    len: u64,
    #[serde(serialize_with = "serialize_array")]
    rim: RmmRealmMeasurement,
    ipa: u64,
    flags: u64,
    #[serde(serialize_with = "serialize_array")]
    content: RmmRealmMeasurement,
}
const RMM_REALM_MEASUREMENT_DESCRIPTOR_DATA_SIZE: usize = 0x100;

impl RmmMeasurementDescriptorData {
    /// Create a new instance of RmmMeasurementDescriptorData
    pub fn new(
        rim: &RmmRealmMeasurement,
        ipa: u64,
        flags: RmmDataFlags,
        content: &RmmRealmMeasurement,
    ) -> RmmMeasurementDescriptorData {
        RmmMeasurementDescriptorData {
            desc_type: 0,
            unused1: [0; 7],
            len: RMM_REALM_MEASUREMENT_DESCRIPTOR_DATA_SIZE as u64,
            rim: *rim,
            ipa,
            flags: flags.bits(),
            content: *content,
        }
    }
    /// Convert the packed structure to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        assert!(self.desc_type == 0);
        let mut bytes = bincode::serialize(self)?;
        assert!(bytes.len() == mem::size_of::<RmmMeasurementDescriptorData>());
        bytes.resize(RMM_REALM_MEASUREMENT_DESCRIPTOR_DATA_SIZE, 0);
        Ok(bytes)
    }
}

/// RmmMeasurementDescriptorRec
///
/// Structure used to calculate the contribution to the RIM of a REC.
#[derive(Clone, Debug, Serialize, PartialEq)]
#[repr(C, packed)]
pub struct RmmMeasurementDescriptorRec {
    desc_type: u8,
    unused1: [u8; 7],
    len: u64,
    #[serde(serialize_with = "serialize_array")]
    rim: RmmRealmMeasurement,
    #[serde(serialize_with = "serialize_array")]
    content: RmmRealmMeasurement,
}
const RMM_REALM_MEASUREMENT_DESCRIPTOR_REC_SIZE: usize = 0x100;

impl RmmMeasurementDescriptorRec {
    /// Create a new instance of RmmMeasurementDescriptorRec
    pub fn new(
        rim: &RmmRealmMeasurement,
        content: &RmmRealmMeasurement,
    ) -> RmmMeasurementDescriptorRec {
        RmmMeasurementDescriptorRec {
            desc_type: 1,
            unused1: [0; 7],
            len: RMM_REALM_MEASUREMENT_DESCRIPTOR_REC_SIZE as u64,
            rim: *rim,
            content: *content,
        }
    }
    /// Convert the packed structure to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        assert!(self.desc_type == 1);
        let mut bytes = bincode::serialize(self)?;
        assert!(bytes.len() == mem::size_of::<RmmMeasurementDescriptorRec>());
        bytes.resize(RMM_REALM_MEASUREMENT_DESCRIPTOR_REC_SIZE, 0);
        Ok(bytes)
    }
}

/// RmmMeasurementDescriptorRipas
///
/// In v1.0-rel0, structure used to calculate the contribution to the RIM of a
/// RIPAS change.
///
/// In v2.0-bet3, the structure does not exist.
#[derive(Clone, Debug, Serialize, PartialEq)]
#[repr(C, packed)]
pub struct RmmMeasurementDescriptorRipas {
    desc_type: u8,
    unused1: [u8; 7],
    len: u64,
    #[serde(serialize_with = "serialize_array")]
    rim: RmmRealmMeasurement,
    base: u64,
    top: u64,
}
const RMM_REALM_MEASUREMENT_DESCRIPTOR_RIPAS_SIZE: usize = 0x100;

impl RmmMeasurementDescriptorRipas {
    /// Create a new instance of RmmMeasurementDescriptorRipas
    pub fn new(
        rim: &RmmRealmMeasurement,
        base: u64,
        top: u64,
    ) -> RmmMeasurementDescriptorRipas {
        RmmMeasurementDescriptorRipas {
            desc_type: 2,
            unused1: [0; 7],
            len: RMM_REALM_MEASUREMENT_DESCRIPTOR_RIPAS_SIZE as u64,
            rim: *rim,
            base,
            top,
        }
    }
    /// Convert the packed structure to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        assert!(self.desc_type == 2);
        let mut bytes = bincode::serialize(self)?;
        assert!(bytes.len() == mem::size_of::<RmmMeasurementDescriptorRipas>());
        bytes.resize(RMM_REALM_MEASUREMENT_DESCRIPTOR_RIPAS_SIZE, 0);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize() {
        let a = 0x12345678u32.to_le();
        let bytes = bincode::serialize(&a).unwrap();

        // By default, bincode encodes in litte-endian. Make sure of it, since
        // we rely on that for RMM structs
        assert!(bytes[0] == 0x78);
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
        assert_eq!(
            RmiHashAlgorithm::try_from(2).unwrap(),
            RmiHashAlgorithm::RmiHashSha384
        );
        assert!(RmiHashAlgorithm::try_from(3).is_err());
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
        assert_eq!(
            "sha384".parse::<RmiHashAlgorithm>().unwrap(),
            RmiHashAlgorithm::RmiHashSha384
        );
        assert!("hello".parse::<RmiHashAlgorithm>().is_err());
    }
}
