// Structures and values defined by the RMM specification.
// At the moment, this library only provides the definitions needed for RIM
// calculation.
use core::mem;

use serde::ser::SerializeTuple;
use serde::{Serialize, Serializer};

pub const RMM_REALM_MEASUREMENT_SIZE: usize = 64;
pub type RmmRealmMeasurement = [u8; RMM_REALM_MEASUREMENT_SIZE];

pub type RmiRealmFlags = u64;

pub const RMI_REALM_F_LPA2: u64 = 1 << 0;
pub const RMI_REALM_F_SVE: u64 = 1 << 1;
pub const RMI_REALM_F_PMU: u64 = 1 << 2;

pub type RmiRecCreateFlags = u64;

pub const RMI_REC_CREATE_F_RUNNABLE: u64 = 1 << 0;

pub type RmmDataFlags = u64;

pub const RMM_DATA_F_MEASURE: u64 = 1 << 0;

pub const RMM_GRANULE: u64 = 0x1000;

#[derive(Copy, Clone)]
pub enum RmiHashAlgorithm {
    RmiHashSha256 = 0,
    RmiHashSha512 = 1,
}

// serde doesn't support serializing large arrays at the moment, so we need to
// do it manually: https://github.com/serde-rs/serde/issues/1937
fn serialize_array<S: Serializer, const N: usize>(
    t: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut ser_tuple = serializer.serialize_tuple(N)?;
    for e in t {
        ser_tuple.serialize_element(e)?;
    }
    ser_tuple.end()
}

/// RmiRealmParams with only the fields that are measured for the RIM. The rest
/// is set to zero (DEN0137 1.0-eac5 B4.3.9.4 RMI_REALM_CREATE initialization)
#[derive(Serialize, Default)]
#[repr(C, packed)]
pub struct RmiRealmParams {
    pub flags: RmiRealmFlags,
    pub s2sz: u8,
    _empty1: [u8; 7],
    pub sve_vl: u8,
    _empty2: [u8; 7],
    pub num_bps: u8,
    _empty3: [u8; 7],
    pub num_wps: u8,
    _empty4: [u8; 7],
    pub pmu_num_ctrs: u8,
    _empty5: [u8; 7],
    pub hash_algo: u8,
}
pub const RMI_REALM_PARAMS_SIZE: usize = 0x1000;

impl RmiRealmParams {
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
            flags,
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
    pub fn as_bytes(&self) -> bincode::Result<Vec<u8>> {
        let mut bytes = bincode::serialize(self)?;
        assert!(bytes.len() == mem::size_of::<RmiRealmParams>());
        bytes.resize(RMI_REALM_PARAMS_SIZE, 0);
        Ok(bytes)
    }
}

/// RmiRecParams with only the fields that are measured for the RIM. The rest is
/// set to zero (DEN0137 1.0-eac5 B4.3.12.4 RMI_REC_CREATE extension of RIM)
#[derive(Serialize)]
#[repr(C, packed)]
pub struct RmiRecParams {
    pub flags: RmiRecCreateFlags,
    #[serde(serialize_with = "serialize_array")]
    _empty1: [u8; 0x200 - 8],
    pub pc: u64,
    #[serde(serialize_with = "serialize_array")]
    _empty2: [u8; 0x100 - 8],
    pub gprs: [u64; 8],
}
pub const RMI_REC_PARAMS_SIZE: usize = 0x1000;

impl RmiRecParams {
    pub fn new(flags: RmiRecCreateFlags, pc: u64, gprs: [u64; 8]) -> RmiRecParams {
        RmiRecParams {
            // Can't use default() because it doesn't work with large arrays.
            flags,
            _empty1: [0; 0x200 - 8],
            pc,
            _empty2: [0; 0x100 - 8],
            gprs,
        }
    }

    /// Convert the packed struct to bytes
    pub fn as_bytes(&self) -> bincode::Result<Vec<u8>> {
        let mut bytes = bincode::serialize(self)?;
        assert!(bytes.len() == mem::size_of::<RmiRecParams>());
        bytes.resize(RMI_REC_PARAMS_SIZE, 0);
        Ok(bytes)
    }
}

#[derive(Serialize)]
#[repr(C, packed)]
pub struct RmmMeasurementDescriptorData {
    // pub?
    desc_type: u8,
    unused1: [u8; 7],
    len: u64,
    #[serde(serialize_with = "serialize_array")]
    rim: RmmRealmMeasurement,
    ipa: u64,
    flags: RmmDataFlags,
    #[serde(serialize_with = "serialize_array")]
    content: RmmRealmMeasurement,
}
pub const RMM_REALM_MEASUREMENT_DESCRIPTOR_DATA_SIZE: usize = 0x100;

impl RmmMeasurementDescriptorData {
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
            flags,
            content: *content,
        }
    }
    pub fn as_bytes(&self) -> bincode::Result<Vec<u8>> {
        assert!(self.desc_type == 0);
        let mut bytes = bincode::serialize(self)?;
        assert!(bytes.len() == mem::size_of::<RmmMeasurementDescriptorData>());
        bytes.resize(RMM_REALM_MEASUREMENT_DESCRIPTOR_DATA_SIZE, 0);
        Ok(bytes)
    }
}

#[derive(Serialize)]
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
pub const RMM_REALM_MEASUREMENT_DESCRIPTOR_REC_SIZE: usize = 0x100;

impl RmmMeasurementDescriptorRec {
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
    pub fn as_bytes(&self) -> bincode::Result<Vec<u8>> {
        assert!(self.desc_type == 1);
        let mut bytes = bincode::serialize(self)?;
        assert!(bytes.len() == mem::size_of::<RmmMeasurementDescriptorRec>());
        bytes.resize(RMM_REALM_MEASUREMENT_DESCRIPTOR_DATA_SIZE, 0);
        Ok(bytes)
    }
}

#[derive(Serialize)]
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
pub const RMM_REALM_MEASUREMENT_DESCRIPTOR_RIPAS_SIZE: usize = 0x100;

impl RmmMeasurementDescriptorRipas {
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
    pub fn as_bytes(&self) -> bincode::Result<Vec<u8>> {
        assert!(self.desc_type == 2);
        let mut bytes = bincode::serialize(self)?;
        assert!(bytes.len() == mem::size_of::<RmmMeasurementDescriptorRipas>());
        bytes.resize(RMM_REALM_MEASUREMENT_DESCRIPTOR_RIPAS_SIZE, 0);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_serialize() {
        let a = 0x12345678u32.to_le();
        let bytes = bincode::serialize(&a).unwrap();

        // By default, bincode encodes in litte-endian. Make sure of it, since
        // we rely on that for RMM structs
        assert!(bytes[0] == 0x78);
    }
}
