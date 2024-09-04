// Define a CoMID structure containing the minimum output for Realm
// endorsements, currently defined here:
// https://datatracker.ietf.org/doc/html/draft-ydb-rats-cca-endorsements-00
//
// This should use a CoMID crate, but none exist at the moment.

use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct ComidTaggedType {
    #[serde(rename = "type")]
    pub vtype: String,
    pub value: String,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct ComidTagId {
    pub id: String,
    pub version: u32,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct ComidClass {
    pub id: ComidTaggedType,
    pub vendor: String,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct ComidEnvironment {
    pub class: ComidClass,
    pub instance: ComidTaggedType,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct ComidIntegrityRegister {
    #[serde(rename = "key-type")]
    pub key_type: String,
    pub value: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct RealmIntegrityRegisters {
    pub rim: ComidIntegrityRegister,
    pub rem0: ComidIntegrityRegister,
    pub rem1: ComidIntegrityRegister,
    pub rem2: ComidIntegrityRegister,
    pub rem3: ComidIntegrityRegister,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct ComidMeasurementValues {
    #[serde(rename = "raw-value")]
    pub raw_value: ComidTaggedType,
    #[serde(rename = "integrity-registers")]
    pub integrity_registers: RealmIntegrityRegisters,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct ComidMeasurement {
    pub value: ComidMeasurementValues,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct ComidTripleRefValue {
    pub environment: ComidEnvironment,
    pub measurement: ComidMeasurement,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct ComidTriples {
    #[serde(rename = "reference-values")]
    pub reference_values: Vec<ComidTripleRefValue>,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct RealmEndorsementsComid {
    #[serde(rename = "tag-identity")]
    pub tag_identity: ComidTagId,
    pub triples: ComidTriples,
}

impl RealmEndorsementsComid {
    pub fn new() -> Self {
        RealmEndorsementsComid {
            ..Default::default()
        }
    }

    /// Initialize a single empty reference values structure. Note that we don't
    /// erase an existing reference_values, but we clear its measurements (so
    /// environment remains).
    pub fn init_refval(&mut self) {
        if self.triples.reference_values.is_empty() {
            self.triples.reference_values = vec![ComidTripleRefValue {
                ..Default::default()
            }];
        }

        self.triples.reference_values[0].measurement = ComidMeasurement {
            ..Default::default()
        };
    }
}
