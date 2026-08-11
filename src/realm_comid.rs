// Define a CoMID structure containing the minimum output for Realm
// endorsements, currently defined here:
// https://datatracker.ietf.org/doc/html/draft-ydb-rats-cca-endorsements-04
//
// Uses corim-rs to create CoMID

use std::iter;

use crate::realm::Realm;
use cca_rmm::RmiHashAlgorithm;
use corim_rs::{
    ClassMapBuilder, ConciseMidTag, ConciseMidTagBuilder, Digest, EnvironmentMap,
    EnvironmentMapBuilder, HashAlgorithm, MeasurementMap, MeasurementValuesMapBuilder,
    RawValueType, ReferenceTripleRecord, TagIdTypeChoice, TagIdentityMap, TaggedBytes,
    TriplesMap, TriplesMapBuilder,
};

type Result<T> = std::result::Result<T, ComidError>;

/// Save endorsements to file
///
/// Writes realm endorsements to file. A CoMID template can be passed to update it with the
/// realm reference values. If no template is provided, a default template is used.
/// The template can be JSON (serialization defined by corim-rs implementation) or
/// CBOR encoded (defined in draft-ydp-rats-cca-endorsements). The ouput is either
/// JSON or CBOR serialized depending on whether the json flag is set
///
/// * `realm`: reference to the [cca_realm_measurements::realm::Realm] object
/// * `output_file`: path to output file
/// * `template_file`: path to template file
/// * `json`: whether to serialize output as JSON. If false, output is serialized as CBOR
pub fn publish_comid<P: AsRef<std::path::Path>>(
    realm: &Realm,
    output_file: P,
    template_file: Option<P>,
    json: bool,
) -> Result<()> {
    let mid = if let Some(template_file) = template_file {
        let template = std::fs::read(template_file)?;
        let mid = cbor_or_json_decode(template)?;
        update_comid(mid, realm)
    } else {
        create_realm_comid(realm)
    }?;
    let output_file = std::fs::File::create(output_file)?;
    if json {
        serde_json::to_writer_pretty(output_file, &mid)
            .map_err(|e| ComidError::custom(format!("error writing JSON: {e}")))?;
    } else {
        ciborium::into_writer(&mid, output_file)
            .map_err(|e| ComidError::custom(format!("error writing CBOR: {e}")))?;
    }
    Ok(())
}

fn update_comid<'a>(
    mut mid: ConciseMidTag<'a>,
    r: &'a Realm,
) -> Result<ConciseMidTag<'a>> {
    let triples = realm_to_triples_map(r)?;
    mid.triples = triples;
    Ok(mid)
}

fn create_realm_comid(r: &Realm) -> Result<ConciseMidTag<'_>> {
    let id = TagIdTypeChoice::Uuid(uuid::Uuid::new_v4().into_bytes().into());
    let tag_id = TagIdentityMap {
        tag_id: id,
        tag_version: None,
    };

    Ok(ConciseMidTagBuilder::new()
        .tag_identity(tag_id)
        .triples(realm_to_triples_map(r)?)
        .build()?)
}

fn realm_to_triples_map(r: &Realm) -> Result<TriplesMap<'_>> {
    Ok(TriplesMapBuilder::new()
        .reference_triples(vec![realm_to_reference_triple_record(r)?])
        .build()?)
}

/// convert [crate::realm::Realm] to [corim_rs::ReferenceTripleRecord]
fn realm_to_reference_triple_record(r: &Realm) -> Result<ReferenceTripleRecord<'_>> {
    let env = rim_to_env_map(r.measurements.get_rim())?;
    let algo = r.get_hash_algo().map_err(ComidError::custom)?;
    let mut mmaps = Vec::new();
    for (k, v) in iter::zip(
        ["cca.rim", "cca.rem0", "cca.rem1", "cca.rem2", "cca.rem3"],
        r.measurements.to_byte_array().iter(),
    ) {
        mmaps.push(measurement_to_mmap(k, v, algo)?)
    }
    mmaps.push(rpv_to_mmap(r.rpv.to_bytes())?);
    Ok(ReferenceTripleRecord::new(env, mmaps))
}

/// convert RIM bytes to CoMID environment-map ([corim_rs::EnvironmentMap])
fn rim_to_env_map(rim: &[u8]) -> Result<EnvironmentMap<'_>> {
    Ok(EnvironmentMapBuilder::new()
        .class(
            ClassMapBuilder::new()
                .class_id(TaggedBytes::from(rim).into())
                .build()?,
        )
        .build()?)
}

/// convert a realm measurement to comid measurement-map ([corim_rs::MeasurementMap])
fn measurement_to_mmap<'a>(
    key: &'static str,
    meas: &'a [u8],
    alg: RmiHashAlgorithm,
) -> Result<MeasurementMap<'a>> {
    Ok(MeasurementMap::new(
        Some(key.into()),
        MeasurementValuesMapBuilder::new()
            .digest(vec![measurement_to_digest(meas, alg)])
            .build()?,
        None,
    ))
}

/// convert a realm measurement to comid digest ([corim_rs::Digest])
fn measurement_to_digest(meas: &[u8], alg: RmiHashAlgorithm) -> Digest {
    let hash_algo = match alg {
        RmiHashAlgorithm::RmiHashSha256 => HashAlgorithm::Sha256,
        RmiHashAlgorithm::RmiHashSha512 => HashAlgorithm::Sha512,
    };
    Digest::new(hash_algo, meas.into())
}

/// convert RPV to comid measurement-map ([corim_rs::MeasurementMap])
fn rpv_to_mmap(rpv: &[u8]) -> Result<MeasurementMap<'_>> {
    let raw_value = RawValueType::new(TaggedBytes::from(rpv).into(), None);
    let val = MeasurementValuesMapBuilder::new().raw(raw_value).build()?;
    Ok(MeasurementMap::new(Some("cca.rpv".into()), val, None))
}

/// helper function to deserialize template CoMID from either CBOR or JSON bytes
fn cbor_or_json_decode(bytes: Vec<u8>) -> Result<ConciseMidTag<'static>> {
    match ciborium::from_reader::<ConciseMidTag, &[u8]>(&bytes) {
        Ok(m) => Ok(m),
        Err(e) => match serde_json::from_slice::<ConciseMidTag>(&bytes) {
            Ok(m) => Ok(m),
            Err(f) => Err(ComidError::custom(format!(
                "error decoding comid: {e}, {f}"
            ))),
        },
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum ComidError {
    #[error("corim error: {0}")]
    CorimError(#[from] corim_rs::Error),

    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("custom: {0}")]
    Custom(String),
}

impl ComidError {
    pub fn custom<D: std::fmt::Display>(message: D) -> Self {
        Self::Custom(message.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_realm() -> Realm {
        let mut realm = Realm::new();
        realm.set_hash_algo(RmiHashAlgorithm::RmiHashSha256);
        realm
    }

    /// equal_fields!(struct1, struct2, info, field1, field2, ...)
    macro_rules! equal_fields {
        ($st1:ident, $st2:ident, $info:literal
         $(,$field:ident)+
         $(,)?) => {
            $(
                assert_eq!($st1.$field, $st2.$field, "{}: {} does not match", $info, stringify!($field));
            )+
        }
    }

    #[test]
    fn test_realm_comid_create() {
        let r = create_realm();
        let mid = create_realm_comid(&r)
            .expect("could not convert realm measurements to CoMID");

        let ref_mid_bytes = include_bytes!("../testdata/realm-comid.cbor");
        let ref_mid: ConciseMidTag = ciborium::from_reader(&ref_mid_bytes[..])
            .expect("could not deserialize reference comid");

        equal_fields!(
            mid,
            ref_mid,
            "comid create",
            language,
            entities,
            linked_tags,
            triples,
            extensions
        );
    }

    #[test]
    fn test_realm_comid_update() {
        let mut r = create_realm();
        r.measurements.rim = [0xff_u8; 64];

        let template_json = include_bytes!("../testdata/realm-comid.json");
        let template_cbor = include_bytes!("../testdata/realm-comid.cbor");

        let template_json_mid: ConciseMidTag = serde_json::from_slice(&template_json[..])
            .expect("could not deserialize json template");

        let template_cbor_mid: ConciseMidTag = ciborium::from_reader(&template_cbor[..])
            .expect("could not deserialize template cbor");

        let mid_from_cbor = update_comid(template_cbor_mid.clone(), &r)
            .expect("could not update CoMID from template");

        let mid_from_json = update_comid(template_json_mid.clone(), &r)
            .expect("could not update CoMID from template");

        equal_fields!(
            mid_from_json,
            template_json_mid,
            "update comid from json template",
            language,
            tag_identity,
            entities,
            linked_tags,
            extensions
        );
        equal_fields!(
            mid_from_cbor,
            template_cbor_mid,
            "update comid from cbor template",
            language,
            tag_identity,
            entities,
            linked_tags,
            extensions
        );
    }
}
