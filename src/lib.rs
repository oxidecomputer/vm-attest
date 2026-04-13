// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as};
use sha2::{
    Sha256,
    digest::{core_api::OutputSizeUser, typenum::Unsigned},
};
use std::{error, fmt, str};
use uuid::Uuid;

mod rot;
pub use rot::{VmInstanceRot, VmInstanceRotError};

const SHA256_DIGEST_LENGTH: usize =
    <Sha256 as OutputSizeUser>::OutputSize::USIZE;

/// User chosen value. Probably random data. Must not be reused.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QualifyingData([u8; 32]);

impl QualifyingData {
    /// When challenging a platform for an attestation the challenger will
    /// typically want to include random qualifying data (a nonce) in their
    /// challenge. This function uses the RNG from `getrandom` to generate
    /// such qualifying data.
    pub fn from_platform_rng() -> Result<Self, getrandom::Error> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce[..])?;
        let nonce = nonce;

        Ok(Self(nonce))
    }

    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

impl AsRef<[u8]> for QualifyingData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for QualifyingData {
    fn from(data: [u8; 32]) -> Self {
        Self(data)
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum MeasurementError {
    #[error("wrong number of fields")]
    FieldCount,
    #[error("invalid hex string")]
    HexDecode(#[from] hex::FromHexError),
    #[error("digest is wrong length for algorithm")]
    BadLength,
    #[error("unsupported algorithm identifier")]
    UnsupportedAlg(String),
}

/// A measurement is a digest. This type represents a measurement with the
/// digest algorithm represented by the variant with the digest in the
/// associated data. When serializing the algorithm identifier must be one
/// from the IANA Named Information Hash Algorithm Registry:
/// https://www.iana.org/assignments/named-information/named-information.xhtml
#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Measurement {
    #[serde(rename = "sha-256")]
    Sha256(#[serde_as(as = "Hex")] [u8; SHA256_DIGEST_LENGTH]),
}

impl str::FromStr for Measurement {
    type Err = MeasurementError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fields: Vec<&str> = s.split(';').collect();

        if fields.len() != 2 {
            return Err(Self::Err::FieldCount);
        }

        let (prefix, digest) = (fields[0], fields[1]);
        let measurement = match prefix {
            "sha-256" => {
                let digest = hex::decode(digest)?;
                Measurement::Sha256(
                    digest.try_into().map_err(|_| Self::Err::BadLength)?,
                )
            }
            _ => {
                return Err(Self::Err::UnsupportedAlg(prefix.to_string()));
            }
        };

        Ok(measurement)
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub enum RotType {
    OxidePlatform,
    OxideInstance,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct MeasurementLog {
    pub rot: RotType,
    pub data: Vec<u8>,
}

/// A representation of the measurement log produced by the VM instance RoT.
/// This is the log of measurements that propolis mixes into the data provided
/// to the attestation produced by the `RotType::OxidePlatform`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VmInstanceConf {
    pub uuid: Uuid,
    pub project: Uuid,
    pub silo: Uuid,
    #[serde(rename = "boot-digest")]
    pub boot_digest: Option<Measurement>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VmInstanceAttestation {
    // the attestation from the Oxide Platform RoT
    // the message signed by RoT is:
    //   attestation = sign(hubpack(log) | qualifying_data)
    // where:
    //   `vm_data` is the 32 bytres passed from the VM down to the VmInstanceRot
    //   `qualifying_data` = sha(vm_cfg | vm_data)
    // this is a hubpack serialization of the `attest_data::Attestation`
    // structure
    // NOTE: JSON would be better
    pub attestation: Vec<u8>,

    // the platform RoT cert chain
    // these are DER encoded, ordered from leaf to first intermediate
    // TODO: encoding these as PEM strings may be preferable, the JSON encoded
    // `Vec<u8>` may end up being less efficient
    pub cert_chain: Vec<Vec<u8>>,

    // measurement logs from the:
    // - Oxide Platform RoT: a hubpack serialized attest_data::Log
    // - VM Instance RoT: a JSON serialized mock::Measurement structure
    pub measurement_logs: Vec<MeasurementLog>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Request {
    Attest(QualifyingData),
}

/// This enumeration represents the response message returned by the
/// `VmInstanceRot` in response to the `attest` function / message.
#[derive(Debug, Deserialize, Serialize)]
pub enum Response {
    Attest(VmInstanceAttestation),
    Error(String),
}

/// An interface for obtaining attestations and supporting data from the VM
/// Instance RoT
pub trait VmInstanceAttester {
    type Error: error::Error + fmt::Debug;

    /// Get an attestation from each of the RoTs resident on the host platform
    /// qualified by the provided `QualifyingData`.
    fn attest(
        &self,
        qualifying_data: &QualifyingData,
    ) -> Result<VmInstanceAttestation, Self::Error>;
}

#[cfg(test)]
mod test {
    use crate::*;
    use hex::FromHexError;

    #[test]
    fn empty_measurement_str() {
        let input = "";

        let measurement: Result<Measurement, _> = input.parse();
        assert_eq!(measurement, Err(MeasurementError::FieldCount));
    }

    #[test]
    fn measurement_str_no_sep() {
        let input = "sha-256:1";
        let measurement: Result<Measurement, _> = input.parse();

        assert_eq!(measurement, Err(MeasurementError::FieldCount));
    }

    #[test]
    fn measurement_bad_prefix() {
        // `sha256` is not an identifier in the nih hash algorithm registry
        let input = "sha256;1";
        let measurement: Result<Measurement, _> = input.parse();

        assert_eq!(
            measurement,
            Err(MeasurementError::UnsupportedAlg("sha256".to_string()))
        );
    }

    #[test]
    fn measurement_bad_hex() {
        // hex strings must be an even length
        let input = "sha-256;1";
        let measurement: Result<Measurement, _> = input.parse();

        assert_eq!(
            measurement,
            Err(MeasurementError::HexDecode(FromHexError::OddLength))
        );
    }

    #[test]
    fn measurement_bad_length() {
        let input = "sha-256;11";
        let measurement: Result<Measurement, _> = input.parse();

        assert_eq!(measurement, Err(MeasurementError::BadLength));
    }

    #[test]
    fn measurement_sha256() {
        let digest_str =
            "e6e5936d72eb137f9d4fea1f55080352cd16c9f0e98becedfaaeb10b2b4e6d30";
        let expected = Measurement::Sha256(
            hex::decode(digest_str)
                .expect("bad hex string")
                .try_into()
                .expect("hex string wrong length"),
        );
        let input = format!("sha-256;{digest_str}");
        let measurement: Result<Measurement, _> = input.parse();

        assert_eq!(measurement, Ok(expected));
    }
}
