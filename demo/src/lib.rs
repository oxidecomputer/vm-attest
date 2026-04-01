// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use log::{debug, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
};

use vm_attest::{QualifyingData, VmInstanceAttestation, VmInstanceAttester};

/// the maximum length of a message that we'll accept from clients
const MAX_LINE_LENGTH: usize = 1024;

mod socket;
pub use socket::{
    VmInstanceRotSocketClient, VmInstanceRotSocketClientError,
    VmInstanceRotSocketRunError, VmInstanceRotSocketServer,
};

mod vsock;
pub use vsock::{VmInstanceRotVsockClient, VmInstanceRotVsockServer};

/// This enumeration represents the response message sent from one of the
/// `VmInstanceTcpServer`
#[derive(Debug, Deserialize, Serialize)]
pub enum VmInstanceAttestDataResponse {
    Attestation(AttestedData),
    Error(String),
}

/// Possible errors from `VmInstanceAttestSocketServer::run`
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceTcpServerError<T: VmInstanceAttester> {
    #[error("failed to deserialize QualifyingData request from JSON")]
    Request(serde_json::Error),

    #[error("failed to serialize Response to JSON")]
    Response(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),

    #[error("error from the underlying VmInstanceRot")]
    VmInstanceRotError(<T as VmInstanceAttester>::Error),
}

/// This type exposes a notional interface that a VM instance may expose. This
/// server allows the caller to challenge the VM instance for an attestation.
/// The VM instance generates some local data, then binds this data to an
/// attestation from the `VmInstanceRot`. The attestation is then returned to
/// the caller in a data structure that includes the generated data for use
/// in the appraisal process.
#[derive(Debug)]
pub struct VmInstanceTcpServer<T: VmInstanceAttester> {
    challenge_listener: TcpListener,
    vm_instance_rot: T,
}

impl<T: VmInstanceAttester> VmInstanceTcpServer<T> {
    pub fn new(challenge_listener: TcpListener, vm_instance_rot: T) -> Self {
        Self {
            challenge_listener,
            vm_instance_rot,
        }
    }

    pub fn run(&self) -> Result<(), VmInstanceTcpServerError<T>> {
        let mut msg = String::new();
        for client in self.challenge_listener.incoming() {
            debug!("new client");

            let reader = BufReader::with_capacity(MAX_LINE_LENGTH, client?);
            let mut reader = reader.take(MAX_LINE_LENGTH as u64);
            loop {
                // read QualifyingData from stream (JSON)
                let count = reader.read_line(&mut msg)?;
                if count == 0 {
                    debug!("read 0 bytes: EOF");
                    break;
                }

                // detect receipt of a message longer than the max
                if count == MAX_LINE_LENGTH && !msg.ends_with('\n') {
                    warn!(
                        "Error: Line length exceeded the limit of {} bytes.",
                        MAX_LINE_LENGTH
                    );
                    let response = VmInstanceAttestDataResponse::Error(
                        "Request too long".to_string(),
                    );
                    let mut response = serde_json::to_string(&response)?;
                    response.push('\n');
                    debug!("sending error response: {response}");
                    reader
                        .get_mut()
                        .get_mut()
                        .write_all(response.as_bytes())?;
                    break;
                }

                debug!("qualifying data received: {msg}");
                let result: Result<QualifyingData, serde_json::Error> =
                    serde_json::from_str(&msg);
                let qdata_in = match result {
                    Ok(q) => q,
                    Err(e) => {
                        let response =
                            VmInstanceAttestDataResponse::Error(e.to_string());
                        let mut response = serde_json::to_string(&response)?;
                        response.push('\n');
                        debug!("sending error response: {response}");
                        reader
                            .get_mut()
                            .get_mut()
                            .write_all(response.as_bytes())?;
                        return Err(VmInstanceTcpServerError::Request(e));
                    }
                };
                debug!("qualifying data decoded: {qdata_in:?}");

                //   - generate `public_key`
                let data = vec![1, 2, 3, 4];

                // `QualifyingData` passed down to the next layer is the
                // qualifying data from the caller combined with the data
                // we've generated locally
                let mut qdata_out = Sha256::new();
                qdata_out.update(qdata_in);
                qdata_out.update(&data);
                let qdata_out = QualifyingData::from(Into::<[u8; 32]>::into(
                    qdata_out.finalize(),
                ));

                // get `attestation` from a `VmInstanceAttester` by passing the
                // qualifying data generated above
                let attestation = match self.vm_instance_rot.attest(&qdata_out)
                {
                    Ok(a) => a,
                    Err(e) => {
                        let response =
                            VmInstanceAttestDataResponse::Error(e.to_string());
                        let mut response = serde_json::to_string(&response)?;
                        response.push('\n');
                        debug!("sending error response: {response}");
                        reader
                            .get_mut()
                            .get_mut()
                            .write_all(response.as_bytes())?;
                        return Err(
                            VmInstanceTcpServerError::VmInstanceRotError(e),
                        );
                    }
                };

                let attested_data = AttestedData { attestation, data };

                let response =
                    VmInstanceAttestDataResponse::Attestation(attested_data);

                //   - return `attestation` + `public_key`
                let mut response = serde_json::to_string(&response)?;
                response.push('\n');

                debug!("sending response: {response}");
                reader.get_mut().get_mut().write_all(response.as_bytes())?;
                msg.clear();
            }
        }

        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AttestedData {
    pub attestation: VmInstanceAttestation,
    pub data: Vec<u8>,
}

/// Possible errors from `VmInstanceAttestSocketServer::run`
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceTcpError {
    #[error("error converting type with serde")]
    Serialization(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),

    #[error("error propagated from the VmInstance")]
    VmInstance(String),
}

/// This type wraps the client side of a TCP connection / stream.
/// The server side should be an instance of the `VmInstanceTcpServer`.
pub struct VmInstanceTcp {
    stream: TcpStream,
}

impl VmInstanceTcp {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// Send a nonce / `QualifyingData` to the `VmInstanceTcpServer`, get back
    /// an `AttestedData` that we deserialize from JSON.
    pub fn attest_data(
        &mut self,
        qdata: &QualifyingData,
    ) -> Result<AttestedData, VmInstanceTcpError> {
        let mut qdata = serde_json::to_string(&qdata)?;
        qdata.push('\n');
        self.stream.write_all(qdata.as_bytes())?;
        debug!("qualifying data sent: {qdata}");

        // get back struct w/ attestation + public key
        let mut reader = BufReader::new(&self.stream);
        let mut response = String::new();
        reader.read_line(&mut response)?;
        debug!("got attesetd key: {response}");

        let response: VmInstanceAttestDataResponse =
            serde_json::from_str(&response)?;
        match response {
            VmInstanceAttestDataResponse::Attestation(a) => Ok(a),
            VmInstanceAttestDataResponse::Error(e) => {
                Err(VmInstanceTcpError::VmInstance(e))
            }
        }
    }
}
