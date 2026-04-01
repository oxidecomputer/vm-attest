// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use log::{debug, warn};
use std::{
    cell::RefCell,
    io::{BufRead, BufReader, Read, Write},
    ops::DerefMut,
};
use vsock::{VsockListener, VsockStream};

use vm_attest::{
    QualifyingData, Request, Response, VmInstanceAttestation,
    VmInstanceAttester, VmInstanceConf, VmInstanceRot, VmInstanceRotError,
};

use crate::MAX_LINE_LENGTH;

/// This type mocks the JSON interface exposed by the VmInstanceRot over a
/// VsockListener. It accepts the same JSON encoded
/// messages exchanged between VM instances and the VM instance RoT /
/// `propolis`. These messages are decoded and passed along to the
/// `VmInstanceRot` held by the `VmInstanceRotVsockServer`. Clients connecting
/// to an instance of this type over the unix socket may either implement the
/// message serialization themselves, or use the `VmInstanceRotVsockClient`.
///
/// ```text
/// + ------------------------------+           +--------+
/// | VmInstanceRotVsockServer      |           |        |
/// +---------------+               |   JSON    | Client |
/// | VmInstanceRot | <--> listener | <-vsock-> |        |
/// +---------------+---------------+           +--------+
/// ```
pub struct VmInstanceRotVsockServer {
    rot: VmInstanceRot,
    conf: VmInstanceConf,
    listener: VsockListener,
}

#[derive(Debug, thiserror::Error)]
pub enum VmInstanceRotVsockError {
    #[error("error from underlying VmInstanceRoT")]
    MockRotError(#[from] VmInstanceRotError),

    #[error("error deserializing Command from JSON")]
    Request(serde_json::Error),

    #[error("error serializing response to JSON")]
    Response(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),
}

impl VmInstanceRotVsockServer {
    pub fn new(
        rot: VmInstanceRot,
        conf: VmInstanceConf,
        listener: VsockListener,
    ) -> Self {
        Self {
            rot,
            conf,
            listener,
        }
    }

    // message handling loop
    pub fn run(&self) -> Result<(), VmInstanceRotVsockError> {
        debug!("listening for clients");

        let mut msg = String::new();
        for client in self.listener.incoming() {
            debug!("new client");

            // `incoming` yeilds iterator over a Result
            let reader = BufReader::with_capacity(MAX_LINE_LENGTH, client?);
            let mut reader = reader.take(MAX_LINE_LENGTH as u64);
            loop {
                // would like to do this before `loop` but we need to write to
                // the client as well
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
                    let response =
                        Response::Error("Request too long".to_string());
                    let mut response = serde_json::to_string(&response)?;
                    response.push('\n');
                    debug!("sending error response: {response}");
                    reader
                        .get_mut()
                        .get_mut()
                        .write_all(response.as_bytes())?;
                    break;
                }

                debug!("string received: {msg}");
                let result: Result<Request, serde_json::Error> =
                    serde_json::from_str(&msg);
                let request = match result {
                    Ok(r) => r,
                    Err(e) => {
                        // send error message to client, then map to error type
                        let response = Response::Error(e.to_string());
                        let mut response = serde_json::to_string(&response)?;
                        response.push('\n');
                        debug!("sending error response: {response}");
                        reader
                            .get_mut()
                            .get_mut()
                            .write_all(response.as_bytes())?;
                        return Err(VmInstanceRotVsockError::Request(e));
                    }
                };

                let response = match request {
                    Request::Attest(q) => {
                        debug!("qualifying data received: {q:?}");
                        // NOTE: We do not contribute to the `QualifyingData`
                        // here. The self.rot impl will handle this for us.
                        match self.rot.attest(&self.conf, &q) {
                            Ok(a) => Response::Attest(a),
                            Err(e) => Response::Error(e.to_string()),
                        }
                    }
                };

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

#[derive(Debug)]
pub struct VmInstanceRotVsockClient {
    socket: RefCell<VsockStream>,
}

impl VmInstanceRotVsockClient {
    pub fn new(socket: VsockStream) -> Self {
        Self {
            socket: RefCell::new(socket),
        }
    }
}

/// Errors returned when trying to sign an attestation
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceRotVsockClientError {
    #[error("error deserializing a PlatformAttestation from JSON")]
    Deserialize(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),

    #[error("error from the VmInstanceRoT")]
    VmInstanceRotError(String),
}

impl VmInstanceAttester for VmInstanceRotVsockClient {
    type Error = VmInstanceRotVsockClientError;

    fn attest(
        &self,
        qualifying_data: &QualifyingData,
    ) -> Result<VmInstanceAttestation, Self::Error> {
        let request = Request::Attest(qualifying_data.clone());
        let mut request = serde_json::to_string(&request)?;
        request.push('\n');
        let request = request;

        debug!("writing request: {request}");
        self.socket.borrow_mut().write_all(request.as_bytes())?;

        let mut socket_mut = self.socket.borrow_mut();
        let mut reader = BufReader::new(socket_mut.deref_mut());

        let mut response = String::new();
        reader.read_line(&mut response)?;

        debug!("got response: {response}");
        // map response message to Result
        let response: Response = serde_json::from_str(&response)?;
        match response {
            Response::Attest(a) => Ok(a),
            Response::Error(e) => Err(Self::Error::VmInstanceRotError(e)),
        }
    }
}
