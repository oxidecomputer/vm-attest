// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use log::{debug, warn};
use std::{
    cell::RefCell,
    io::{BufRead, BufReader, Read, Write},
    ops::DerefMut,
    os::unix::net::{UnixListener, UnixStream},
};

use vm_attest::{
    QualifyingData, Request, Response, VmInstanceAttestation,
    VmInstanceAttester, VmInstanceConf, VmInstanceRot, VmInstanceRotError,
};

use crate::MAX_LINE_LENGTH;

/// This type wraps the client side of a `UnixStream` socket.
/// The server side should be an instance of the `VmInstanceRotSocketServer`
/// type. Clients should give instances of this type a unix socket connected
/// to the VmInstanceRotSocketServer and then interact with it through the
/// `VmInstanceRoT` trait.
#[derive(Debug)]
pub struct VmInstanceRotSocketClient {
    socket: RefCell<UnixStream>,
}

impl VmInstanceRotSocketClient {
    pub fn new(socket: UnixStream) -> Self {
        Self {
            socket: RefCell::new(socket),
        }
    }
}

/// Errors returned when trying to sign an attestation
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceRotSocketClientError {
    #[error("error deserializing a Command from JSON")]
    CommandDeserialize(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),

    #[error("error from the VmInstanceRot: {0}")]
    VmInstanceRot(String),
}

impl VmInstanceAttester for VmInstanceRotSocketClient {
    type Error = VmInstanceRotSocketClientError;

    /// Turn the `QualifyingData` provided into a JSON message that we send
    /// over the socket. We get back a `PlatformAttestation` that we
    /// deserialize from JSON.
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
        let response: Response = serde_json::from_str(&response)?;
        match response {
            Response::Attest(p) => Ok(p),
            Response::Error(e) => Err(Self::Error::VmInstanceRot(e)),
        }
    }
}

/// This type mocks the JSON interface exposed by the VmInstanceRot over a
/// UnixSocket. It holds a `UnixListener` accepts the same JSON encoded
/// messages exchanged between VM instances and the VM instance RoT /
/// `propolis`. These messages are decoded and passed along to the
/// `VmInstanceRot` held by the `VmInstanceRotSocketServer`. Clients connecting
/// to an instance of this type over the unix socket may either implement the
/// message serialization themselves, or use the `VmInstanceRotSocketClient`.
///
/// ```text
/// + ------------------------------+               +--------+
/// | VmInstanceRotSocketServer     |               |        |
/// +---------------+               |     JSON      | Client |
/// | VmInstanceRot | <--> listener | <-unix-sock-> |        |
/// +---------------+---------------+               +--------+
/// ```
pub struct VmInstanceRotSocketServer {
    rot: VmInstanceRot,
    conf: VmInstanceConf,
    listener: UnixListener,
}

/// Possible errors from `VmInstanceAttestSocketServer::run`
#[derive(Debug, thiserror::Error)]
pub enum VmInstanceRotSocketRunError {
    #[error("error from underlying VmInstanceRoT mock")]
    MockRotError(#[from] VmInstanceRotError),

    #[error("failed to deserialize QualifyingData request from JSON")]
    Request(serde_json::Error),

    #[error("failed to serialize response to JSON")]
    Response(#[from] serde_json::Error),

    #[error("error from the underlying socket")]
    Socket(#[from] std::io::Error),
}

impl VmInstanceRotSocketServer {
    pub fn new(
        rot: VmInstanceRot,
        conf: VmInstanceConf,
        listener: UnixListener,
    ) -> Self {
        Self {
            rot,
            conf,
            listener,
        }
    }

    // message handling loop
    pub fn run(&self) -> Result<(), VmInstanceRotSocketRunError> {
        debug!("listening for clients");

        let mut msg = String::new();
        for client in self.listener.incoming() {
            debug!("new client");

            // `incoming` yeilds iterator over a Result
            // we should only receive `QualifyingData` over this interface so
            // we can limit the line length to something reasonable
            let reader = BufReader::with_capacity(MAX_LINE_LENGTH, client?);
            let mut reader = reader.take(MAX_LINE_LENGTH as u64);
            loop {
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
                    Ok(q) => q,
                    Err(e) => {
                        let response = Response::Error(e.to_string());
                        let mut response = serde_json::to_string(&response)?;
                        response.push('\n');
                        debug!("sending error response: {response}");
                        reader
                            .get_mut()
                            .get_mut()
                            .write_all(response.as_bytes())?;
                        return Err(VmInstanceRotSocketRunError::Request(e));
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
