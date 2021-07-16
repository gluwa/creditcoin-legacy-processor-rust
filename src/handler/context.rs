use std::mem;

use super::{
    constants::{EXTERNAL_GATEWAY_TIMEOUT, GATEWAY_TIMEOUT},
    settings::Settings,
    types::{
        CCApplyError::{InternalError, InvalidTransaction},
        Guid, SigHash, TxnResult,
    },
    utils::{self, sha512_id},
};
use crate::sdk::messages::processor::TpProcessRequest;

pub struct HandlerContext {
    // sighash: Option<SigHash>,
    // guid: Option<Guid>,
    // replaying: bool,
    // transitioning: bool,
    // current_state: BTreeMap<State, State>,
    tip: u64,
    gateway_context: zmq::Context,
    local_gateway_sock: zmq::Socket,
    settings: Settings,
    gateway_endpoint: String,
}

impl HandlerContext {
    pub fn create(
        gateway_context: zmq::Context,
        gateway_endpoint: String,
        settings: Settings,
    ) -> TxnResult<Self> {
        Ok(Self {
            local_gateway_sock: utils::create_socket(
                &gateway_context,
                &gateway_endpoint,
                GATEWAY_TIMEOUT,
            )?,
            gateway_context,
            gateway_endpoint,
            settings,
            tip: 0,
        })
    }

    pub fn tip(&self) -> u64 {
        self.tip
    }

    pub fn sighash(&self, request: &TpProcessRequest) -> TxnResult<SigHash> {
        // TODO: transitioning
        let signer = request.get_header().get_signer_public_key();
        let compressed = utils::compress(signer)?;
        let hash = sha512_id(compressed.as_bytes());
        Ok(SigHash(hash))
    }

    pub fn guid(&self, request: &TpProcessRequest) -> Guid {
        // TODO: transitioning
        Guid(request.get_header().get_nonce().to_owned())
    }

    pub fn get_setting(&self, key: &str) -> Option<String> {
        self.settings.get(key).map(|s| s.clone())
    }

    fn try_verify_external(&mut self, gateway_command: &str) -> TxnResult<Option<String>> {
        log::warn!("Falling back to external gateway");
        let new_local_sock = utils::create_socket(
            &self.gateway_context,
            &self.gateway_endpoint,
            GATEWAY_TIMEOUT,
        )?;
        mem::drop(mem::replace(&mut self.local_gateway_sock, new_local_sock));

        let address = self.get_setting("sawtooth.validator.gateway");

        if let Some(mut external_gateway_address) = address {
            log::info!("Found external gateway address");

            if !external_gateway_address.starts_with("tcp://") {
                external_gateway_address.insert_str(0, "tcp://");
            }

            let external_gateway_sock = utils::create_socket(
                &self.gateway_context,
                &external_gateway_address,
                EXTERNAL_GATEWAY_TIMEOUT,
            )?;
            external_gateway_sock
                .send(gateway_command, 0)
                .map_err(|e| {
                    InternalError(format!(
                        "Failed to send command to external gateway : {}",
                        e
                    ))
                })?;
            let external_response = external_gateway_sock
                .recv_string(0)
                .map_err(|e| {
                    InternalError(format!(
                        "Failed to receive response from external gateway : {}",
                        e
                    ))
                })?
                .map_err(|_| InternalError("External gateway response was invalid UTF-8".into()))?;
            Ok(Some(external_response))
        } else {
            Ok(None)
        }
    }

    pub fn verify(&mut self, gateway_command: &str) -> TxnResult<()> {
        self.local_gateway_sock
            .send(gateway_command, 0)
            .map_err(|e| InternalError(format!("Failed to send command to gateway : {}", e)))?;
        let response = self.local_gateway_sock.recv_string(0);
        let response = match response {
            Ok(Ok(s)) if s.is_empty() || s == "miss" => {
                self.try_verify_external(gateway_command)?.unwrap_or(s)
            }
            Err(_) => self.try_verify_external(gateway_command)?.ok_or_else(|| {
                InternalError("Both local and external gateways were inaccessible".into())
            })?,
            Ok(Ok(s)) => s,
            Ok(Err(_)) => {
                return Err(InvalidTransaction(
                    "Gateway response was invalid UTF-8".into(),
                ))?;
            }
        };

        if response == "good" {
            Ok(())
        } else {
            log::warn!(
                "Gateway failed to validate transaction, got response: {}",
                response
            );
            Err(InvalidTransaction(
                "Couldn't validate the transaction".into(),
            ))?
        }
    }
}

#[cfg(all(test, feature = "mock"))]
pub mod mocked {
    use super::*;
    mockall::mock! {
        pub HandlerContext {
            pub fn create(
                gateway_context: zmq::Context,
                gateway_endpoint: String,
                settings: Settings,
            ) -> TxnResult<Self>;

            pub fn tip(&self) -> u64;

            pub fn sighash(&self, request: &TpProcessRequest) -> TxnResult<SigHash>;
            pub fn guid(&self, request: &TpProcessRequest) -> Guid;

            pub fn get_setting(&self, key: &str) -> Option<String>;

            pub fn verify(&mut self, gateway_command: &str) -> TxnResult<()>;
        }
    }
}
