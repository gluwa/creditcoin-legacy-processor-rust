use std::{iter::repeat, mem};

use crate::{
    ext::IntegerExt,
    handler::{constants::SETTINGS_NAMESPACE, types::CCApplyError},
};

use super::{
    constants::{EXTERNAL_GATEWAY_TIMEOUT, GATEWAY_TIMEOUT, TX_FEE, TX_FEE_KEY},
    types::{
        CCApplyError::{InternalError, InvalidTransaction},
        Guid, SigHash, TxnResult,
    },
    utils::{self, sha512_id},
};
use once_cell::unsync::OnceCell;
use rug::Integer;
use sawtooth_sdk::{
    messages::{processor::TpProcessRequest, setting::Setting, Message},
    processor::handler::{ContextError, TransactionContext},
};
use sha2::{Digest, Sha256};

pub struct HandlerContext<'tx> {
    // sighash: Option<SigHash>,
    // guid: Option<Guid>,
    // replaying: bool,
    // transitioning: bool,
    // current_state: BTreeMap<State, State>,
    tip: u64,
    gateway_context: zmq::Context,
    local_gateway_sock: zmq::Socket,
    gateway_endpoint: String,
    tx_ctx: &'tx dyn TransactionContext,
    tx_fee: OnceCell<Integer>,
}

const MAX_KEY_PARTS: usize = 4;
const ADDRESS_PART_SIZE: usize = 16;

fn make_settings_key(key: &str) -> String {
    let mut address = String::new();
    address.push_str(SETTINGS_NAMESPACE);
    address.push_str(
        &key.splitn(MAX_KEY_PARTS, '.')
            .chain(repeat(""))
            .map(short_hash)
            .take(MAX_KEY_PARTS)
            .collect::<Vec<_>>()
            .join(""),
    );

    address
}

fn short_hash(s: &str) -> String {
    let mut sha = Sha256::new();
    sha.update(s.as_bytes());
    let result = hex::encode(sha.finalize());
    result[..ADDRESS_PART_SIZE].to_owned()
}

impl<'tx> HandlerContext<'tx> {
    pub fn create(
        gateway_context: zmq::Context,
        gateway_endpoint: String,
        tx_ctx: &'tx dyn TransactionContext,
    ) -> TxnResult<Self> {
        Ok(Self {
            local_gateway_sock: utils::create_socket(
                &gateway_context,
                &gateway_endpoint,
                GATEWAY_TIMEOUT,
            )?,
            gateway_context,
            gateway_endpoint,
            tx_ctx,
            tip: 0,
            tx_fee: OnceCell::new(),
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

    fn find_setting(bytes: &[u8], key: &str) -> TxnResult<Option<String>> {
        let setting = Setting::parse_from_bytes(&bytes).map_err(|e| {
            CCApplyError::InternalError(format!("Failed to parse setting from bytes: {}", e))
        })?;
        for entry in setting.get_entries() {
            if entry.get_key() == key {
                return Ok(Some(entry.get_value().to_owned()));
            }
        }
        Ok(None)
    }

    pub fn get_setting(&self, key: &str) -> TxnResult<Option<String>> {
        log::debug!("getting setting for key {:?}", key);
        let k = make_settings_key(key);
        let state = self.tx_ctx.get_state_entry(&k);
        match state {
            Ok(Some(value)) => Self::find_setting(&value, key),
            Ok(None) => {
                log::debug!("no setting found for key {:?}", key);
                Ok(None)
            }
            Err(ContextError::AuthorizationError(_)) => {
                log::warn!("Falling back to a client request - the settings namespace is not declared as a transaction input");
                let state = self.tx_ctx.get_state_entries_by_prefix(&k)?;
                if state.is_empty() {
                    log::debug!("setting not found for key {:?}", key);
                    Ok(None)
                } else {
                    let (_addr, value) = &state[0];
                    Self::find_setting(&value, key)
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn tx_fee(&self) -> TxnResult<&Integer> {
        self.tx_fee
            .get_or_try_init(|| match self.get_setting(TX_FEE_KEY) {
                Ok(Some(val)) => Integer::try_parse(&val),
                Ok(None) => {
                    log::debug!(
                        "Transaction fee not set in on-chain settings, falling back to default"
                    );
                    Ok(TX_FEE.clone())
                }
                Err(e) => Err(e),
            })
    }

    fn try_verify_external(&mut self, gateway_command: &str) -> TxnResult<Option<String>> {
        log::warn!("Falling back to external gateway");
        let new_local_sock = utils::create_socket(
            &self.gateway_context,
            &self.gateway_endpoint,
            GATEWAY_TIMEOUT,
        )?;
        mem::drop(mem::replace(&mut self.local_gateway_sock, new_local_sock));

        let address = self.get_setting("sawtooth.validator.gateway")?;

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
                tx_ctx: &dyn TransactionContext,
            ) -> TxnResult<Self>;

            pub fn tip(&self) -> u64;

            pub fn sighash(&self, request: &TpProcessRequest) -> TxnResult<SigHash>;
            pub fn guid(&self, request: &TpProcessRequest) -> Guid;

            pub fn get_setting(&self, key: &str) -> TxnResult<Option<String>>;

            pub fn verify(&mut self, gateway_command: &str) -> TxnResult<()>;
        }
    }

    impl MockHandlerContext {
        pub fn tx_fee(&self) -> TxnResult<Integer> {
            Ok(TX_FEE.clone())
        }
    }
}
