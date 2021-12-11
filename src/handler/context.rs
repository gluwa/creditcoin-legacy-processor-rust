use std::{iter::repeat, mem};

use crate::handler::{constants::SETTINGS_NAMESPACE, types::CCApplyError};

use super::{
    constants::{EXTERNAL_GATEWAY_TIMEOUT, GATEWAY_TIMEOUT, TX_FEE, TX_FEE_KEY},
    types::{
        CCApplyError::{InternalError, InvalidTransaction},
        Credo, Guid, SigHash, TxnResult,
    },
    utils::{self, sha512_id},
};
use once_cell::unsync::OnceCell;
use sawtooth_sdk::{
    messages::{processor::TpProcessRequest, setting::Setting, Message},
    processor::handler::{ContextError, TransactionContext},
};
use sha2::{Digest, Sha256};

pub struct HandlerContext<'tx> {
    gateway_context: zmq::Context,
    #[cfg(not(all(test, feature = "mock")))]
    local_gateway_sock: zmq::Socket,
    gateway_endpoint: String,
    tx_ctx: &'tx dyn TransactionContext,
    tx_fee: OnceCell<Credo>,
    request: &'tx TpProcessRequest,
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
        request: &'tx TpProcessRequest,
    ) -> TxnResult<Self> {
        Ok(Self {
            #[cfg(not(all(test, feature = "mock")))]
            local_gateway_sock: utils::create_socket(
                &gateway_context,
                &gateway_endpoint,
                GATEWAY_TIMEOUT,
            )?,
            gateway_context,
            gateway_endpoint,
            tx_ctx,
            tx_fee: OnceCell::new(),
            request,
        })
    }

    pub fn sighash(&self, request: &TpProcessRequest) -> TxnResult<SigHash> {
        // skipcq: RS-D1000
        // TODO: transitioning
        let signer = request.get_header().get_signer_public_key();
        let compressed = utils::compress(signer)?;
        let hash = sha512_id(compressed.as_bytes());
        Ok(SigHash(hash))
    }

    pub fn guid(&self, request: &TpProcessRequest) -> Guid {
        // skipcq: RS-D1000
        // TODO: transitioning
        Guid(request.get_header().get_nonce().to_owned())
    }

    fn find_setting(bytes: &[u8], key: &str) -> TxnResult<Option<String>> {
        let setting = Setting::parse_from_bytes(bytes).map_err(|e| {
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
        let inputs = self.request.get_header().get_inputs();
        let client_request = !inputs.into_iter().any(|s| k.starts_with(s));
        if client_request {
            log::warn!("Falling back to a client request - the settings namespace is not declared as a transaction input");
            let state = self.tx_ctx.get_state_entries_by_prefix("", &k);
            match state {
                Ok(state) if !state.is_empty() => {
                    let (_addr, value) = &state[0];
                    Self::find_setting(value, key)
                }
                Ok(state) if state.is_empty() => {
                    log::debug!("setting not found for key {:?}", key);
                    Ok(None)
                }
                Err(ContextError::ResponseAttributeError(_)) => {
                    log::debug!(
                        "received response attribute error, setting not found for key {:?}",
                        key
                    );
                    Ok(None)
                }
                Err(e) => {
                    log::error!("other error {} received getting setting {:?}", e, key);
                    Err(e.into())
                }
                _ => unreachable!(),
            }
        } else {
            let state = self.tx_ctx.get_state_entry(&k);
            match state {
                Ok(Some(value)) => Self::find_setting(&value, key),
                Ok(None) => {
                    log::debug!("no setting found for key {:?}", key);
                    Ok(None)
                }
                Err(e) => Err(e.into()),
            }
        }
    }

    pub fn tx_fee(&self) -> TxnResult<&Credo> {
        self.tx_fee
            .get_or_try_init(|| match self.get_setting(TX_FEE_KEY) {
                Ok(Some(val)) => Credo::try_parse(&val),
                Ok(None) => {
                    log::debug!(
                        "Transaction fee not set in on-chain settings, falling back to default"
                    );
                    Ok(TX_FEE.clone())
                }
                Err(e) => Err(e),
            })
    }

    #[cfg(not(all(test, feature = "mock")))]
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
            log::debug!("Found external gateway address");

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

    #[cfg(not(all(test, feature = "mock")))]
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
    use crate::handler::types::Credo;
    mockall::mock! {
        pub HandlerContext {
            pub fn create(
                gateway_context: zmq::Context,
                gateway_endpoint: String,
                tx_ctx: &dyn TransactionContext,
                request: &TpProcessRequest,
            ) -> TxnResult<Self>;

            pub fn tip(&self) -> u64;

            pub fn sighash(&self, request: &TpProcessRequest) -> TxnResult<SigHash>;
            pub fn guid(&self, request: &TpProcessRequest) -> Guid;

            pub fn get_setting(&self, key: &str) -> TxnResult<Option<String>>;

            pub fn verify(&mut self, gateway_command: &str) -> TxnResult<()>;
        }
    }

    impl MockHandlerContext {
        pub fn tx_fee(&self) -> TxnResult<Credo> {
            Ok(TX_FEE.clone())
        }
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::HandlerContext;
    use crate::handler::{
        constants::{SETTINGS_NAMESPACE, TX_FEE, TX_FEE_KEY},
        tests::mocked::MockTransactionContext,
        types::Credo,
    };
    use sawtooth_sdk::messages::processor::TpProcessRequest;
    use sawtooth_sdk::messages::Message;
    #[test]
    fn tx_fee_fetches_from_chain() {
        let zmq_context = zmq::Context::new();
        let mut mock_tx_ctx = MockTransactionContext::default();
        let mut request = TpProcessRequest::default();
        request
            .mut_header()
            .mut_inputs()
            .push(String::from(SETTINGS_NAMESPACE));
        let k = super::make_settings_key(TX_FEE_KEY);
        let k = &*Box::leak(k.into_boxed_str());
        let mut setting = sawtooth_sdk::messages::setting::Setting::new();
        let mut entry = sawtooth_sdk::messages::setting::Setting_Entry::new();
        entry.set_key(TX_FEE_KEY.into());
        entry.set_value("1".into());
        setting.mut_entries().push(entry);
        let serialized = setting.write_to_bytes().unwrap();
        mock_tx_ctx
            .expect_get_state_entry()
            .with(mockall::predicate::eq(k))
            .returning(move |_| Ok(Some(serialized.clone())));
        let context = HandlerContext::create(
            zmq_context,
            "tcp://dummy:8080".into(),
            &mock_tx_ctx,
            &request,
        )
        .unwrap();
        let result = context.tx_fee().unwrap().clone();
        assert_eq!(result, Credo(1.into()));
    }
    #[test]
    fn tx_fee_falls_back_to_default() {
        let zmq_context = zmq::Context::new();
        let mut mock_tx_ctx = MockTransactionContext::default();
        let k = super::make_settings_key(TX_FEE_KEY);
        let k = &*Box::leak(k.into_boxed_str());
        let mut request = TpProcessRequest::default();
        request
            .mut_header()
            .mut_inputs()
            .push(String::from(SETTINGS_NAMESPACE));
        mock_tx_ctx
            .expect_get_state_entry()
            .with(mockall::predicate::eq(k))
            .returning(move |_| Ok(None));
        let context = HandlerContext::create(
            zmq_context,
            "tcp://dummy:8080".into(),
            &mock_tx_ctx,
            &request,
        )
        .unwrap();
        let result = context.tx_fee().unwrap().clone();
        assert_eq!(&result, &*TX_FEE);
    }
}
