use sawtooth_sdk::messages::processor::TpProcessRequest;
use typed_builder::TypedBuilder;

use super::{
    settings::Settings,
    types::{Guid, SigHash, TxnResult},
    utils::{self, sha512_id},
};

#[allow(dead_code)]
#[derive(TypedBuilder)]
pub struct HandlerContext {
    // #[builder(default)]
    // sighash: Option<SigHash>,
    // #[builder(default)]
    // guid: Option<Guid>,
    #[builder(default = 0)]
    pub tip: u64,
    // #[builder(default = false)]
    // replaying: bool,
    // #[builder(default = false)]
    // transitioning: bool,
    // #[builder(default)]
    // current_state: BTreeMap<State, State>,
    gateway_context: zmq::Context,
    local_gateway_sock: zmq::Socket,
    settings: Settings,
    gateway_endpoint: String,
}

impl HandlerContext {
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

    pub fn gateway_context(&self) -> &zmq::Context {
        &self.gateway_context
    }

    pub fn local_gateway_sock(&self) -> &zmq::Socket {
        &self.local_gateway_sock
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn gateway_endpoint(&self) -> &str {
        &self.gateway_endpoint
    }

    pub fn gateway_context_mut(&mut self) -> &mut zmq::Context {
        &mut self.gateway_context
    }

    pub fn local_gateway_sock_mut(&mut self) -> &mut zmq::Socket {
        &mut self.local_gateway_sock
    }

    pub fn settings_mut(&mut self) -> &mut Settings {
        &mut self.settings
    }

    pub fn gateway_endpoint_mut(&mut self) -> &mut str {
        &mut self.gateway_endpoint
    }

    pub fn get_setting(&self, key: &str) -> Option<String> {
        self.settings.get(key).map(|s| s.clone())
    }
}

#[cfg(test)]
pub mod mocked {
    use super::*;
    mockall::mock! {
        pub HandlerContext {
            pub fn tip(&self) -> u64;

            pub fn sighash(&self, request: &TpProcessRequest) -> TxnResult<SigHash>;
            pub fn guid(&self, request: &TpProcessRequest) -> Guid;
            pub fn gateway_context(&self) -> &zmq::Context;

            pub fn local_gateway_sock(&self) -> &zmq::Socket;

            pub fn settings(&self) -> &Settings;

            pub fn gateway_endpoint(&self) -> &str;

            pub fn gateway_context_mut(&mut self) -> &mut zmq::Context;

            pub fn local_gateway_sock_mut(&mut self) -> &mut zmq::Socket;

            pub fn settings_mut(&mut self) -> &mut Settings;

            pub fn gateway_endpoint_mut(&mut self) -> &mut str;

            pub fn get_setting(&self, key: &str) -> Option<String>;
        }
    }
}
