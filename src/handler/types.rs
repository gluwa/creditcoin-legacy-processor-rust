use std::ops::Deref;

use derive_more::{From, Into};
use rug::Integer;

use crate::handler::constants::*;
use crate::handler::utils::sha512_id;
use crate::string;

pub type TxnResult<T, E = anyhow::Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, From, Into, Default)]
pub struct SigHash(pub String);

impl SigHash {
    pub fn to_wallet_id(&self) -> WalletId {
        let wallet_id = string!(NAMESPACE_PREFIX, WALLET, self);
        wallet_id.into()
    }
}

impl Deref for SigHash {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, From, Into, Default)]
pub struct WalletId(pub String);

impl From<&SigHash> for WalletId {
    fn from(sig: &SigHash) -> Self {
        let buf = string!(NAMESPACE_PREFIX, WALLET, sig.as_str());
        WalletId(buf)
    }
}

impl Deref for WalletId {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for WalletId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, From, Into, Default)]
pub struct Guid(pub String);

impl Deref for Guid {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, From, Into, Default)]
pub struct Address(pub String);

impl Address {
    pub fn with_prefix_key(prefix: &str, key: &str) -> Self {
        let id = sha512_id(key);
        let addr = string!(NAMESPACE_PREFIX, prefix, &id);
        assert_eq!(addr.len(), MERKLE_ADDRESS_LENGTH);
        Self(addr)
    }
}

impl Deref for Address {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for Address {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, From, Into, Default)]
pub struct State(pub Vec<u8>);

impl Deref for State {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for State {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

pub type StateVec = Vec<(String, Vec<u8>)>;

// #[derive(Shrinkwrap, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, From, Default)]
// #[from(forward)]
// pub struct BlockNum(Integer);

pub type BlockNum = Integer;
