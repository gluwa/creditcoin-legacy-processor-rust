use std::convert::TryFrom;
use std::fmt;
use std::ops::Add;
use std::ops::Deref;
use std::ops::Div;
use std::ops::Sub;

use derive_more::{From, Into};
use rug::integer::SmallInteger;
use rug::Integer;

use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::ContextError;

use crate::handler::constants::*;
use crate::handler::utils::sha512_id;
use crate::string;

pub type TxnResult<T, E = anyhow::Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum CCApplyError {
    InvalidTransaction(String),
    InternalError(String),
}

impl fmt::Display for CCApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            CCApplyError::InvalidTransaction(e) => write!(f, "{}", e),
            CCApplyError::InternalError(e) => write!(f, "Internal error: {}", e),
        }
    }
}

impl From<CCApplyError> for ApplyError {
    fn from(err: CCApplyError) -> Self {
        match err {
            CCApplyError::InvalidTransaction(e) => ApplyError::InvalidTransaction(e),
            CCApplyError::InternalError(e) => ApplyError::InternalError(e),
        }
    }
}

impl std::error::Error for CCApplyError {}

impl From<ContextError> for CCApplyError {
    fn from(context_error: ContextError) -> Self {
        match context_error {
            ContextError::TransactionReceiptError(..) => {
                CCApplyError::InternalError(format!("{}", context_error))
            }
            _ => CCApplyError::InvalidTransaction(format!("{}", context_error)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, From, Into, Default)]
pub struct SigHash(pub String);

impl From<&str> for SigHash {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

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

impl fmt::Display for SigHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
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

impl From<SigHash> for WalletId {
    fn from(sig: SigHash) -> Self {
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

impl From<&str> for Guid {
    fn from(s: &str) -> Self {
        Guid(s.to_string())
    }
}

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

impl From<&Address> for String {
    fn from(address: &Address) -> String {
        address.0.clone()
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, From, Default)]
pub struct CurrencyAmount(pub Integer);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, From, Default)]
pub struct BlockNum(pub u64);

impl BlockNum {
    pub fn new() -> Self {
        Self(0)
    }
}

impl fmt::Display for BlockNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<&str> for BlockNum {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        println!("value = {:?}", value);
        if value.contains('-') {
            println!("It's negative!");
            return Err(CCApplyError::InvalidTransaction(NEGATIVE_NUMBER_ERR.into()))?;
        }
        Ok(BlockNum(value.parse::<u64>().map_err(|_e| {
            anyhow::Error::from(CCApplyError::InvalidTransaction(INVALID_NUMBER_ERR.into()))
        })?))
    }
}

impl TryFrom<&String> for BlockNum {
    type Error = anyhow::Error;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        <Self as TryFrom<&str>>::try_from(&*value)
    }
}

impl Add<u64> for BlockNum {
    type Output = BlockNum;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}
impl Sub<u64> for BlockNum {
    type Output = TxnResult<BlockNum>;

    fn sub(self, rhs: u64) -> Self::Output {
        Ok(Self(self.0.checked_sub(rhs).ok_or_else(|| {
            CCApplyError::InvalidTransaction(
                "The subtraction would have resulted in overflow".into(),
            )
        })?))
    }
}
impl Add<BlockNum> for BlockNum {
    type Output = BlockNum;

    fn add(self, rhs: BlockNum) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}
impl Add<&BlockNum> for BlockNum {
    type Output = BlockNum;

    fn add(self, rhs: &BlockNum) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}
impl Sub<&BlockNum> for BlockNum {
    type Output = TxnResult<BlockNum>;

    fn sub(self, rhs: &BlockNum) -> Self::Output {
        Ok(Self(self.0.checked_sub(rhs.0).ok_or_else(|| {
            CCApplyError::InvalidTransaction(
                "The subtraction would have resulted in overflow".into(),
            )
        })?))
    }
}
impl Sub<BlockNum> for BlockNum {
    type Output = TxnResult<BlockNum>;

    fn sub(self, rhs: BlockNum) -> Self::Output {
        Ok(Self(self.0.checked_sub(rhs.0).ok_or_else(|| {
            CCApplyError::InvalidTransaction(
                "The subtraction would have resulted in overflow".into(),
            )
        })?))
    }
}
impl PartialEq<u64> for BlockNum {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}
impl PartialEq<BlockNum> for u64 {
    fn eq(&self, other: &BlockNum) -> bool {
        *self == other.0
    }
}
impl PartialOrd<u64> for BlockNum {
    fn partial_cmp(&self, other: &u64) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}
impl PartialOrd<BlockNum> for u64 {
    fn partial_cmp(&self, other: &BlockNum) -> Option<std::cmp::Ordering> {
        self.partial_cmp(&other.0)
    }
}
impl Div<BlockNum> for BlockNum {
    type Output = BlockNum;

    fn div(self, rhs: BlockNum) -> Self::Output {
        Self(self.0 / rhs.0)
    }
}
impl From<BlockNum> for SmallInteger {
    fn from(value: BlockNum) -> Self {
        SmallInteger::from(value.0)
    }
}
impl From<BlockNum> for u64 {
    fn from(value: BlockNum) -> Self {
        value.0
    }
}
