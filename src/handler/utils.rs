use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::Write;

use crate::ext::IntegerExt;
use crate::ext::MessageExt;
use crate::handler::constants::BLOCKS_IN_PERIOD_UPDATE1;
use crate::protos::Wallet;

use prost::Message;
use rug::Assign;
use rug::Integer;
use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::TransactionContext;
use serde_cbor::Value;
use sha2::{Digest, Sha512};

use crate::handler::constants::{
    MERKLE_ADDRESS_LENGTH, NAMESPACE_PREFIX_LENGTH, PREFIX_LENGTH, SKIP_TO_GET_60,
};

use super::constants::INTEREST_MULTIPLIER;
use super::constants::INVALID_NUMBER_FORMAT_ERR;
use super::constants::REWARD_AMOUNT;
use super::types::CCApplyError::InvalidTransaction;
use super::types::Credo;
use super::types::CurrencyAmount;
use super::types::State;
use super::types::StateVec;
use super::types::WalletId;
use super::types::{Address, CCApplyError};
use super::types::{BlockInterval, BlockNum};
use super::types::{SigHash, TxnResult};
use super::HandlerContext;

#[macro_export]
macro_rules! bail_transaction {
    (makeit $e: expr) => {
        core::result::Result::Err(
            crate::handler::types::CCApplyError::InvalidTransaction(($e).into()),
        )
    };
    ($s: expr) => {
        return bail_transaction!(makeit $s)?
    };

    ($s: expr, context = $c: expr) => {
        use anyhow::Context;
        return bail_transaction!(makeit $s).map_err(anyhow::Error::from).context($c)
    };
    ($s: literal, context = $c: literal, $($t2: tt),*) => {
        bail_transaction!($s, context = format!($c, $($t2),*))
    };
    ($s: literal, $($t1: tt),* context = $c: literal, $($t2: tt),*) => {
        bail_transaction!(format!($s, $($t1),*), context = format!($c, $($t2),*))
    };
    ($s: literal, $($t: tt),*) => {
        bail_transaction!(makeit (format!($s, $($t),*)))?
    };
}

#[macro_export]
macro_rules! string {
    ($($s: expr),+ $(,)?) => {
        {
            let mut capacity = 0;
            $( capacity += $s.len(); )*

            let mut string = ::std::string::String::with_capacity(capacity);
            $(
                string.push_str(&*$s);
            )*
            string
        }
    };
}

pub fn get_string<'a>(
    map: &'a BTreeMap<Value, Value>,
    key: &str,
    name: &str,
) -> TxnResult<&'a String> {
    match map.get(&Value::Text(key.into())) {
        Some(Value::Text(text)) => Ok(text),
        Some(value) => {
            bail_transaction!("Value for {} was not a string, found : {:?}", name, value)
        }
        None => {
            bail_transaction!("Expecting {}", name)
        }
    }
}

pub fn get_integer_string<'a>(
    map: &'a BTreeMap<Value, Value>,
    key: &str,
    name: &str,
) -> TxnResult<&'a String> {
    let s = get_string(map, key, name)?;
    Integer::try_parse(s)?;
    Ok(s)
}

pub fn get_integer(map: &BTreeMap<Value, Value>, key: &str, name: &str) -> TxnResult<Integer> {
    let str_value = get_string(map, key, name)?;
    Integer::try_parse(str_value)
}

pub fn get_signed_integer(
    map: &BTreeMap<Value, Value>,
    key: &str,
    name: &str,
) -> TxnResult<Integer> {
    let str_value = get_string(map, key, name)?;
    Integer::try_parse_signed(str_value)
}

pub fn get_u64(map: &BTreeMap<Value, Value>, key: &str, name: &str) -> TxnResult<u64> {
    let str_value = get_string(map, key, name)?;
    str_value
        .parse()
        .map_err(|_| CCApplyError::InvalidTransaction(INVALID_NUMBER_FORMAT_ERR.into()).into())
}

pub fn get_block_num(map: &BTreeMap<Value, Value>, key: &str, name: &str) -> TxnResult<BlockNum> {
    let str_value = get_string(map, key, name)?;
    if str_value.is_empty() {
        Ok(BlockNum::new())
    } else {
        BlockNum::try_from(str_value)
    }
}

#[test]
fn get_block_num_basic() {
    let mut map = BTreeMap::new();
    map.insert(Value::Text("key".into()), Value::Text("3".into()));

    assert_eq!(
        get_block_num(&map, "key", "name").unwrap(),
        BlockNum::from(3)
    );
}

#[test]
fn get_block_num_empty_string() {
    let mut map = BTreeMap::new();
    map.insert(Value::Text("key".into()), Value::Text(String::new()));

    assert_eq!(get_block_num(&map, "key", "name").unwrap(), BlockNum::new());
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    let mut buf = String::with_capacity(2 * bytes.len());
    for b in bytes {
        write!(buf, "{:02x}", b).unwrap();
    }
    buf
}

pub fn sha512_id<B: AsRef<[u8]>>(bytes: B) -> String {
    let res = sha512(bytes);
    let ret = &res[SKIP_TO_GET_60..];
    assert_eq!(
        ret.len(),
        MERKLE_ADDRESS_LENGTH - NAMESPACE_PREFIX_LENGTH - PREFIX_LENGTH
    );
    ret.to_owned()
}

pub fn sha512_bytes<B: AsRef<[u8]>>(bytes: B) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result.to_vec()
}

pub fn sha512<B: AsRef<[u8]>>(bytes: B) -> String {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    to_hex_string(&result)
}

pub fn is_hex(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[test]
fn is_hex_accepts_hex() {
    assert!(is_hex("abcdefABCDEF1234567890"));
    assert!(is_hex(""));
}

#[test]
fn is_hex_rejects_nonhex() {
    assert!(!is_hex("g1234567890"));
}

pub fn compress(uncompressed: &str) -> TxnResult<String> {
    let marker = &uncompressed[..2];
    if uncompressed.len() == 2 * (1 + 2 * 32) && is_hex(uncompressed) && marker == "04" {
        let x = &uncompressed[2..][..(2 * 32)];
        let y_last = &uncompressed[2 * (1 + 32 + 31)..][..2];
        let last = i32::from_str_radix(y_last, 16)
            .map_err(|_| CCApplyError::InvalidTransaction("Unexpected public key format".into()))?;
        let mut compressed = String::with_capacity(2 + x.len());

        if last % 2 == 1 {
            compressed.push_str("03");
        } else {
            compressed.push_str("02");
        }
        compressed.push_str(x);
        Ok(compressed)
    } else if (marker == "02" || marker == "03") && uncompressed.len() == 66 {
        Ok(uncompressed.to_owned())
    } else {
        Err(CCApplyError::InvalidTransaction(
            "Unexpected public key format".into(),
        ))?
    }
}

pub fn params_from_bytes(bytes: &[u8]) -> anyhow::Result<Value> {
    let res = serde_cbor::from_slice(bytes)?;
    Ok(res)
}

pub fn create_socket(
    zmq_context: &zmq::Context,
    endpoint: &str,
    timeout: i32,
) -> TxnResult<zmq::Socket> {
    let sock = zmq_context
        .socket(zmq::SocketType::REQ)
        .map_err(|e| CCApplyError::InternalError(format!("Failed to create socket : {}", e)))?;
    sock.connect(endpoint).map_err(|e| {
        CCApplyError::InternalError(format!("Failed to connect socket to endpoint : {}", e))
    })?;
    sock.set_rcvtimeo(timeout).map_err(|e| {
        CCApplyError::InternalError(format!("Failed to set socket receive timeout : {}", e))
    })?;
    sock.set_sndtimeo(timeout).map_err(|e| {
        CCApplyError::InternalError(format!("Failed to set socket send timeout : {}", e))
    })?;
    sock.set_linger(0)
        .map_err(|e| CCApplyError::InternalError(format!("Failed to set socket linger : {}", e)))?;
    Ok(sock)
}

pub fn last_block(request: &TpProcessRequest) -> BlockNum {
    // skipcq: RS-D1000
    // TODO: transitioning
    let tip = request.get_tip();
    if tip == 0 {
        log::warn!("tip was 0");
        BlockNum(0)
    } else {
        BlockNum(tip - 1)
    }
}

pub fn get_state_data<A: AsRef<str>>(
    tx_ctx: &dyn TransactionContext,
    address: A,
) -> TxnResult<State> {
    let address = address.as_ref();
    let state_data = match tx_ctx.get_state_entry(address) {
        Ok(data) => data.ok_or_else(|| {
            CCApplyError::InvalidTransaction(format!("Existing state expected {}", address))
        }),
        Err(sawtooth_sdk::processor::handler::ContextError::AuthorizationError(s)) => {
            log::warn!(
                "Received authorization error from validator, the address may be invalid: {}",
                s
            );
            Err(CCApplyError::InvalidTransaction(format!(
                "Existing state expected {}",
                address
            )))?
        }
        Err(e) => Err(CCApplyError::from(e))?,
    }?;
    Ok(state_data.into())
}

pub fn try_get_state_data<A: AsRef<str>>(
    tx_ctx: &dyn TransactionContext,
    address: A,
) -> TxnResult<Option<State>> {
    let address = address.as_ref();
    Ok(tx_ctx
        .get_state_entry(address)
        .map_err(CCApplyError::from)?
        .map(Into::into))
}

pub fn add_state<M: Message>(states: &mut StateVec, id: String, message: &M) -> TxnResult<()> {
    let mut buf = Vec::with_capacity(message.encoded_len());
    message
        .encode(&mut buf)
        .map_err(|e| CCApplyError::InvalidTransaction(format!("Failed to add state : {}", e)))?;
    states.push((id, buf));
    Ok(())
}

pub fn add_fee(
    ctx: &mut HandlerContext,
    request: &TpProcessRequest,
    sighash: &SigHash,
    states: &mut StateVec,
) -> TxnResult<()> {
    let guid = ctx.guid(request);
    let fee_id = Address::with_prefix_key(super::constants::FEE, guid.as_str());
    let fee = crate::protos::Fee {
        sighash: sighash.clone().into(),
        block: last_block(request).to_string(),
    };
    add_state(states, fee_id.into(), &fee)
}

pub fn add_fee_state(
    ctx: &mut HandlerContext,
    request: &TpProcessRequest,
    sighash: &SigHash,
    states: &mut StateVec,
    wallet_id: &WalletId,
    wallet: &crate::protos::Wallet,
) -> TxnResult<()> {
    add_fee(ctx, request, sighash, states)?;
    add_state(states, wallet_id.clone().into(), wallet)
}

pub fn calc_interest(
    amount: &CurrencyAmount,
    ticks: BlockInterval,
    interest: &CurrencyAmount,
) -> CurrencyAmount {
    let mut total = amount.clone();
    let mut i = 0;

    while i < ticks {
        let compound = (total.clone() * interest) / INTEREST_MULTIPLIER;
        total += compound;
        i += 1;
    }
    total
}

fn calc_reward(new_formula: bool, block_idx: BlockNum) -> TxnResult<Credo> {
    let mut buf = Integer::new();
    let mut reward = Credo::new();

    if new_formula {
        buf.assign((block_idx / BLOCKS_IN_PERIOD_UPDATE1).0);

        let period = buf.to_i32().ok_or_else(|| {
            InvalidTransaction("Block number is too large to fit in an i32".into())
        })?;
        let fraction = (19.0f64 / 20.0f64).powi(period);
        let fraction_str = format!("{:.6}", fraction);
        let pos = fraction_str.find('.').unwrap();
        assert!(pos > 0);

        let fraction_in_wei_str = if fraction_str.starts_with('0') {
            let mut pos = 2;
            for c in fraction_str.bytes().skip(pos) {
                if c == b'0' {
                    pos += 1;
                } else {
                    break;
                }
            }
            format!("{:0<width$}", &fraction_str[pos..], width = 20 - pos)
        } else {
            format!("{}{:0<18}", &fraction_str[..pos], &fraction_str[pos + 1..])
        };

        reward.assign(Credo::try_parse(&fraction_in_wei_str)? * 28u64);
    } else {
        reward.assign(&*REWARD_AMOUNT);
    }
    Ok(reward.into())
}

#[test]
fn reward_calculation_old_formula() {
    assert_eq!(calc_reward(false, BlockNum(1)).unwrap(), &*REWARD_AMOUNT);
}

#[test]
fn reward_calculation_new_formula() {
    assert_eq!(
        calc_reward(true, BlockNum(1)).unwrap(),
        Credo::try_parse("1_000_000_000_000_000_000").unwrap() * 28
    );

    assert_eq!(
        calc_reward(true, BLOCKS_IN_PERIOD_UPDATE1).unwrap(),
        Credo::try_parse("950_000_000_000_000_000").unwrap() * 28
    );
}

pub(crate) fn award(
    tx_ctx: &dyn TransactionContext,
    new_formula: bool,
    block_idx: BlockNum,
    signer: &str,
) -> TxnResult<()> {
    let reward = calc_reward(new_formula, block_idx)?;
    let reward_str = reward.to_string();

    if reward > 0 {
        let sighash = SigHash::from_public_key(signer)?;
        let wallet_id = sighash.to_wallet_id();
        let state_data = try_get_state_data(tx_ctx, &wallet_id)?.unwrap_or_default();
        let wallet = if state_data.is_empty() {
            Wallet { amount: reward_str }
        } else {
            let wallet = Wallet::try_parse(&state_data)?;
            let balance = Credo::from_wallet(&wallet)? + reward;
            Wallet {
                amount: balance.to_string(),
            }
        };

        let mut buf = Vec::with_capacity(wallet.encoded_len());
        wallet
            .encode(&mut buf)
            .map_err(|e| InvalidTransaction(format!("Failed to add state : {}", e)))?;
        tx_ctx.set_state_entry(wallet_id.into(), buf)?;
    }
    Ok(())
}
