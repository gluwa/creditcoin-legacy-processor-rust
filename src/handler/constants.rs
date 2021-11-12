use std::time::Duration;

use once_cell::sync::Lazy;
use rug::Integer;

pub const NAMESPACE: &str = "CREDITCOIN";
pub const NAMESPACE_PREFIX_LENGTH: usize = 6;
pub const MERKLE_ADDRESS_LENGTH: usize = 70;
pub const PREFIX_LENGTH: usize = 4;
pub const WALLET: &str = "0000";
pub const ADDR: &str = "1000";
pub const TRANSFER: &str = "2000";
pub const ASK_ORDER: &str = "3000";
pub const BID_ORDER: &str = "4000";
pub const DEAL_ORDER: &str = "5000";
pub const REPAYMENT_ORDER: &str = "6000";
pub const OFFER: &str = "7000";
pub const ERC20: &str = "8000";
pub const PROCESSED_BLOCK: &str = "9000";
pub const FEE: &str = "0100";
pub const SETTINGS_NAMESPACE: &str = "000000";

pub const PROCESSED_BLOCK_ID: &str = "000000000000000000000000000000000000000000000000000000000000";

pub const INTEREST_MULTIPLIER: u64 = 1000000;
pub const CONFIRMATION_COUNT: u64 = 30;
pub const YEAR_OF_BLOCKS: u64 = 60 * 24 * 365;

pub const BLOCKS_IN_PERIOD_UPDATE1: u64 = 2500000;

pub const BLOCK_REWARD_PROCESSING_COUNT: u64 = 10;

pub const SKIP_TO_GET_60: usize = 512 / 8 * 2 - 60; // 512 - hash size in bits, 8 - bits in byte, 2 - hex digits for byte, 60 - merkle address length (70) without namespace length (6) and prexix length (4)

pub const DEAL_EXP_FIX_BLOCK: u64 = 278890;

pub const GATEWAY_TIMEOUT: i32 = 5000;
pub const EXTERNAL_GATEWAY_TIMEOUT: i32 = 25000;

pub const MESSAGE_TIMEOUT: Duration = Duration::from_secs(6);

// For debugging
// pub const GATEWAY_TIMEOUT: i32 = 10000;

pub static NAMESPACE_PREFIX: Lazy<String> = Lazy::new(|| {
    let ns = super::utils::sha512(NAMESPACE);
    String::from(&ns[..NAMESPACE_PREFIX_LENGTH])
});

pub static DEAL_ORDER_PREFIX: Lazy<String> = Lazy::new(|| {
    let mut s = NAMESPACE_PREFIX.clone();
    s.push_str(DEAL_ORDER);
    s
});

pub static REPAYMENT_ORDER_PREFIX: Lazy<String> = Lazy::new(|| {
    let mut s = NAMESPACE_PREFIX.clone();
    s.push_str(REPAYMENT_ORDER);
    s
});

pub const TX_FEE_KEY: &str = "sawtooth.validator.fee";
pub const TX_FEE_STRING: &str = "10000000000000000";

pub static TX_FEE: Lazy<Integer> =
    Lazy::new(|| Integer::from_str_radix(TX_FEE_STRING, 10).unwrap());

pub const REWARD_AMOUNT_STRING: &str = "222000000000000000000";

pub static REWARD_AMOUNT: Lazy<Integer> =
    Lazy::new(|| Integer::from_str_radix(REWARD_AMOUNT_STRING, 10).unwrap());

// Error messages

pub const INVALID_NUMBER_ERR: &str = "Invalid number";
pub const INVALID_NUMBER_FORMAT_ERR: &str = "Invalid number format";
pub const NEGATIVE_NUMBER_ERR: &str = "Expecting a positive value";
