#![cfg(test)]
#![allow(non_snake_case, non_upper_case_globals)]

use std::sync::Once;

use mockall::predicate;
use prost::Message;
use rug::Integer;
use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::TransactionContext;

use crate::ext::MessageExt;
use crate::handler::constants::*;
use crate::handler::settings::Settings;
use crate::handler::types::SigHash;
use crate::handler::types::WalletId;
use crate::handler::utils;
use crate::string;

use super::context::mocked::MockHandlerContext;
use super::{CCTransaction, Housekeeping};

use mockall::mock;

mock! {
    TransactionContext {}

    impl TransactionContext for TransactionContext {
        fn get_state_entry(&self, address: &str) -> Result<Option<Vec<u8>>, sawtooth_sdk::processor::handler::ContextError>;

        fn get_state_entries(
            &self,
            addresses: &[String],
        ) -> Result<Vec<(String, Vec<u8>)>, sawtooth_sdk::processor::handler::ContextError>;

        fn set_state_entry(
            &self,
            address: String,
            data: Vec<u8>,
        ) -> Result<(), sawtooth_sdk::processor::handler::ContextError>;

        fn set_state_entries(&self, entries: Vec<(String, Vec<u8>)>) -> Result<(), sawtooth_sdk::processor::handler::ContextError>;

        fn delete_state_entry(
            &self,
            address: &str,
        ) -> Result<Option<String>, sawtooth_sdk::processor::handler::ContextError>;

        fn delete_state_entries(&self, addresses: &[String]) -> Result<Vec<String>, sawtooth_sdk::processor::handler::ContextError> ;

        fn add_receipt_data(&self, data: &[u8]) -> Result<(), sawtooth_sdk::processor::handler::ContextError> ;

        fn add_event(
            &self,
            event_type: String,
            attributes: Vec<(String, String)>,
            data: &[u8],
        ) -> Result<(), sawtooth_sdk::processor::handler::ContextError> ;

        fn get_sig_by_num(&self, block_num: u64) -> Result<String, sawtooth_sdk::processor::handler::ContextError> ;

        fn get_reward_block_signatures(
            &self,
            block_id: &str,
            first_pred: u64,
            last_pred: u64,
        ) -> Result<Vec<String>, sawtooth_sdk::processor::handler::ContextError> ;

        fn get_state_entries_by_prefix(
            &self,
            address: &str,
        ) -> Result<Vec<(String, Vec<u8>)>, sawtooth_sdk::processor::handler::ContextError> ;
    }
}

mock! {
    Settings {
        pub fn get(&self, key: &str) -> Option<&'static str>;
    }
}

use once_cell::sync::Lazy;

static INIT_LOGS: Once = Once::new();

fn init_logs() {
    INIT_LOGS.call_once(|| {
        crate::setup_logs(3).unwrap();
    })
}

fn wallet_with(balance: Option<u64>) -> Option<Vec<u8>> {
    balance.map(|b| {
        let wallet = crate::protos::Wallet {
            amount: b.to_string(),
        };
        let mut buf = Vec::with_capacity(wallet.encoded_len());
        wallet.encode(&mut buf).unwrap();
        buf
    })
}

macro_rules! expect {
    ($id: ident, $fun: ident ($($arg: ident == $e: expr),*) -> $ret: expr; $count:literal times) => {
        paste::paste! {
            $id.[<expect_ $fun>]()
                .times($count)
                .withf(move |$($arg),*| {
                    $($arg == $e)&&*
                })
                .return_once(|$($arg),*| {
                    $ret
                });
        }
    };
    ($id: ident, $fun: ident ($($arg: ident == $e: expr),*) -> $ret: expr) => {
       expect!($id, $fun ($($arg == $e),*) -> $ret ; 1 times);
    };
}

#[test]
fn housekeeping_reward_in_chain() {
    init_logs();

    // Housekeeeping with block idx = 0
    let command = Housekeeping {
        block_idx: Integer::new(),
    };

    // Chain tip is far ahead
    let request = TpProcessRequest {
        tip: (CONFIRMATION_COUNT * 2 + BLOCK_REWARD_PROCESSING_COUNT) * 4,
        ..Default::default()
    };
    static processed_block_idx: Lazy<String> = Lazy::new(|| {
        string!(
            NAMESPACE_PREFIX.as_str(),
            PROCESSED_BLOCK,
            PROCESSED_BLOCK_ID,
        )
    });
    let mut tx_ctx = MockTransactionContext::default();

    // get_state_entry should be called on the processed_block_idx address, and we will return
    // CONFIRMATION_COUNT * 2 + BLOCK_REWARD_PROCESSING_COUNT, which will force housekeeping to run
    tx_ctx
        .expect_get_state_entry()
        .once()
        .with(predicate::eq(processed_block_idx.as_str()))
        .return_once(|_| {
            Ok(Some(
                Integer::from(CONFIRMATION_COUNT * 2 + BLOCK_REWARD_PROCESSING_COUNT)
                    .to_string()
                    .into_bytes(),
            ))
        });

    // pretend update1 is not set
    let mut ctx = MockHandlerContext::default();
    ctx.expect_get_setting()
        .once()
        .with(predicate::eq("sawtooth.validator.update1"))
        .returning(|_| None);

    let height_start = CONFIRMATION_COUNT * 2 + BLOCK_REWARD_PROCESSING_COUNT + 1;
    let height_end = height_start + BLOCK_REWARD_PROCESSING_COUNT;

    let mut signers = vec![];

    // housekeeping tries to get the signatures for the blocks
    // from height_start to height_end in order to issue mining rewards
    // return a dummy signer
    for height in height_start..height_end {
        let signer = format!("signer{}", height);
        signers.push(signer.clone());
        tx_ctx
            .expect_get_sig_by_num()
            .with(predicate::eq(height))
            .once()
            .return_once(|_| Ok(signer));
    }

    let reward_amount = REWARD_AMOUNT.clone();

    for (idx, signer) in signers.clone().into_iter().enumerate() {
        let wallet_id = WalletId::from(&SigHash(utils::sha512_id(signer.as_bytes())));
        let wallet_id_ = wallet_id.clone();

        // the first signer has no wallet, the rest have an existing balance of `idx`
        let balance = if idx == 0 { None } else { Some(idx as u64) };

        log::info!("starting balance = {:?}", balance);

        // housekeeping should try to fetch the current wallet for each signer
        // return the balance above
        tx_ctx
            .expect_get_state_entry()
            .withf(move |k| k == wallet_id.as_str())
            .once()
            .returning(move |_| Ok(wallet_with(balance)));

        // we expect the wallet to have an updated balance of reward_amount + old balance
        let wallet_expected = crate::protos::Wallet {
            amount: (reward_amount.clone() + balance.unwrap_or(0)).to_string(),
        };
        let state_expected = wallet_expected.to_bytes();
        log::info!("expect end wallet = {:?}", wallet_expected);
        // housekeeping should try to set the state to update
        // the wallet balance with the reward added
        tx_ctx
            .expect_set_state_entry()
            .withf(move |addr, state| addr == wallet_id_.as_str() && state == &state_expected)
            .once()
            .returning(|_, _| Ok(()));
    }

    // housekeeping should then set the processed_block_idx to the last processed block height
    // which in this case is height_end - 1
    tx_ctx
        .expect_set_state_entry()
        .once()
        .withf(move |addr, state| {
            addr == processed_block_idx.as_str()
                && state == &(height_end - 1).to_string().into_bytes()
        })
        .returning(|_, _| Ok(()));

    // run housekeeping
    command.execute(&request, &tx_ctx, &mut ctx).unwrap();
}
