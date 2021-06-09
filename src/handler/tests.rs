#![cfg(test)]
#![allow(non_snake_case, non_upper_case_globals)]

mod mocked;

use mocked::{MockSettings, MockTransactionContext};
use sawtooth_sdk::processor::handler::ApplyError;
use serde_cbor::Value;

use std::collections::BTreeMap;
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
use super::AddAskOrder;
use super::AddBidOrder;
use super::AddDealOrder;
use super::AddOffer;
use super::AddRepaymentOrder;
use super::CloseDealOrder;
use super::CloseRepaymentOrder;
use super::CollectCoins;
use super::CompleteDealOrder;
use super::CompleteRepaymentOrder;
use super::Exempt;
use super::LockDealOrder;
use super::RegisterAddress;
use super::RegisterTransfer;
use super::SendFunds;
use super::{CCTransaction, Housekeeping};

use once_cell::sync::Lazy;

static INIT_LOGS: Once = Once::new();

fn init_logs() {
    INIT_LOGS.call_once(|| {
        // UNCOMMENT TO COLLECT LOGS
        // crate::setup_logs(3).unwrap();
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
    ($id: ident, $fun: ident ($($arg: pat if $e: expr),*) -> $ret: expr , $count:literal times) => {
        paste::paste! {
            $id.[<expect_ $fun>]()
                .times($count)
                .withf(move |$($arg),*| {
                    $($e)&&*
                })
                .return_once(move |$($arg),*| {
                    $ret
                });
        }
    };
    ($id: ident, $fun: ident ($($arg: pat if $e: expr),*) -> $ret: expr) => {
       expect!($id, $fun ($($arg if $e),*) -> $ret , 1 times);
    };
}

static PROCESSED_BLOCK_IDX: Lazy<String> = Lazy::new(|| {
    string!(
        NAMESPACE_PREFIX.as_str(),
        PROCESSED_BLOCK,
        PROCESSED_BLOCK_ID,
    )
});

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
    let mut tx_ctx = MockTransactionContext::default();

    // get_state_entry should be called on the processed_block_idx address, and we will return
    // CONFIRMATION_COUNT * 2 + BLOCK_REWARD_PROCESSING_COUNT, which will force housekeeping to run
    expect!(tx_ctx,
        get_state_entry(k if k == PROCESSED_BLOCK_IDX.as_str())
        -> Ok(Some(
            Integer::from(CONFIRMATION_COUNT * 2 + BLOCK_REWARD_PROCESSING_COUNT).to_string().into_bytes()
        ))
    );

    // pretend update1 is not set
    let mut ctx = MockHandlerContext::default();
    expect!(ctx,
        get_setting(k if k == "sawtooth.validator.update1") -> None
    );

    let height_start = CONFIRMATION_COUNT * 2 + BLOCK_REWARD_PROCESSING_COUNT + 1;
    let height_end = height_start + BLOCK_REWARD_PROCESSING_COUNT;

    let mut signers = vec![];

    // housekeeping tries to get the signatures for the blocks
    // from height_start to height_end in order to issue mining rewards
    // return a dummy signer
    for height in height_start..height_end {
        let signer = format!("signer{}", height);
        signers.push(signer.clone());
        expect!(tx_ctx,
            get_sig_by_num(h if *h == height) -> Ok(signer)
        );
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
        expect!(
            tx_ctx,
            get_state_entry(k if k == wallet_id.as_str()) -> Ok(wallet_with(balance))
        );

        // we expect the wallet to have an updated balance of reward_amount + old balance
        let wallet_expected = crate::protos::Wallet {
            amount: (reward_amount.clone() + balance.unwrap_or(0)).to_string(),
        };
        let state_expected = wallet_expected.to_bytes();

        log::info!("expect end wallet = {:?}", wallet_expected);
        // housekeeping should try to set the state to update
        // the wallet balance with the reward added
        expect!(
            tx_ctx,
            set_state_entry(
                addr if addr == wallet_id_.as_str(),
                state if state == &state_expected
            ) -> Ok(())
        );
    }

    // housekeeping should then set the processed_block_idx to the last processed block height
    // which in this case is height_end - 1
    expect!(tx_ctx, set_state_entry(
            addr if addr == PROCESSED_BLOCK_IDX.as_str(),
            state if state == &(height_end - 1).to_string().into_bytes()
        ) -> Ok(())
    );

    // run housekeeping
    command.execute(&request, &tx_ctx, &mut ctx).unwrap();
}

#[test]
fn housekeeping_reward_fork() {
    init_logs();

    // Housekeeeping with block idx = 0
    let command = Housekeeping {
        block_idx: Integer::new(),
    };

    let last_processed = CONFIRMATION_COUNT * 2 + BLOCK_REWARD_PROCESSING_COUNT;

    // Chain tip is far ahead
    let request = TpProcessRequest {
        tip: last_processed * 4,
        block_signature: "headblocksig".into(),
        ..Default::default()
    };
    let mut tx_ctx = MockTransactionContext::default();

    // get_state_entry should be called on the processed_block_idx address, and we will return
    // CONFIRMATION_COUNT * 2 + BLOCK_REWARD_PROCESSING_COUNT, which will force housekeeping to run
    expect!(tx_ctx,
        get_state_entry(k if k == PROCESSED_BLOCK_IDX.as_str())
        -> Ok(Some(
            Integer::from(last_processed).to_string().into_bytes()
        ))
    );

    // pretend update1 is not set
    let mut ctx = MockHandlerContext::default();
    expect!(ctx,
        get_setting(k if k == "sawtooth.validator.update1") -> None
    );

    // the get_reward_block_signatures path iterates in reverse inclusively, so if last_processed = 5
    // and BLOCK_REWARD_PROCESSING_COUNT = 5, then the bounds
    // should be [10, 6] i.e. [last_processed + BLOCK_REWARD_PROCESSING_COUNT, last_processed+1]
    let last_pred = last_processed + 1;
    let first_pred = last_processed + BLOCK_REWARD_PROCESSING_COUNT;

    log::warn!("{}..{}", last_pred, first_pred);

    let mut signers: Vec<String> = (last_pred..first_pred)
        .map(|i| format!("signer{}", i))
        .collect();

    let signers_ = signers.clone();

    // housekeeping tries to get the signatures for the blocks
    // iterating backwards from first_pred to last_pred
    expect!(tx_ctx,
        get_reward_block_signatures(id if id == "headblocksig", first if *first == first_pred, last if *last == last_pred) -> Ok(
            signers_.clone()
        )
    );

    let reward_amount = REWARD_AMOUNT.clone();

    for (idx, signer) in signers.clone().into_iter().enumerate() {
        let wallet_id = WalletId::from(&SigHash(utils::sha512_id(signer.as_bytes())));
        let wallet_id_ = wallet_id.clone();

        // the first signer has no wallet, the rest have an existing balance of `idx`
        let balance = if idx == 0 { None } else { Some(idx as u64) };

        log::info!("starting balance = {:?}", balance);

        // housekeeping should try to fetch the current wallet for each signer
        // return the balance above
        expect!(
            tx_ctx,
            get_state_entry(k if k == wallet_id.as_str()) -> Ok(wallet_with(balance))
        );

        // we expect the wallet to have an updated balance of reward_amount + old balance
        let wallet_expected = crate::protos::Wallet {
            amount: (reward_amount.clone() + balance.unwrap_or(0)).to_string(),
        };
        let state_expected = wallet_expected.to_bytes();

        log::info!("expect end wallet = {:?}", wallet_expected);
        // housekeeping should try to set the state to update
        // the wallet balance with the reward added
        expect!(
            tx_ctx,
            set_state_entry(
                addr if addr == wallet_id_.as_str(),
                state if state == &state_expected
            ) -> Ok(())
        );
    }

    // housekeeping should then set the processed_block_idx to the last processed block height
    // which in this case is height_end - 1
    expect!(tx_ctx, set_state_entry(
            addr if addr == PROCESSED_BLOCK_IDX.as_str(),
            state if state == &(first_pred).to_string().into_bytes()
        ) -> Ok(())
    );

    // run housekeeping
    command.execute(&request, &tx_ctx, &mut ctx).unwrap();
}

#[test]
fn housekeeping_not_enough_confirmations() {
    init_logs();

    // Housekeeeping with block idx = 0
    let command = Housekeeping {
        block_idx: Integer::new(),
    };

    // no blocks have been processed
    let last_processed = 0;

    // Chain tip is not quite at the threshold for running because
    // the blocks have not yet gotten enough confirmations
    let request = TpProcessRequest {
        tip: BLOCK_REWARD_PROCESSING_COUNT + 1,
        block_signature: "headblocksig".into(),
        ..Default::default()
    };
    let mut tx_ctx = MockTransactionContext::default();

    expect!(tx_ctx,
        get_state_entry(k if k == PROCESSED_BLOCK_IDX.as_str())
        -> Ok(Some(
            Integer::from(last_processed).to_string().into_bytes()
        ))
    );

    let mut ctx = MockHandlerContext::default();

    // execute housekeeping
    command.execute(&request, &tx_ctx, &mut ctx).unwrap();
}

#[test]
fn housekeeping_within_block_reward_count() {
    init_logs();

    // Housekeeeping with block idx = 0
    let command = Housekeeping {
        block_idx: Integer::new(),
    };

    // pretend we've issued some rewards already
    let last_processed = 4 * CONFIRMATION_COUNT + BLOCK_REWARD_PROCESSING_COUNT;

    // Chain tip is not quite at the threshold for running because
    // fewer than BLOCK_REWARD_PROCESSING_COUNT additional blocks have been processed
    let request = TpProcessRequest {
        tip: last_processed + BLOCK_REWARD_PROCESSING_COUNT - 1,
        block_signature: "headblocksig".into(),
        ..Default::default()
    };
    let mut tx_ctx = MockTransactionContext::default();

    // Housekeeping should check the last processed block, then bail out
    expect!(tx_ctx,
        get_state_entry(k if k == PROCESSED_BLOCK_IDX.as_str())
        -> Ok(Some(
            Integer::from(last_processed).to_string().into_bytes()
        ))
    );

    let mut ctx = MockHandlerContext::default();

    // execute housekeeping
    command.execute(&request, &tx_ctx, &mut ctx).unwrap();
}
