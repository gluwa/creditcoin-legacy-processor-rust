#![cfg(all(test, feature = "mock"))]
#![allow(non_snake_case, non_upper_case_globals)]

pub mod mocked;

use mocked::{MockSettings, MockTransactionContext};
use sawtooth_sdk::processor::handler::ApplyError;
use serde_cbor::Value;

use std::collections::BTreeMap;
use std::sync::Once;

use enclose::enclose;
use itertools::Itertools;
use mockall::predicate;
use prost::Message;
use rug::Integer;
use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::TransactionContext;

use crate::ext::{IntegerExt, MessageExt};
use crate::handler::constants::*;
use crate::handler::types::{CCApplyError, SigHash};
use crate::handler::types::{Guid, WalletId};
use crate::handler::utils::{self, calc_interest};
use crate::{protos, string};

use super::context::mocked::MockHandlerContext;
use super::types::{Address, BlockNum, TxnResult};
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

// TEST UTILS

static INIT_LOGS: Once = Once::new();

fn init_logs() {
    INIT_LOGS.call_once(|| {
        // UNCOMMENT TO COLLECT LOGS
        // crate::setup_logs(3).unwrap();
    })
}

fn wallet_with(balance: Option<impl Into<Integer> + Clone>) -> Option<Vec<u8>> {
    balance.map(|b| {
        let wallet = crate::protos::Wallet {
            amount: b.into().to_string(),
        };
        let mut buf = Vec::with_capacity(wallet.encoded_len());
        wallet.encode(&mut buf).unwrap();
        buf
    })
}

macro_rules! expect {
    ($id: ident, $fun: ident where $c: expr, returning $ret: expr, $count: literal times) => {

        paste::paste! {
                #[allow(unused_variables)]
                $id.[<expect_ $fun>]()
                .times($count)
                .withf($c)
                .return_once($ret)
            }

    };
    ($id: ident, $fun: ident where $c: expr, returning $ret: expr) => {
        expect!($id, $fun where $c, returning $ret, 1 times)
    };
    ($id: ident, $fun: ident ($($arg: pat),* $(,)?), returning $ret: expr) => {
        expect!($id, $fun where { |$($arg),*| true}, returning $ret, 1 times)
    };
    ($id: ident, $fun: ident ($($arg: pat if $e: expr),* $(,)?) -> $ret: expr , $count:literal times) => {
        expect!($id, $fun where {
            move |$($arg),*| {
                $($e)&&*
            }
        }, returning {
            move |$($arg),*| {
                $ret
            }
        }, 1 times)
    };
    ($id: ident, $fun: ident ($($arg: pat),* $(,)?) -> $ret: expr , $count:literal times) => {
        expect!($id, $fun where { |$($arg),*| true}, returning {move |$($arg),*| {
            $ret
        }}, $count times)
    };
    ($id: ident, $fun: ident ($($arg: pat),* $(,)?) -> $ret: expr ) => {
        expect!($id, $fun ($($arg),*) -> $ret , 1 times)
    };
    ($id: ident, $fun: ident ($($arg: pat if $e: expr),*  $(,)?) -> $ret: expr) => {
       expect!($id, $fun ($($arg if $e),*) -> $ret , 1 times)
    };
    ($id: ident, get balance at $w: ident -> $ret: expr) => {
        expect!($id, get_state_entry where {
            enclose!(($w) move |_w| {
                _w == $w.as_str()
            })
        }, returning {
            move |_| Ok(wallet_with($ret))
        }, 1 times)
    };
    ($id: ident, get balance at $w: ident, returning $ret: expr) => {
        expect!($id, get_state_entry where {
            enclose!(($w) move |_w| {
                _w == $w.as_str()
            })
        }, returning $ret, 1 times)
    };
    ($id: ident, set balance at $w: ident to $amt: ident) => {
        {
            expect!($id, set_state_entry where {
                let $amt = $amt.clone();
                let _wallet = wallet_with(Some($amt)).unwrap();
                enclose!(($w) move |_w, _a| {
                    _w == $w.as_str() && _a == &_wallet
                })
            }, returning {
                |_,_| Ok(())
            }, 1 times);
            wallet_with(Some($amt.clone())).unwrap()
        }
    };
    ($id: ident, set balance at $w: ident to ($amt: expr)) => {
        {
            expect!($id, set_state_entry where {
                enclose!(($w) move |_w, _a| {
                    _w == $w.as_str() && _a == &wallet_with(Some($amt.clone())).unwrap()
                })
            }, returning {
                |_,_| Ok(())
            }, 1 times);
            wallet_with(Some($amt.clone())).unwrap()
        }
    };
    ($id: ident, sighash -> $sig: ident) => {
        expect!($id, sighash where {
            |_| true
        }, returning {
            enclose!(($sig) move |_| Ok($sig))
        })
    };
    ($id: ident, sighash -> $sig: expr) => {
        expect!($id, sighash where {
            |_| true
        }, returning {
            enclose!(($sig) move |_| Ok(crate::handler::types::SigHash($sig.to_string())))
        })
    };
    ($id: ident, guid -> $guid: ident) => {
        expect!($id, guid where {
            |_| true
        }, returning {
            enclose!(($guid) move |_| $guid)
        })
    };
    ($id: ident, guid -> $guid: literal) => {
        expect!($id, guid where {
            |_| true
        }, returning {
            move |_| crate::handler::types::Guid($guid.to_string())
        })
    };
}

static PROCESSED_BLOCK_IDX: Lazy<String> = Lazy::new(|| {
    string!(
        NAMESPACE_PREFIX.as_str(),
        PROCESSED_BLOCK,
        PROCESSED_BLOCK_ID,
    )
});

// ----- COMMAND DESERIALIZATION TESTS -----
use super::CCCommand;
use serde::Serialize;
use serde_cbor::value;
use std::convert::TryFrom;

macro_rules! command {
    ($num: ident $(,)? $($param: ident),*) => {
        paste::paste! {
            #[derive(Serialize, PartialEq, Clone)]
            struct [<$num ArgCommand>] {
                v: String,
                $(
                    [<$param:lower>] : String
                ),*
            }

            impl [<$num ArgCommand>] {
                fn new<$($param : serde::Serialize + std::fmt::Display),*>(v: impl Into<String>, $([<$param:lower>]: $param),*) -> Self {
                    Self {
                        v: v.into(),
                        $([<$param:lower>] : [<$param:lower>].to_string()),*
                    }
                }
            }

            impl<$($param : serde::Serialize + std::fmt::Display),* > From<(&str, $($param),*)> for [<$num ArgCommand>] {
                fn from((v, $([<$param:lower>]),*): (&str, $($param),*)) -> Self {
                    Self {
                        v: v.into(),
                        $([<$param:lower>] : [<$param:lower>].to_string()),*
                    }
                }
            }
        }
    };
}

command!(Zero);
command!(One, P1);
command!(Two, P1, P2);
command!(Three, P1, P2, P3);
command!(Four, P1, P2, P3, P4);
command!(Five, P1, P2, P3, P4, P5);
command!(Six, P1, P2, P3, P4, P5, P6);

#[track_caller]
fn deserialize_success(value: impl Serialize, expected: impl Into<CCCommand>) {
    let value = value::to_value(value).unwrap();
    let expected = expected.into();
    let result = CCCommand::try_from(value).unwrap();
    assert_eq!(result, expected);
}

#[track_caller]
fn deserialize_failure(value: impl Serialize, expected_err: &str) {
    let value = value::to_value(value).unwrap();
    let result = CCCommand::try_from(value).unwrap_err();
    match result.downcast_ref::<CCApplyError>() {
        Some(CCApplyError::InvalidTransaction(s)) => {
            assert_eq!(s, expected_err);
        }
        _ => panic!("Expected an InvalidTransaction error"),
    };
}

// SendFunds

#[test]
fn send_funds_accept() {
    deserialize_success(
        TwoArgCommand::new("SendFunds", 1, "foo"),
        SendFunds {
            amount: 1.into(),
            sighash: SigHash("foo".into()),
        },
    )
}

#[test]
fn send_funds_case_insensitive() {
    deserialize_success(
        TwoArgCommand::new("SeNdfUnDs", 1, "foo"),
        SendFunds {
            amount: 1.into(),
            sighash: SigHash("foo".into()),
        },
    )
}

#[test]
fn send_funds_rejects_negative() {
    deserialize_failure(
        TwoArgCommand::new("SendFunds", -1, "foo"),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn send_funds_rejects_non_integer() {
    deserialize_failure(
        TwoArgCommand::new("SendFunds", "bad", "foo"),
        INVALID_NUMBER_FORMAT_ERR,
    );
}

#[test]
fn send_funds_rejects_missing_arg() {
    deserialize_failure(OneArgCommand::new("SendFunds", 1), "Expecting sighash");
    deserialize_failure(ZeroArgCommand::new("SendFunds"), "Expecting amount");
}

// RegisterAddress

#[test]
fn register_address_accept() {
    deserialize_success(
        ThreeArgCommand::new("RegisterAddress", "blockchain", "address", "network"),
        RegisterAddress {
            blockchain: "blockchain".into(),
            address: "address".into(),
            network: "network".into(),
        },
    )
}

#[test]
fn register_address_case_insensitive() {
    deserialize_success(
        ThreeArgCommand::new("ReGiStErAdDrEsS", "blockchain", "address", "network"),
        RegisterAddress {
            blockchain: "blockchain".into(),
            address: "address".into(),
            network: "network".into(),
        },
    )
}

#[test]
fn register_address_missing_arg() {
    deserialize_failure(
        TwoArgCommand::new("RegisterAddress", "blockchain", "address"),
        "Expecting network",
    );
    deserialize_failure(
        OneArgCommand::new("RegisterAddress", "blockchain"),
        "Expecting address",
    );
    deserialize_failure(
        ZeroArgCommand::new("RegisterAddress"),
        "Expecting blockchain",
    );
}

// RegisterTransfer

#[test]
fn register_transfer_accept() {
    deserialize_success(
        ThreeArgCommand::new("RegisterTransfer", 1, "orderid", "txid"),
        RegisterTransfer {
            gain: 1.into(),
            order_id: "orderid".into(),
            blockchain_tx_id: "txid".into(),
        },
    );
}

#[test]
fn register_transfer_case_insensitive() {
    deserialize_success(
        ThreeArgCommand::new("ReGiStErTrAnSfEr", 1, "orderid", "txid"),
        RegisterTransfer {
            gain: 1.into(),
            order_id: "orderid".into(),
            blockchain_tx_id: "txid".into(),
        },
    );
}

#[test]
fn register_transfer_accepts_negative_gain() {
    deserialize_success(
        ThreeArgCommand::new("RegisterTransfer", -1, "orderid", "txid"),
        RegisterTransfer {
            gain: (-1).into(),
            order_id: "orderid".into(),
            blockchain_tx_id: "txid".into(),
        },
    );
}

#[test]
fn register_transfer_invalid_gain() {
    deserialize_failure(
        ThreeArgCommand::new("RegisterTransfer", "invalid", "orderid", "txid"),
        INVALID_NUMBER_FORMAT_ERR,
    );
}

#[test]
fn register_transfer_missing_arg() {
    deserialize_failure(
        TwoArgCommand::new("RegisterTransfer", 1, "orderid"),
        "Expecting blockchainTxId",
    );
    deserialize_failure(
        OneArgCommand::new("RegisterTransfer", 1),
        "Expecting orderID",
    );
    deserialize_failure(ZeroArgCommand::new("RegisterTransfer"), "Expecting gain");
}

// AddAskOrder

#[test]
fn add_ask_order_accept() {
    let args = SixArgCommand::new("AddAskOrder", "addressid", 1, 2, 3, 4, 5);
    let args_uppercase = SixArgCommand {
        p1: "ADDRESSID".into(),
        ..args.clone()
    };
    let expected = AddAskOrder {
        address_id: "addressid".into(),
        amount_str: 1.to_string(),
        interest: 2.to_string(),
        maturity: 3.to_string(),
        fee: 4.to_string(),
        expiration: 5.into(),
    };
    deserialize_success(args, expected.clone());
    deserialize_success(args_uppercase, expected.clone());
}

#[test]
fn add_ask_order_case_insensitive() {
    let args = SixArgCommand::new("AdDAsKoRdEr", "addressid", 1, 2, 3, 4, 5);
    let expected = AddAskOrder {
        address_id: "addressid".into(),
        amount_str: 1.to_string(),
        interest: 2.to_string(),
        maturity: 3.to_string(),
        fee: 4.to_string(),
        expiration: 5.into(),
    };
    deserialize_success(args, expected);
}

#[test]
fn add_ask_order_negative_amount() {
    deserialize_failure(
        SixArgCommand::new("AddAskOrder", "addressid", -1, 2, 3, 4, 5),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn add_ask_order_invalid_amount() {
    deserialize_failure(
        SixArgCommand::new("AddAskOrder", "addressid", "bad", 2, 3, 4, 5),
        INVALID_NUMBER_FORMAT_ERR,
    );
}

#[test]
fn add_ask_order_negative_interest() {
    deserialize_failure(
        SixArgCommand::new("AddAskOrder", "addressid", 1, -2, 3, 4, 5),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn add_ask_order_invalid_interest() {
    deserialize_failure(
        SixArgCommand::new("AddAskOrder", "addressid", 1, "BAD", 3, 4, 5),
        INVALID_NUMBER_FORMAT_ERR,
    );
}

#[test]
fn add_ask_order_negative_maturity() {
    deserialize_failure(
        SixArgCommand::new("AddAskOrder", "addressid", 1, 2, -3, 4, 5),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn add_ask_order_invalid_maturity() {
    deserialize_failure(
        SixArgCommand::new("AddAskOrder", "addressid", 1, 2, "BAD", 4, 5),
        INVALID_NUMBER_FORMAT_ERR,
    );
}

#[test]
fn add_ask_order_negative_fee() {
    deserialize_failure(
        SixArgCommand::new("AddAskOrder", "addressid", 1, 2, 3, -4, 5),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn add_ask_order_invalid_fee() {
    deserialize_failure(
        SixArgCommand::new("AddAskOrder", "addressid", 1, 2, 3, "BAD", 5),
        INVALID_NUMBER_FORMAT_ERR,
    );
}

#[test]
fn add_ask_order_negative_expiration() {
    deserialize_failure(
        SixArgCommand::new("AddAskOrder", "addressid", 1, 2, 3, 4, -5),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn add_ask_order_invalid_expiration() {
    deserialize_failure(
        SixArgCommand::new("AddAskOrder", "addressid", 1, 2, 3, 4, "BAD"),
        INVALID_NUMBER_ERR,
    );
}

#[test]
fn add_ask_order_missing_arg() {
    deserialize_failure(
        FiveArgCommand::new("AddAskOrder", "addressid", 1, 2, 3, 4),
        "Expecting expiration",
    );
    deserialize_failure(
        FourArgCommand::new("AddAskOrder", "addressid", 1, 2, 3),
        "Expecting fee",
    );
    deserialize_failure(
        ThreeArgCommand::new("AddAskOrder", "addressid", 1, 2),
        "Expecting maturity",
    );
    deserialize_failure(
        TwoArgCommand::new("AddAskOrder", "addressid", 1),
        "Expecting interest",
    );
    deserialize_failure(
        OneArgCommand::new("AddAskOrder", "addressid"),
        "Expecting amount",
    );
    deserialize_failure(ZeroArgCommand::new("AddAskOrder"), "Expecting addressId");
}

// AddBidOrder

#[test]
fn add_bid_order_accept() {
    let args = SixArgCommand::new("AddBidOrder", "addressid", 1, 2, 3, 4, 5);
    let args_uppercase = SixArgCommand {
        p1: "ADDRESSID".into(),
        ..args.clone()
    };
    let expected = AddBidOrder {
        address_id: "addressid".into(),
        amount_str: 1.to_string(),
        interest: 2.to_string(),
        maturity: 3.to_string(),
        fee: 4.to_string(),
        expiration: 5.into(),
    };
    deserialize_success(args, expected.clone());
    deserialize_success(args_uppercase, expected.clone());
}

#[test]
fn add_bid_order_case_insensitive() {
    let args = SixArgCommand::new("AdDbIdOrDeR", "addressid", 1, 2, 3, 4, 5);
    let expected = AddBidOrder {
        address_id: "addressid".into(),
        amount_str: 1.to_string(),
        interest: 2.to_string(),
        maturity: 3.to_string(),
        fee: 4.to_string(),
        expiration: 5.into(),
    };
    deserialize_success(args, expected);
}

#[test]
fn add_bid_order_negative_amount() {
    deserialize_failure(
        SixArgCommand::new("AddBidOrder", "addressid", -1, 2, 3, 4, 5),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn add_bid_order_invalid_amount() {
    deserialize_failure(
        SixArgCommand::new("AddBidOrder", "addressid", "bad", 2, 3, 4, 5),
        INVALID_NUMBER_FORMAT_ERR,
    );
}

#[test]
fn add_bid_order_negative_interest() {
    deserialize_failure(
        SixArgCommand::new("AddBidOrder", "addressid", 1, -2, 3, 4, 5),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn add_bid_order_invalid_interest() {
    deserialize_failure(
        SixArgCommand::new("AddBidOrder", "addressid", 1, "BAD", 3, 4, 5),
        INVALID_NUMBER_FORMAT_ERR,
    );
}

#[test]
fn add_bid_order_negative_maturity() {
    deserialize_failure(
        SixArgCommand::new("AddBidOrder", "addressid", 1, 2, -3, 4, 5),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn add_bid_order_invalid_maturity() {
    deserialize_failure(
        SixArgCommand::new("AddBidOrder", "addressid", 1, 2, "BAD", 4, 5),
        INVALID_NUMBER_FORMAT_ERR,
    );
}

#[test]
fn add_bid_order_negative_fee() {
    deserialize_failure(
        SixArgCommand::new("AddBidOrder", "addressid", 1, 2, 3, -4, 5),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn add_bid_order_invalid_fee() {
    deserialize_failure(
        SixArgCommand::new("AddBidOrder", "addressid", 1, 2, 3, "BAD", 5),
        INVALID_NUMBER_FORMAT_ERR,
    );
}

#[test]
fn add_bid_order_negative_expiration() {
    deserialize_failure(
        SixArgCommand::new("AddBidOrder", "addressid", 1, 2, 3, 4, -5),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn add_bid_order_invalid_expiration() {
    deserialize_failure(
        SixArgCommand::new("AddBidOrder", "addressid", 1, 2, 3, 4, "BAD"),
        INVALID_NUMBER_ERR,
    );
}

#[test]
fn add_bid_order_missing_arg() {
    deserialize_failure(
        FiveArgCommand::new("AddBidOrder", "addressid", 1, 2, 3, 4),
        "Expecting expiration",
    );
    deserialize_failure(
        FourArgCommand::new("AddBidOrder", "addressid", 1, 2, 3),
        "Expecting fee",
    );
    deserialize_failure(
        ThreeArgCommand::new("AddBidOrder", "addressid", 1, 2),
        "Expecting maturity",
    );
    deserialize_failure(
        TwoArgCommand::new("AddBidOrder", "addressid", 1),
        "Expecting interest",
    );
    deserialize_failure(
        OneArgCommand::new("AddBidOrder", "addressid"),
        "Expecting amount",
    );
    deserialize_failure(ZeroArgCommand::new("AddBidOrder"), "Expecting addressId");
}

// AddOffer

#[test]
fn add_offer_accept() {
    let args = ThreeArgCommand::new("AddOffer", "askorder", "bidorder", 1);
    let args_upper = ThreeArgCommand {
        p1: "ASKORDER".into(),
        p2: "BIDORDER".into(),
        ..args.clone()
    };
    let expected = AddOffer {
        ask_order_id: "askorder".into(),
        bid_order_id: "bidorder".into(),
        expiration: 1.into(),
    };
    deserialize_success(args, expected.clone());
    deserialize_success(args_upper, expected);
}

#[test]
fn add_offer_case_insensitive() {
    let args = ThreeArgCommand::new("AdDoFfEr", "askorder", "bidorder", 1);
    let expected = AddOffer {
        ask_order_id: "askorder".into(),
        bid_order_id: "bidorder".into(),
        expiration: 1.into(),
    };
    deserialize_success(args, expected);
}

#[test]
fn add_offer_negative_expiration() {
    deserialize_failure(
        ThreeArgCommand::new("AddOffer", "ask", "bid", -2),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn add_offer_invalid_expiration() {
    deserialize_failure(
        ThreeArgCommand::new("AddOffer", "ask", "bid", "BAD"),
        INVALID_NUMBER_ERR,
    );
}

#[test]
fn add_offer_missing_arg() {
    deserialize_failure(
        TwoArgCommand::new("AddOffer", "ask", "bid"),
        "Expecting expiration",
    );
    deserialize_failure(
        OneArgCommand::new("AddOffer", "ask"),
        "Expecting bidOrderId",
    );
    deserialize_failure(ZeroArgCommand::new("AddOffer"), "Expecting askOrderId");
}

// AddDealOrder

#[test]
fn add_deal_order_accept() {
    let expected = AddDealOrder {
        offer_id: "offerid".into(),
        expiration: 1.into(),
    };
    deserialize_success(
        TwoArgCommand::new("AddDealOrder", "offerid", 1),
        expected.clone(),
    );
    deserialize_success(TwoArgCommand::new("AddDealOrder", "OFFERID", 1), expected);
}

#[test]
fn add_deal_order_case_insensitive() {
    let expected = AddDealOrder {
        offer_id: "offerid".into(),
        expiration: 1.into(),
    };
    deserialize_success(TwoArgCommand::new("AdDdEaLoRdEr", "offerid", 1), expected);
}

#[test]
fn add_deal_order_negative_expiration() {
    deserialize_failure(
        TwoArgCommand::new("AddDealOrder", "offerid", -1),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn add_deal_order_invalid_expiration() {
    deserialize_failure(
        TwoArgCommand::new("AddDealOrder", "offerid", "BAD"),
        INVALID_NUMBER_ERR,
    );
}

#[test]
fn add_deal_order_missing_arg() {
    deserialize_failure(
        OneArgCommand::new("AddDealOrder", "offerid"),
        "Expecting expiration",
    );
    deserialize_failure(ZeroArgCommand::new("AddDealOrder"), "Expecting offerId");
}

// CompleteDealOrder

#[test]
fn complete_deal_order_accept() {
    let expected = CompleteDealOrder {
        deal_order_id: "orderid".into(),
        transfer_id: "transferid".into(),
    };
    deserialize_success(
        TwoArgCommand::new("CompleteDealOrder", "orderid", "transferid"),
        expected.clone(),
    );
    deserialize_success(
        TwoArgCommand::new("CompleteDealOrder", "ORDERID", "TRANSFERID"),
        expected,
    );
}

#[test]
fn complete_deal_order_case_insensitive() {
    let expected = CompleteDealOrder {
        deal_order_id: "orderid".into(),
        transfer_id: "transferid".into(),
    };
    deserialize_success(
        TwoArgCommand::new("CoMpLeTeDeAlOrDer", "orderid", "transferid"),
        expected,
    );
}

#[test]
fn complete_deal_order_missing_arg() {
    deserialize_failure(
        OneArgCommand::new("CompleteDealOrder", "orderid"),
        "Expecting transferId",
    );
    deserialize_failure(
        ZeroArgCommand::new("CompleteDealOrder"),
        "Expecting dealOrderId",
    );
}

// LockDealOrder

#[test]
fn lock_deal_order_accept() {
    let expected = LockDealOrder {
        deal_order_id: "orderid".into(),
    };
    deserialize_success(
        OneArgCommand::new("LockDealOrder", "orderid"),
        expected.clone(),
    );
    deserialize_success(OneArgCommand::new("LockDealOrder", "ORDERID"), expected);
}

#[test]
fn lock_deal_order_case_insensitive() {
    let expected = LockDealOrder {
        deal_order_id: "orderid".into(),
    };
    deserialize_success(OneArgCommand::new("LoCkDeAlOrDeR", "orderid"), expected);
}

#[test]
fn lock_deal_order_missing_arg() {
    deserialize_failure(
        ZeroArgCommand::new("LockDealOrder"),
        "Expecting dealOrderId",
    );
}

// CloseDealOrder

#[test]
fn close_deal_order_accept() {
    let expected = CloseDealOrder {
        deal_order_id: "orderid".into(),
        transfer_id: "transferid".into(),
    };
    deserialize_success(
        TwoArgCommand::new("CloseDealOrder", "orderid", "transferid"),
        expected.clone(),
    );
    deserialize_success(
        TwoArgCommand::new("CloseDealOrder", "ORDERID", "TRANSFERID"),
        expected,
    );
}

#[test]
fn close_deal_order_case_insensitive() {
    let expected = CloseDealOrder {
        deal_order_id: "orderid".into(),
        transfer_id: "transferid".into(),
    };
    deserialize_success(
        TwoArgCommand::new("ClOsEdEaLoRdEr", "orderid", "transferid"),
        expected,
    );
}

#[test]
fn close_deal_order_missing_arg() {
    deserialize_failure(
        OneArgCommand::new("CloseDealOrder", "orderid"),
        "Expecting transferId",
    );
    deserialize_failure(
        ZeroArgCommand::new("CloseDealOrder"),
        "Expecting dealOrderId",
    );
}

// Exempt

#[test]
fn exempt_accept() {
    let expected = Exempt {
        deal_order_id: "orderid".into(),
        transfer_id: "transferid".into(),
    };
    deserialize_success(
        TwoArgCommand::new("Exempt", "orderid", "transferid"),
        expected.clone(),
    );
    deserialize_success(
        TwoArgCommand::new("Exempt", "ORDERID", "TRANSFERID"),
        expected,
    );
}

#[test]
fn exempt_case_insensitive() {
    let expected = Exempt {
        deal_order_id: "orderid".into(),
        transfer_id: "transferid".into(),
    };
    deserialize_success(
        TwoArgCommand::new("ExEmPt", "orderid", "transferid"),
        expected,
    );
}

#[test]
fn exempt_missing_arg() {
    deserialize_failure(
        OneArgCommand::new("Exempt", "orderid"),
        "Expecting transferId",
    );
    deserialize_failure(ZeroArgCommand::new("Exempt"), "Expecting dealOrderId");
}

// AddRepaymentOrder

#[test]
fn add_repayment_order_accept() {
    let expected = AddRepaymentOrder {
        deal_order_id: "orderid".into(),
        address_id: "addressid".into(),
        amount: "1".into(),
        expiration: 2.into(),
    };
    deserialize_success(
        FourArgCommand::new("AddRepaymentOrder", "orderid", "addressid", 1, 2),
        expected.clone(),
    );
    deserialize_success(
        FourArgCommand::new("AddRepaymentOrder", "ORDERID", "ADDRESSID", 1, 2),
        expected.clone(),
    );
}

#[test]
fn add_repayment_order_case_insensitive() {
    let expected = AddRepaymentOrder {
        deal_order_id: "orderid".into(),
        address_id: "addressid".into(),
        amount: "1".into(),
        expiration: 2.into(),
    };
    deserialize_success(
        FourArgCommand::new("AdDrEpAyMeNtOrDeR", "orderid", "addressid", 1, 2),
        expected,
    );
}

#[test]
fn add_repayment_order_negative_amount() {
    deserialize_failure(
        FourArgCommand::new("AddRepaymentOrder", "orderid", "addressid", -1, 2),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn add_repayment_order_invalid_amount() {
    deserialize_failure(
        FourArgCommand::new("AddRepaymentOrder", "orderid", "addressid", "BAD", 2),
        INVALID_NUMBER_FORMAT_ERR,
    );
}

#[test]
fn add_repayment_order_invalid_expiration() {
    deserialize_failure(
        FourArgCommand::new("AddRepaymentOrder", "orderid", "addressid", 1, "BAD"),
        INVALID_NUMBER_ERR,
    );
}

#[test]
fn add_repayment_order_missing_arg() {
    deserialize_failure(
        ThreeArgCommand::new("AddRepaymentOrder", "orderid", "addressid", 1),
        "Expecting expiration",
    );
    deserialize_failure(
        TwoArgCommand::new("AddRepaymentOrder", "orderid", "addressid"),
        "Expecting amount",
    );
    deserialize_failure(
        OneArgCommand::new("AddRepaymentOrder", "orderid"),
        "Expecting addressId",
    );
    deserialize_failure(
        ZeroArgCommand::new("AddRepaymentOrder"),
        "Expecting dealOrderId",
    );
}

// CompleteRepaymentOrder

#[test]
fn complete_repayment_order_accept() {
    let expected = CompleteRepaymentOrder {
        repayment_order_id: "repaymentid".into(),
    };
    deserialize_success(
        OneArgCommand::new("CompleteRepaymentOrder", "repaymentid"),
        expected.clone(),
    );
    deserialize_success(
        OneArgCommand::new("CompleteRepaymentOrder", "REPAYMENTID"),
        expected.clone(),
    );
}

#[test]
fn complete_repayment_order_case_insensitive() {
    let expected = CompleteRepaymentOrder {
        repayment_order_id: "repaymentid".into(),
    };
    deserialize_success(
        OneArgCommand::new("CoMpLeTeRePaYmEnToRdEr", "repaymentid"),
        expected,
    );
}

#[test]
fn complete_repayment_order_missing_arg() {
    deserialize_failure(
        ZeroArgCommand::new("CompleteRepaymentOrder"),
        "Expecting repaymentOrderId",
    );
}

// CloseRepaymentOrder

#[test]
fn close_repayment_order_accept() {
    let expected = CloseRepaymentOrder {
        repayment_order_id: "repaymentid".into(),
        transfer_id: "transferid".into(),
    };
    deserialize_success(
        TwoArgCommand::new("CloseRepaymentOrder", "repaymentid", "transferid"),
        expected.clone(),
    );
    deserialize_success(
        TwoArgCommand::new("CloseRepaymentOrder", "REPAYMENTID", "TRANSFERID"),
        expected.clone(),
    );
}

#[test]
fn close_repayment_order_case_insensitive() {
    let expected = CloseRepaymentOrder {
        repayment_order_id: "repaymentid".into(),
        transfer_id: "transferid".into(),
    };
    deserialize_success(
        TwoArgCommand::new("ClOsErEpAyMeNtOrDeR", "repaymentid", "transferid"),
        expected,
    );
}

#[test]
fn close_repayment_order_missing_arg() {
    deserialize_failure(
        OneArgCommand::new("CloseRepaymentOrder", "repaymentid"),
        "Expecting transferId",
    );
    deserialize_failure(
        ZeroArgCommand::new("CloseRepaymentOrder"),
        "Expecting repaymentOrderId",
    );
}

// CollectCoins

#[test]
fn collect_coins_accept() {
    let expected = CollectCoins {
        eth_address: "ethaddress".into(),
        amount: 1.into(),
        blockchain_tx_id: "blockchainid".into(),
    };

    deserialize_success(
        ThreeArgCommand::new("CollectCoins", "ethaddress", 1, "blockchainid"),
        expected.clone(),
    );
    deserialize_success(
        ThreeArgCommand::new("CollectCoins", "ETHADDRESS", 1, "BLOCKCHAINID"),
        expected.clone(),
    );
}

#[test]
fn collect_coins_case_insensitive() {
    let expected = CollectCoins {
        eth_address: "ethaddress".into(),
        amount: 1.into(),
        blockchain_tx_id: "blockchainid".into(),
    };

    deserialize_success(
        ThreeArgCommand::new("CoLlEcTcOiNs", "ethaddress", 1, "blockchainid"),
        expected,
    );
}

#[test]
fn collect_coins_negative_amount() {
    deserialize_failure(
        ThreeArgCommand::new("CollectCoins", "ethaddress", -1, "blockchainid"),
        NEGATIVE_NUMBER_ERR,
    );
}

#[test]
fn collect_coins_invalid_amount() {
    deserialize_failure(
        ThreeArgCommand::new("CollectCoins", "ethaddress", "BAD", "blockchainid"),
        INVALID_NUMBER_FORMAT_ERR,
    );
}

#[test]
fn collect_coins_missing_arg() {
    deserialize_failure(
        TwoArgCommand::new("CollectCoins", "ethaddress", 1),
        "Expecting blockchainTxId",
    );
    deserialize_failure(
        OneArgCommand::new("CollectCoins", "ethaddress"),
        "Expecting amount",
    );
    deserialize_failure(ZeroArgCommand::new("CollectCoins"), "Expecting ethAddress");
}

// Housekeeping

#[test]
fn housekeeping_accept() {
    deserialize_success(
        OneArgCommand::new("Housekeeping", 1),
        CCCommand::Housekeeping(Housekeeping {
            block_idx: 1.into(),
        }),
    )
}

#[test]
fn housekeeping_case_insensitive() {
    deserialize_success(
        OneArgCommand::new("HoUsEkEePiNg", 1),
        CCCommand::Housekeeping(Housekeeping {
            block_idx: 1.into(),
        }),
    )
}

#[test]
fn housekeeping_negative_block_idx() {
    deserialize_failure(OneArgCommand::new("Housekeeping", -1), NEGATIVE_NUMBER_ERR);
}

#[test]
fn housekeeping_invalid_block_idx() {
    deserialize_failure(
        OneArgCommand::new("Housekeeping", "BAD"),
        INVALID_NUMBER_ERR,
    );
}

#[test]
fn housekeeping_rejects_missing_arg() {
    deserialize_failure(ZeroArgCommand::new("Housekeeping"), "Expecting blockIdx");
}

fn make_fee(guid: &Guid, sighash: &SigHash, block: Option<u64>) -> (String, Vec<u8>) {
    let fee_id = Address::with_prefix_key(super::constants::FEE, guid.as_str());
    let fee = crate::protos::Fee {
        sighash: sighash.clone().into(),
        block: block.unwrap_or_default().to_string(),
    };
    (fee_id.to_string(), fee.to_bytes())
}

fn expect_set_state_entries(tx_ctx: &mut MockTransactionContext, entries: Vec<(String, Vec<u8>)>) {
    expect!(tx_ctx, set_state_entries where {
        let entries = entries.into_iter().sorted().collect_vec();
        move |e| {
            let s = itertools::sorted(e.clone()).collect_vec();
            for (entry, other) in entries.iter().zip(&s) {
                if entry != other {
                    println!("Not equal! Expected {:?} -- Found {:?}", entry, other);
                    return false;
                }
            }
            if entries.len() != s.len() {
                println!("Unequal lengths! Expected {:?} -- Found {:?}", entries.len(), s.len());
                return false;
            }
            true
        }
    }, returning |_| Ok(()));
}

fn expect_delete_state_entries(tx_ctx: &mut MockTransactionContext, entries: Vec<String>) {
    tx_ctx
        .expect_delete_state_entries()
        .once()
        .withf({
            let entries = entries.into_iter().sorted().collect_vec();
            move |e| {
                let s = itertools::sorted(e.clone()).collect_vec();
                for (entry, &other) in entries.iter().zip(&s) {
                    if entry != other {
                        println!("Not equal! Expected {:?} -- Found {:?}", entry, other);
                        return false;
                    }
                }
                if entries.len() != s.len() {
                    println!(
                        "Unequal lengths! Expected {:?} -- Found {:?}",
                        entries.len(),
                        s.len()
                    );
                    return false;
                }
                true
            }
        })
        .returning(|_| Ok(Vec::new()));
}

// ----- COMMAND EXECUTION TESTS -----
#[track_caller]
fn execute_success(
    command: impl CCTransaction,
    request: &TpProcessRequest,
    tx_ctx: &MockTransactionContext,
    ctx: &mut MockHandlerContext,
) {
    command.execute(request, tx_ctx, ctx).unwrap();
}

#[track_caller]
fn execute_failure(
    command: impl CCTransaction,
    request: &TpProcessRequest,
    tx_ctx: &MockTransactionContext,
    ctx: &mut MockHandlerContext,
    expected_err: &str,
) {
    let result = command.execute(request, tx_ctx, ctx).unwrap_err();
    match result.downcast_ref::<CCApplyError>() {
        Some(CCApplyError::InvalidTransaction(s)) => {
            assert_eq!(s, expected_err);
        }
        _ => panic!("Expected an InvalidTransaction error"),
    };
}

// --- SendFunds ---

#[test]
fn send_funds_success() {
    init_logs();
    let destination = SigHash("destination".into());
    let command = SendFunds {
        amount: 1.into(),
        sighash: destination.clone(),
    };

    let request = TpProcessRequest::default();

    let mut tx_ctx = MockTransactionContext::default();

    let my_sighash = SigHash("mysighash".into());
    let my_wallet_id = WalletId::from(&my_sighash);
    let dest_wallet_id = WalletId::from(&destination);

    let mut ctx = MockHandlerContext::default();
    expect!(ctx, sighash -> my_sighash);

    let amount_needed = command.amount.clone() + &*TX_FEE;

    expect!(tx_ctx, get balance at my_wallet_id -> Some(amount_needed));
    expect!(tx_ctx, get balance at dest_wallet_id -> Some(0));

    let guid = Guid("txnguid".into());

    expect!(ctx, guid -> guid);

    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            (my_wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            (dest_wallet_id.to_string(), wallet_with(Some(1)).unwrap()),
            make_fee(&guid, &my_sighash, None),
        ],
    );

    command.execute(&request, &tx_ctx, &mut ctx).unwrap();
}

#[test]
fn send_funds_cannot_afford_fee() {
    init_logs();

    let destination = SigHash::from("destination");
    let command = SendFunds {
        amount: 1.into(),
        sighash: destination.clone(),
    };

    let request = TpProcessRequest::default();

    let mut tx_ctx = MockTransactionContext::default();

    let my_sighash = SigHash::from("mysighash");
    let my_wallet_id = WalletId::from(&my_sighash);

    let mut ctx = MockHandlerContext::default();
    expect!(ctx, sighash -> my_sighash);

    expect!(tx_ctx, get balance at my_wallet_id -> Some(1));

    execute_failure(command, &request, &tx_ctx, &mut ctx, "Insufficient funds");
}

#[test]
fn send_funds_cannot_afford_amount() {
    init_logs();

    let destination = SigHash::from("destination");
    let command = SendFunds {
        amount: 1.into(),
        sighash: destination.clone(),
    };

    let request = TpProcessRequest::default();

    let mut tx_ctx = MockTransactionContext::default();

    let my_sighash = SigHash::from("mysighash");
    let my_wallet_id = WalletId::from(&my_sighash);

    let mut ctx = MockHandlerContext::default();
    expect!(ctx, sighash -> my_sighash);

    expect!(tx_ctx, get balance at my_wallet_id -> Some(TX_FEE.clone()));

    execute_failure(command, &request, &tx_ctx, &mut ctx, "Insufficient funds");
}

#[test]
fn send_funds_to_self() {
    init_logs();

    let destination = SigHash::from("mysighash");
    let command = SendFunds {
        amount: 1.into(),
        sighash: destination.clone(),
    };

    let request = TpProcessRequest::default();

    let tx_ctx = MockTransactionContext::default();

    let my_sighash = SigHash::from("mysighash");

    let mut ctx = MockHandlerContext::default();
    expect!(ctx, sighash -> my_sighash);

    execute_failure(command, &request, &tx_ctx, &mut ctx, "Invalid destination");
}

// --- RegisterAddress ---

fn charge_fee(tx_ctx: &mut MockTransactionContext, sighash: &SigHash) {
    let wallet_id = WalletId::from(sighash);
    let fee = TX_FEE.clone();
    expect!(tx_ctx, get balance at wallet_id -> Some(fee));
}

#[test]
fn register_address_success() {
    init_logs();

    let command = RegisterAddress {
        blockchain: "ethereum".into(),
        address: "myaddress".into(),
        network: "rinkeby".into(),
    };

    let request = TpProcessRequest::default();

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let my_sighash = SigHash::from("mysighash");
    let guid = Guid::from("myguid");

    expect!(ctx, sighash -> my_sighash);
    expect!(ctx, guid -> guid);

    let wallet_id = WalletId::from(&my_sighash);
    let fee = TX_FEE.clone();
    expect!(tx_ctx, get balance at wallet_id -> Some(fee));

    let register_id = string!("ethereum", "myaddress", "rinkeby");
    let address = Address::with_prefix_key(ADDR, &register_id);

    // check if there is an existing address, in this case we will pretend that there is not one
    expect!(tx_ctx, get_state_entry where enclose!((address) move |a| &a == &address.as_str()), returning |_| Ok(None));

    let address_proto = crate::protos::Address {
        blockchain: command.blockchain.clone(),
        value: command.address.clone(),
        network: command.network.clone(),
        sighash: my_sighash.to_string(),
    };

    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            (address.to_string(), address_proto.to_bytes()),
            (wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            make_fee(&guid, &my_sighash, None),
        ],
    );

    execute_success(command, &request, &tx_ctx, &mut ctx);
}

#[test]
fn register_address_taken() {
    init_logs();

    let command = RegisterAddress {
        blockchain: "ethereum".into(),
        address: "myaddress".into(),
        network: "rinkeby".into(),
    };

    let request = TpProcessRequest::default();

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let my_sighash = SigHash::from("mysighash");

    expect!(ctx, sighash -> my_sighash);

    let wallet_id = WalletId::from(&my_sighash);
    let fee = TX_FEE.clone();
    expect!(tx_ctx, get balance at wallet_id -> Some(fee));

    let register_id = string!("ethereum", "myaddress", "rinkeby");
    let address = Address::with_prefix_key(ADDR, &register_id);

    let existing_address = protos::Address {
        blockchain: command.blockchain.clone(),
        value: command.address.clone(),
        network: command.network.clone(),
        sighash: my_sighash.to_string(),
    };

    // check if there is an existing address, in this case we will pretend that there IS one
    expect!(tx_ctx, get_state_entry where enclose!((address) move |a| &a == &address.as_str()), returning move |_| Ok(Some(existing_address.to_bytes())));

    execute_failure(
        command,
        &request,
        &tx_ctx,
        &mut ctx,
        "The address has been already registered",
    );
}

#[test]
fn register_transfer_success() {
    init_logs();

    let command = RegisterTransfer {
        gain: 1.into(),
        order_id: string!(DEAL_ORDER_PREFIX, "orderid"),
        blockchain_tx_id: "blockchaintxid".into(),
    };

    let request = TpProcessRequest::default();

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let my_sighash = SigHash::from("mysighash");
    let other_sighash = SigHash::from("othersighash");

    expect!(ctx, sighash -> my_sighash);

    let wallet_id = WalletId::from(&my_sighash);
    let fee = TX_FEE.clone();
    expect!(tx_ctx, get balance at wallet_id -> Some(fee));

    let src_address_id = "srcaddress".to_string();
    let dst_address_id = "destaddress".to_string();

    let order_address = command.order_id.clone();
    let deal_order = protos::DealOrder {
        blockchain: "ethereum".into(),
        src_address: src_address_id.clone(),
        dst_address: dst_address_id.clone(),
        amount: 1.to_string(),
        sighash: my_sighash.to_string(),
        ..Default::default()
    };

    expect!(tx_ctx, get_state_entry where enclose!((order_address => address) move |a| &a == &address.as_str()), returning enclose!((deal_order) move |_| Ok(Some(deal_order.to_bytes()))));

    let src_address = protos::Address {
        blockchain: deal_order.blockchain.clone(),
        value: "aaaaaaaaaa".into(),
        network: "rinkeby".into(),
        sighash: other_sighash.to_string(),
    };
    let dst_address = protos::Address {
        blockchain: deal_order.blockchain.clone(),
        value: "aaaaaaaaaa".into(),
        network: "rinkeby".into(),
        sighash: my_sighash.to_string(),
    };

    expect!(tx_ctx, get_state_entry where enclose!((dst_address_id => address) move |a| &a == &address), returning enclose!((dst_address) move |_| Ok(Some(dst_address.to_bytes()))));
    expect!(tx_ctx, get_state_entry where enclose!((src_address_id => address) move |a| &a == &address), returning enclose!((src_address) move |_| Ok(Some(src_address.to_bytes()))));

    let transfer_id = Address::with_prefix_key(
        TRANSFER,
        &string!(
            &src_address.blockchain,
            &command.blockchain_tx_id,
            &src_address.network
        ),
    );

    let transfer = protos::Transfer {
        blockchain: src_address.blockchain.clone(),
        src_address: dst_address_id.clone(),
        dst_address: src_address_id.clone(),
        order: command.order_id.clone(),
        amount: (command.gain.clone() + 1u64).to_string(),
        tx: command.blockchain_tx_id.clone(),
        sighash: my_sighash.to_string(),
        block: 0.to_string(),
        processed: false,
    };

    expect!(tx_ctx, get_state_entry where enclose!((transfer_id => tf_id) move |a| &a == &tf_id.as_str()), returning move |_| Ok(None));

    expect!(ctx, verify(_) -> Ok(()));

    let guid = Guid::from("guid");

    expect!(ctx, guid -> guid);

    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            (transfer_id.to_string(), transfer.to_bytes()),
            (wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            make_fee(&guid, &my_sighash, None),
        ],
    );

    execute_success(command, &request, &tx_ctx, &mut ctx);
}

// --- AddAskOrder ---

#[test]
fn add_ask_order_success() {
    init_logs();

    let command = AddAskOrder {
        address_id: "addressid".into(),
        amount_str: "1000".into(),
        interest: "10000".into(),
        maturity: "100".into(),
        fee: "1".into(),
        expiration: 10000.into(),
    };

    let request = TpProcessRequest {
        tip: 1,
        ..Default::default()
    };

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let my_sighash = SigHash::from("mysighash");
    expect!(ctx, sighash -> my_sighash);

    let guid = Guid::from("txnguid");
    expect!(ctx, guid -> guid);
    expect!(ctx, guid -> guid);

    let address = Address::with_prefix_key(ASK_ORDER, guid.as_str());

    expect!(tx_ctx, get_state_entry where enclose!((address) move |a| a == address.as_str()), returning |_| Ok(None));

    let address_proto = protos::Address {
        blockchain: "ethereum".into(),
        network: "rinkeby".into(),
        sighash: my_sighash.clone().into(),
        value: "somevalue".into(),
    };

    expect!(tx_ctx,
        get_state_entry
            where enclose!((command.address_id => address_id) move |a| a == &address_id),
        returning enclose!((my_sighash, address_proto) move |_| Ok(Some(
            address_proto.to_bytes()
        )))
    );

    let ask_order = protos::AskOrder {
        blockchain: address_proto.blockchain.clone(),
        address: command.address_id.clone(),
        amount: command.amount_str.clone(),
        interest: command.interest.clone(),
        maturity: command.maturity.clone(),
        fee: command.fee.clone(),
        expiration: command.expiration.into(),
        block: (request.tip - 1).to_string(),
        sighash: my_sighash.to_string(),
    };

    let wallet_id = WalletId::from(&my_sighash);

    expect!(tx_ctx, get balance at wallet_id -> Some(TX_FEE.clone()));

    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            (address.into(), ask_order.to_bytes()),
            (wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            make_fee(&guid, &my_sighash, None),
        ],
    );

    execute_success(command, &request, &tx_ctx, &mut ctx);
}

// --- AddBidOrder ---
#[test]
fn add_bid_order_success() {
    init_logs();

    let command = AddBidOrder {
        address_id: "addressid".into(),
        amount_str: "1000".into(),
        interest: "10000".into(),
        maturity: "100".into(),
        fee: "1".into(),
        expiration: 10000.into(),
    };

    let request = TpProcessRequest {
        tip: 1,
        ..Default::default()
    };

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let my_sighash = SigHash::from("mysighash");
    expect!(ctx, sighash -> my_sighash);

    let guid = Guid::from("txnguid");
    expect!(ctx, guid -> guid);
    expect!(ctx, guid -> guid);

    let address = Address::with_prefix_key(BID_ORDER, guid.as_str());

    expect!(tx_ctx, get_state_entry where enclose!((address) move |a| a == address.as_str()), returning |_| Ok(None));

    let address_proto = protos::Address {
        blockchain: "ethereum".into(),
        network: "rinkeby".into(),
        sighash: my_sighash.clone().into(),
        value: "somevalue".into(),
    };

    expect!(tx_ctx,
        get_state_entry
            where enclose!((command.address_id => address_id) move |a| a == &address_id),
        returning enclose!((my_sighash, address_proto) move |_| Ok(Some(
            address_proto.to_bytes()
        )))
    );

    let ask_order = protos::BidOrder {
        blockchain: address_proto.blockchain.clone(),
        address: command.address_id.clone(),
        amount: command.amount_str.clone(),
        interest: command.interest.clone(),
        maturity: command.maturity.clone(),
        fee: command.fee.clone(),
        expiration: command.expiration.into(),
        block: (request.tip - 1).to_string(),
        sighash: my_sighash.to_string(),
    };

    let wallet_id = WalletId::from(&my_sighash);

    expect!(tx_ctx, get balance at wallet_id -> Some(TX_FEE.clone()));

    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            (address.into(), ask_order.to_bytes()),
            (wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            make_fee(&guid, &my_sighash, None),
        ],
    );

    execute_success(command, &request, &tx_ctx, &mut ctx);
}

// --- AddOffer ---

#[test]
fn add_offer_success() {
    init_logs();

    let command = AddOffer {
        ask_order_id: "askorderid".into(),
        bid_order_id: "bidorderid".into(),
        expiration: 10000.into(),
    };

    let request = TpProcessRequest {
        tip: 5,
        ..Default::default()
    };

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let my_sighash = SigHash::from("mysighash");
    expect!(ctx, sighash -> my_sighash);

    let guid = Guid::from("txnguid");
    expect!(ctx, guid -> guid);

    let wallet_id = WalletId::from(&my_sighash);
    expect!(tx_ctx, get balance at wallet_id -> Some(TX_FEE.clone()));

    let offer_address = Address::with_prefix_key(
        OFFER,
        &string!(&command.ask_order_id, &command.bid_order_id),
    );

    expect!(tx_ctx, get_state_entry where enclose!((offer_address => address_id) move |a| a == address_id.as_str()), returning |_| Ok(None));

    // expect!(tx_ctx, get_state_entry where enclose!((offer_address -> address_id) move |a| a == address_id.as_str()), returning |_| Ok(None));

    let ask_order = protos::AskOrder {
        blockchain: "ethereum".into(),
        address: "askaddressid".into(),
        amount: "1000".into(),
        interest: "10000".into(),
        maturity: "100".into(),
        fee: "1".into(),
        expiration: 1000,
        block: 0.to_string(),
        sighash: my_sighash.to_string(),
    };

    expect!(tx_ctx, get_state_entry where enclose! { (command.ask_order_id => id) move |a|
        a == id
    }, returning enclose!((ask_order) move |_| Ok(Some(ask_order.to_bytes()))));

    let bid_sighash = SigHash::from("biddersighash");

    let bid_order = protos::BidOrder {
        blockchain: "ethereum".into(),
        address: "bidaddressid".into(),
        amount: "1000".into(),
        interest: "10000".into(),
        maturity: "100".into(),
        fee: "1".into(),
        expiration: 1000,
        block: 1.to_string(),
        sighash: bid_sighash.to_string(),
    };

    expect!(tx_ctx, get_state_entry where enclose! { (command.bid_order_id => id) move |a|
        a == id
    }, returning enclose!((bid_order) move |_| Ok(Some(bid_order.to_bytes()))));

    let src_address_proto = protos::Address {
        blockchain: "ethereum".into(),
        network: "rinkeby".into(),
        sighash: my_sighash.clone().into(),
        value: "somevalue".into(),
    };

    expect!(tx_ctx, get_state_entry where enclose! { (ask_order.address => id) move |a|
        a == id
    }, returning enclose!((src_address_proto) move |_| Ok(Some(src_address_proto.to_bytes()))));

    let dest_address_proto = protos::Address {
        blockchain: "ethereum".into(),
        network: "rinkeby".into(),
        sighash: bid_sighash.clone().into(),
        value: "somevalue".into(),
    };
    expect!(tx_ctx, get_state_entry where enclose! { (bid_order.address => id) move |a|
        a == id
    }, returning enclose!((dest_address_proto) move |_| Ok(Some(dest_address_proto.to_bytes()))));

    let offer = protos::Offer {
        blockchain: src_address_proto.blockchain.clone(),
        ask_order: command.ask_order_id.clone(),
        bid_order: command.bid_order_id.clone(),
        expiration: command.expiration.into(),
        block: (request.tip - 1).to_string(),
        sighash: my_sighash.to_string(),
    };

    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            (offer_address.into(), offer.to_bytes()),
            (wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            make_fee(&guid, &my_sighash, Some(request.tip - 1)),
        ],
    );

    execute_success(command, &request, &tx_ctx, &mut ctx);
}

// --- AddDealOrder ---

#[test]
fn add_deal_order_success() {
    init_logs();

    let command = AddDealOrder {
        offer_id: "someofferid".into(),
        expiration: 10000.into(),
    };

    let request = TpProcessRequest {
        tip: 5,
        ..Default::default()
    };

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let address_id = Address::with_prefix_key(DEAL_ORDER, &command.offer_id);

    // Check for existing deal order
    expect!(tx_ctx, get_state_entry where enclose! {(address_id) move |a| a == address_id.as_str()}, returning |_| Ok(None));

    let my_sighash = SigHash::from("mysighash");

    // Get the sighash of the transaction submitter
    expect!(ctx, sighash -> my_sighash);

    let offer = protos::Offer {
        blockchain: "ethereum".into(),
        ask_order: "askorderid".into(),
        bid_order: "bidorderid".into(),
        expiration: 10000,
        block: 4.to_string(),
        sighash: my_sighash.to_string(),
    };

    // Get the offer specified in the transaction
    expect!(
        tx_ctx,
        get_state_entry
            where enclose! { (command.offer_id => offer_id) move |a|
                a == offer_id
            },
        returning enclose! { (offer) move |_|
            Ok(Some(offer.to_bytes()))
        }
    );

    let bid_order = protos::BidOrder {
        blockchain: offer.blockchain.clone(),
        address: "bidorderaddress".into(),
        amount: 1.to_string(),
        interest: 100.to_string(),
        maturity: 1000.to_string(),
        fee: 1.to_string(),
        expiration: 10000,
        block: 2.to_string(),
        sighash: my_sighash.to_string(),
    };

    // Get the bid order specified in the offer
    expect!(
        tx_ctx,
        get_state_entry
            where enclose! { (offer.bid_order => id) move|a|
                a == id
            },
        returning enclose! { (bid_order) move |_|
            Ok(Some(bid_order.to_bytes()))
        }
    );

    let other_sighash = SigHash::from("othersighash");

    let ask_order = protos::AskOrder {
        blockchain: offer.blockchain.clone(),
        address: "askorderaddress".into(),
        amount: 2.to_string(),
        interest: 100.to_string(),
        maturity: 1000.to_string(),
        fee: 1.to_string(),
        expiration: 10000,
        block: 1.to_string(),
        sighash: other_sighash.to_string(),
    };

    // Get the ask order specified in the offer
    expect!(
        tx_ctx,
        get_state_entry
            where enclose! { (offer.ask_order => id) move |a|
                a == id
            },
        returning enclose! { (ask_order) move|_|
            Ok(Some(ask_order.to_bytes()))
        }
    );

    // Make sure the fundraiser has enough wallet balance to cover the bid order fee + standard txn fee
    let wallet_id = WalletId::from(&my_sighash);
    let balance = Integer::try_parse(&bid_order.fee).unwrap() + &*TX_FEE;
    expect!(tx_ctx, get balance at wallet_id -> Some(balance));

    // Construct the deal order
    let deal_order = protos::DealOrder {
        blockchain: offer.blockchain,
        src_address: ask_order.address,
        dst_address: bid_order.address,
        amount: bid_order.amount,
        interest: bid_order.interest,
        maturity: bid_order.maturity,
        fee: bid_order.fee,
        expiration: command.expiration.into(),
        sighash: my_sighash.to_string(),
        block: (request.tip - 1).to_string(),
        ..Default::default()
    };

    let guid = Guid::from("txnguid");
    expect!(ctx, guid -> guid);

    // Set new states
    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            // update fundraiser wallet to balance - fee
            (wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            // register a new fee, for return later
            make_fee(&guid, &my_sighash, Some(request.tip - 1)),
            // add the new deal order to state
            (address_id.to_string(), deal_order.to_bytes()),
        ],
    );

    expect_delete_state_entries(
        &mut tx_ctx,
        vec![
            offer.ask_order.clone(),
            offer.bid_order.clone(),
            command.offer_id.clone(),
        ],
    );

    execute_success(command, &request, &tx_ctx, &mut ctx);
}

fn expect_get_state_entry(
    tx_ctx: &mut MockTransactionContext,
    id: impl Into<String>,
    ret: Option<impl Message + Default>,
    times: Option<usize>,
) {
    let id = id.into();
    let ret = ret.map(|m| m.to_bytes());
    tx_ctx
        .expect_get_state_entry()
        .times(times.unwrap_or(1))
        .withf(move |m| m == &id)
        .return_once({
            let ret = ret.clone();
            |_| Ok(ret)
        });
}

// --- CompleteDealOrder ---

#[test]
fn complete_deal_order_success() {
    let command = CompleteDealOrder {
        deal_order_id: "dealorderid".into(),
        transfer_id: "transferid".into(),
    };

    let request = TpProcessRequest {
        tip: 5,
        ..Default::default()
    };

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let my_sighash = SigHash::from("mysighash");

    expect!(ctx, sighash -> my_sighash);

    // Construct the deal order
    let deal_order = protos::DealOrder {
        blockchain: "ethereum".into(),
        src_address: "srcaddressid".into(),
        dst_address: "dstaddressid".into(),
        amount: 1.to_string(),
        sighash: my_sighash.to_string(),
        maturity: 1000.to_string(),
        fee: 1.to_string(),
        expiration: 10000,
        block: 2.to_string(),
        ..Default::default()
    };

    expect_get_state_entry(
        &mut tx_ctx,
        &command.deal_order_id,
        Some(deal_order.clone()),
        Some(1),
    );

    let src_address = protos::Address {
        blockchain: deal_order.blockchain.clone(),
        value: "someaddressvalue".into(),
        network: "rinkeby".into(),
        sighash: my_sighash.to_string(),
    };

    expect_get_state_entry(
        &mut tx_ctx,
        &deal_order.src_address,
        Some(src_address.clone()),
        Some(1),
    );

    let transfer = protos::Transfer {
        blockchain: deal_order.blockchain.clone(),
        src_address: deal_order.src_address.clone(),
        dst_address: deal_order.dst_address.clone(),
        order: command.deal_order_id.clone(),
        amount: deal_order.amount.clone(),
        tx: "sometx".into(),
        block: (request.tip - 1).to_string(),
        processed: false,
        sighash: my_sighash.to_string(),
    };

    expect_get_state_entry(
        &mut tx_ctx,
        command.transfer_id.clone(),
        Some(transfer.clone()),
        Some(1),
    );

    let wallet_id = WalletId::from(&my_sighash);
    let fee = &*TX_FEE - Integer::try_parse(&deal_order.fee).unwrap();
    expect!(tx_ctx, get balance at wallet_id -> Some(fee));

    let updated_transfer = protos::Transfer {
        processed: true,
        ..transfer
    };

    let updated_deal_order = protos::DealOrder {
        loan_transfer: command.transfer_id.clone(),
        block: (request.tip - 1).to_string(),
        ..deal_order.clone()
    };

    let guid = Guid::from("txnguid");
    expect!(ctx, guid -> guid);

    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            (wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            make_fee(&guid, &my_sighash, Some(request.tip - 1)),
            (command.transfer_id.clone(), updated_transfer.to_bytes()),
            (command.deal_order_id.clone(), updated_deal_order.to_bytes()),
        ],
    );

    execute_success(command, &request, &tx_ctx, &mut ctx);
}

// --- LockDealOrder ---

#[test]
fn lock_deal_order_success() {
    init_logs();

    let command = LockDealOrder {
        deal_order_id: "dealorderid".into(),
    };

    let request = TpProcessRequest {
        tip: 6,
        ..Default::default()
    };

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let my_sighash = SigHash::from("mysighash");

    expect!(ctx, sighash -> my_sighash);

    // Construct the deal order
    let deal_order = protos::DealOrder {
        blockchain: "ethereum".into(),
        src_address: "srcaddressid".into(),
        dst_address: "dstaddressid".into(),
        amount: 1.to_string(),
        sighash: my_sighash.to_string(),
        maturity: 1000.to_string(),
        fee: 1.to_string(),
        expiration: 10000,
        block: 4.to_string(),
        loan_transfer: "transferid".into(),
        ..Default::default()
    };

    expect_get_state_entry(
        &mut tx_ctx,
        command.deal_order_id.clone(),
        Some(deal_order.clone()),
        Some(1),
    );

    let wallet_id = WalletId::from(&my_sighash);
    let fee = TX_FEE.clone();
    expect!(tx_ctx, get balance at wallet_id -> Some(fee));

    let guid = Guid::from("txnguid");
    expect!(ctx, guid -> guid);

    let updated_deal_order = protos::DealOrder {
        lock: my_sighash.to_string(),
        ..deal_order
    };

    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            (wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            make_fee(&guid, &my_sighash, Some(request.tip - 1)),
            (command.deal_order_id.clone(), updated_deal_order.to_bytes()),
        ],
    );

    execute_success(command, &request, &tx_ctx, &mut ctx);
}

// --- CloseDealOrder ---

#[test]
fn close_deal_order_success() {
    init_logs();

    let command = CloseDealOrder {
        deal_order_id: "dealorderid".into(),
        transfer_id: "repaytransferid".into(),
    };

    let request = TpProcessRequest {
        tip: 7,
        ..Default::default()
    };

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let my_sighash = SigHash::from("mysighash");

    expect!(ctx, sighash -> my_sighash);

    // Construct the deal order
    let deal_order = protos::DealOrder {
        blockchain: "ethereum".into(),
        src_address: "srcaddressid".into(),
        dst_address: "dstaddressid".into(),
        amount: 1.to_string(),
        maturity: 1000.to_string(),
        fee: 1.to_string(),
        expiration: 10000,
        block: 4.to_string(),
        loan_transfer: "transferid".into(),
        lock: my_sighash.to_string(),
        sighash: my_sighash.to_string(),
        interest: 0.to_string(),
        ..Default::default()
    };

    expect_get_state_entry(
        &mut tx_ctx,
        command.deal_order_id.clone(),
        Some(deal_order.clone()),
        Some(1),
    );

    let loan_transfer = protos::Transfer {
        blockchain: deal_order.blockchain.clone(),
        src_address: deal_order.src_address.clone(),
        dst_address: deal_order.dst_address.clone(),
        order: command.deal_order_id.clone(),
        amount: deal_order.amount.clone(),
        tx: "sometx".into(),
        block: (request.tip - 1).to_string(),
        processed: false,
        sighash: my_sighash.to_string(),
    };

    expect_get_state_entry(
        &mut tx_ctx,
        deal_order.loan_transfer.clone(),
        Some(loan_transfer.clone()),
        Some(1),
    );

    let repayment_transfer = protos::Transfer {
        blockchain: deal_order.blockchain.clone(),
        src_address: deal_order.src_address.clone(),
        dst_address: deal_order.dst_address.clone(),
        order: command.deal_order_id.clone(),
        amount: deal_order.amount.clone(),
        tx: "somerepaytx".into(),
        block: (request.tip - 1).to_string(),
        processed: false,
        sighash: my_sighash.to_string(),
    };

    expect_get_state_entry(
        &mut tx_ctx,
        command.transfer_id.clone(),
        Some(repayment_transfer.clone()),
        Some(1),
    );

    let wallet_id = WalletId::from(&my_sighash);
    let fee = TX_FEE.clone();
    expect!(tx_ctx, get balance at wallet_id -> Some(fee));

    let guid = Guid::from("txnguid");
    expect!(ctx, guid -> guid);

    let updated_deal_order = protos::DealOrder {
        lock: my_sighash.to_string(),
        repayment_transfer: command.transfer_id.clone(),
        ..deal_order
    };

    let updated_repayment_transfer = protos::Transfer {
        processed: true,
        ..repayment_transfer
    };
    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            (wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            make_fee(&guid, &my_sighash, Some(request.tip - 1)),
            (command.deal_order_id.clone(), updated_deal_order.to_bytes()),
            (
                command.transfer_id.clone(),
                updated_repayment_transfer.to_bytes(),
            ),
        ],
    );

    execute_success(command, &request, &tx_ctx, &mut ctx);
}

// --- Exempt ---

#[test]
fn exempt_success() {
    init_logs();

    let command = Exempt {
        deal_order_id: "dealorderid".into(),
        transfer_id: "repaytransferid".into(),
    };

    let request = TpProcessRequest {
        tip: 7,
        ..Default::default()
    };

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let my_sighash = SigHash::from("mysighash");

    expect!(ctx, sighash -> my_sighash);

    // Construct the deal order
    let deal_order = protos::DealOrder {
        blockchain: "ethereum".into(),
        src_address: "srcaddressid".into(),
        dst_address: "dstaddressid".into(),
        amount: 1.to_string(),
        maturity: 1000.to_string(),
        fee: 1.to_string(),
        expiration: 10000,
        block: 4.to_string(),
        loan_transfer: "transferid".into(),
        sighash: my_sighash.to_string(),
        interest: 0.to_string(),
        ..Default::default()
    };

    expect_get_state_entry(
        &mut tx_ctx,
        command.deal_order_id.clone(),
        Some(deal_order.clone()),
        Some(1),
    );

    let repayment_transfer = protos::Transfer {
        blockchain: deal_order.blockchain.clone(),
        src_address: deal_order.src_address.clone(),
        dst_address: deal_order.dst_address.clone(),
        order: command.deal_order_id.clone(),
        amount: deal_order.amount.clone(),
        tx: "somerepaytx".into(),
        block: (request.tip - 1).to_string(),
        processed: false,
        sighash: my_sighash.to_string(),
    };

    expect_get_state_entry(
        &mut tx_ctx,
        command.transfer_id.clone(),
        Some(repayment_transfer.clone()),
        Some(1),
    );

    let src_address = protos::Address {
        blockchain: deal_order.blockchain.clone(),
        value: "srcaddressvalue".into(),
        network: "rinkeby".into(),
        sighash: my_sighash.to_string(),
    };

    expect_get_state_entry(
        &mut tx_ctx,
        deal_order.src_address.clone(),
        Some(src_address.clone()),
        Some(1),
    );

    let wallet_id = WalletId::from(&my_sighash);
    let fee = TX_FEE.clone();
    expect!(tx_ctx, get balance at wallet_id -> Some(fee));

    let guid = Guid::from("txnguid");
    expect!(ctx, guid -> guid);

    let updated_deal_order = protos::DealOrder {
        repayment_transfer: command.transfer_id.clone(),
        ..deal_order
    };

    let updated_repayment_transfer = protos::Transfer {
        processed: true,
        ..repayment_transfer
    };
    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            (wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            make_fee(&guid, &my_sighash, Some(request.tip - 1)),
            (command.deal_order_id.clone(), updated_deal_order.to_bytes()),
            (
                command.transfer_id.clone(),
                updated_repayment_transfer.to_bytes(),
            ),
        ],
    );

    execute_success(command, &request, &tx_ctx, &mut ctx);
}

// --- AddRepaymentOrder ---

#[test]
fn add_repayment_order_success() {
    init_logs();

    let command = AddRepaymentOrder {
        deal_order_id: "dealorderid".into(),
        address_id: "buyeraddressid".into(),
        amount: 5.to_string(),
        expiration: 10000.into(),
    };

    let request = TpProcessRequest {
        tip: 7,
        ..Default::default()
    };

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let fundraiser_sighash = SigHash::from("fundraisersighash");

    let my_sighash = SigHash::from("loanersighash");

    let other_investor_sighash = SigHash::from("otherinvestorsighash");

    expect!(ctx, sighash -> my_sighash);

    let wallet_id = WalletId::from(&my_sighash);
    let fee = TX_FEE.clone();
    expect!(tx_ctx, get balance at wallet_id -> Some(fee));

    let guid = Guid::from("txnguid");
    expect!(ctx, guid -> guid);

    let repay_id = Address::with_prefix_key(REPAYMENT_ORDER, &guid);

    expect_get_state_entry(&mut tx_ctx, &repay_id, Option::<String>::None, Some(1));

    // Construct the deal order
    let deal_order = protos::DealOrder {
        blockchain: "ethereum".into(),
        src_address: "srcaddressid".into(),
        dst_address: "dstaddressid".into(),
        amount: 1.to_string(),
        maturity: 1000.to_string(),
        fee: 1.to_string(),
        expiration: 10000,
        block: 4.to_string(),
        loan_transfer: "transferid".into(),
        sighash: fundraiser_sighash.to_string(),
        interest: 0.to_string(),
        ..Default::default()
    };

    expect_get_state_entry(
        &mut tx_ctx,
        command.deal_order_id.clone(),
        Some(deal_order.clone()),
        Some(1),
    );

    let src_address = protos::Address {
        blockchain: deal_order.blockchain.clone(),
        value: "srcaddressvalue".into(),
        network: "rinkeby".into(),
        sighash: other_investor_sighash.to_string(),
    };

    expect_get_state_entry(
        &mut tx_ctx,
        deal_order.src_address.clone(),
        Some(src_address.clone()),
        Some(1),
    );

    let new_address = protos::Address {
        value: "newaddressvalue".into(),
        sighash: my_sighash.to_string(),
        ..src_address.clone()
    };

    expect_get_state_entry(
        &mut tx_ctx,
        command.address_id.clone(),
        Some(new_address.clone()),
        Some(1),
    );

    expect!(ctx, guid -> guid);

    let repayment_order = protos::RepaymentOrder {
        blockchain: src_address.blockchain,
        src_address: command.address_id.clone(),
        dst_address: deal_order.src_address,
        amount: command.amount.clone(),
        expiration: command.expiration.into(),
        block: (request.tip - 1).to_string(),
        deal: command.deal_order_id.clone(),
        sighash: my_sighash.to_string(),
        ..Default::default()
    };

    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            (wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            make_fee(&guid, &my_sighash, Some(request.tip - 1)),
            (repay_id.to_string(), repayment_order.to_bytes()),
        ],
    );

    execute_success(command, &request, &tx_ctx, &mut ctx);
}

// --- CompleteRepaymentOrder ---

#[test]
fn complete_repayment_order_success() {
    init_logs();

    let command = CompleteRepaymentOrder {
        repayment_order_id: "repayorderid".into(),
    };

    let request = TpProcessRequest {
        tip: 8,
        ..Default::default()
    };

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let fundraiser_sighash = SigHash::from("fundraisersighash");

    let my_sighash = SigHash::from("investorsighash");

    let buyer_sighash = SigHash::from("buyersighash");

    expect!(ctx, sighash -> my_sighash);

    let wallet_id = WalletId::from(&my_sighash);
    let fee = TX_FEE.clone();
    expect!(tx_ctx, get balance at wallet_id -> Some(fee));

    let guid = Guid::from("txnguid");
    expect!(ctx, guid -> guid);

    let deal_order_id = "dealorderid".to_string();

    let deal_order = protos::DealOrder {
        blockchain: "ethereum".into(),
        src_address: "srcaddressid".into(),
        dst_address: "dstaddressid".into(),
        amount: 1.to_string(),
        maturity: 1000.to_string(),
        fee: 1.to_string(),
        expiration: 10000,
        block: 4.to_string(),
        loan_transfer: "transferid".into(),
        sighash: fundraiser_sighash.to_string(),
        interest: 0.to_string(),
        ..Default::default()
    };

    expect_get_state_entry(
        &mut tx_ctx,
        &deal_order_id,
        Some(deal_order.clone()),
        Some(1),
    );

    let repayment_order = protos::RepaymentOrder {
        blockchain: "ethereum".into(),
        src_address: "buyeraddressid".into(),
        dst_address: deal_order.src_address.clone(),
        amount: 5.to_string(),
        expiration: 10000,
        block: (request.tip - 2).to_string(),
        deal: deal_order_id.clone(),
        sighash: buyer_sighash.to_string(),
        ..Default::default()
    };

    expect_get_state_entry(
        &mut tx_ctx,
        &command.repayment_order_id,
        Some(repayment_order.clone()),
        Some(1),
    );

    let dst_address = protos::Address {
        blockchain: repayment_order.blockchain.clone(),
        value: "oldsrcaddressvalue".into(),
        network: "rinkeby".into(),
        sighash: my_sighash.to_string(),
    };

    expect_get_state_entry(
        &mut tx_ctx,
        repayment_order.dst_address.clone(),
        Some(dst_address.clone()),
        Some(1),
    );

    let updated_repayment_order = protos::RepaymentOrder {
        previous_owner: my_sighash.to_string(),
        ..repayment_order
    };

    let updated_deal_order = protos::DealOrder {
        lock: my_sighash.to_string(),
        ..deal_order
    };

    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            (wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            make_fee(&guid, &my_sighash, Some(request.tip - 1)),
            (
                command.repayment_order_id.clone(),
                updated_repayment_order.to_bytes(),
            ),
            (deal_order_id.clone(), updated_deal_order.to_bytes()),
        ],
    );

    execute_success(command, &request, &tx_ctx, &mut ctx);
}

// --- CloseRepaymentOrder ---

#[test]
fn close_repayment_order_success() {
    init_logs();

    let command = CloseRepaymentOrder {
        repayment_order_id: "repayorderid".into(),
        transfer_id: "repaytransferid".into(),
    };

    let request = TpProcessRequest {
        tip: 9,
        ..Default::default()
    };

    let mut tx_ctx = MockTransactionContext::default();
    let mut ctx = MockHandlerContext::default();

    let fundraiser_sighash = SigHash::from("fundraisersighash");

    let my_sighash = SigHash::from("buyersighash");

    let owner_sighash = SigHash::from("investorsighash");

    expect!(ctx, sighash -> my_sighash);

    let wallet_id = WalletId::from(&my_sighash);
    let fee = TX_FEE.clone();
    expect!(tx_ctx, get balance at wallet_id -> Some(fee));

    let guid = Guid::from("txnguid");
    expect!(ctx, guid -> guid);

    let deal_order_id = "dealorderid".to_string();

    let deal_order = protos::DealOrder {
        blockchain: "ethereum".into(),
        src_address: "srcaddressid".into(),
        dst_address: "dstaddressid".into(),
        amount: 1.to_string(),
        maturity: 1000.to_string(),
        fee: 1.to_string(),
        expiration: 10000,
        block: 4.to_string(),
        loan_transfer: "transferid".into(),
        sighash: fundraiser_sighash.to_string(),
        interest: 0.to_string(),
        lock: my_sighash.to_string(),
        ..Default::default()
    };

    expect_get_state_entry(
        &mut tx_ctx,
        &deal_order_id,
        Some(deal_order.clone()),
        Some(1),
    );

    let repayment_order = protos::RepaymentOrder {
        blockchain: "ethereum".into(),
        src_address: "buyeraddressid".into(),
        dst_address: deal_order.src_address.clone(),
        amount: 5.to_string(),
        expiration: 10000,
        block: (request.tip - 2).to_string(),
        deal: deal_order_id.clone(),
        sighash: my_sighash.to_string(),
        previous_owner: owner_sighash.to_string(),
        ..Default::default()
    };

    expect_get_state_entry(
        &mut tx_ctx,
        &command.repayment_order_id,
        Some(repayment_order.clone()),
        Some(1),
    );

    let repayment_transfer = protos::Transfer {
        blockchain: repayment_order.blockchain.clone(),
        src_address: repayment_order.src_address.clone(),
        dst_address: repayment_order.dst_address.clone(),
        order: command.repayment_order_id.clone(),
        amount: repayment_order.amount.clone(),
        tx: "sometx".into(),
        block: (request.tip - 2).to_string(),
        processed: false,
        sighash: my_sighash.to_string(),
    };

    expect_get_state_entry(
        &mut tx_ctx,
        &command.transfer_id,
        Some(repayment_transfer.clone()),
        Some(1),
    );

    let dst_address = protos::Address {
        blockchain: repayment_order.blockchain.clone(),
        value: "oldsrcaddressvalue".into(),
        network: "rinkeby".into(),
        sighash: my_sighash.to_string(),
    };

    expect_get_state_entry(
        &mut tx_ctx,
        deal_order.src_address.clone(),
        Some(dst_address.clone()),
        Some(1),
    );

    let updated_repayment_order = protos::RepaymentOrder {
        transfer: command.transfer_id.clone(),
        ..repayment_order
    };

    let updated_deal_order = protos::DealOrder {
        src_address: updated_repayment_order.src_address.clone(),
        lock: "".to_string(),
        ..deal_order
    };

    let updated_transfer = protos::Transfer {
        processed: true,
        ..repayment_transfer
    };

    expect_set_state_entries(
        &mut tx_ctx,
        vec![
            (wallet_id.to_string(), wallet_with(Some(0)).unwrap()),
            make_fee(&guid, &my_sighash, Some(request.tip - 1)),
            (
                command.repayment_order_id.clone(),
                updated_repayment_order.to_bytes(),
            ),
            (deal_order_id.clone(), updated_deal_order.to_bytes()),
            (command.transfer_id.clone(), updated_transfer.to_bytes()),
        ],
    );

    execute_success(command, &request, &tx_ctx, &mut ctx);
}

// --- Housekeeping ---

#[test]
fn housekeeping_reward_in_chain() {
    init_logs();

    // Housekeeeping with block idx = 0
    let command = Housekeeping {
        block_idx: BlockNum(0),
    };

    // Chain tip is far ahead
    let request = TpProcessRequest {
        tip: u64::from((CONFIRMATION_COUNT * 2 + BLOCK_REWARD_PROCESSING_COUNT) * 4),
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
        get_setting(k if k == "sawtooth.validator.update1") -> Ok(None)
    );

    let height_start = CONFIRMATION_COUNT * 2 + BLOCK_REWARD_PROCESSING_COUNT + 1;
    let height_end = height_start + BLOCK_REWARD_PROCESSING_COUNT;

    let mut signers = vec![];

    // housekeeping tries to get the signatures for the blocks
    // from height_start to height_end in order to issue mining rewards
    // return a dummy signer
    for height in height_start.0..height_end.0 {
        let signer = format!("signer{}", height);
        signers.push(signer.clone());
        expect!(tx_ctx,
            get_sig_by_num(h if *h == height) -> Ok(signer)
        );
    }

    let reward_amount = REWARD_AMOUNT.clone();

    for (idx, signer) in signers.clone().into_iter().enumerate() {
        let wallet_id = WalletId::from(&SigHash(utils::sha512_id(signer.as_bytes())));

        // the first signer has no wallet, the rest have an existing balance of `idx`
        let balance = if idx == 0 { None } else { Some(idx as u64) };

        log::info!("starting balance = {:?}", balance);

        // housekeeping should try to fetch the current wallet for each signer
        // return the balance above
        expect!(tx_ctx, get balance at wallet_id -> balance);

        // we expect the wallet to have an updated balance of reward_amount + old balance
        let amount_expected = reward_amount.clone() + balance.unwrap_or(0);

        log::info!("expect end wallet = {:?}", amount_expected);
        // housekeeping should try to set the state to update
        // the wallet balance with the reward added
        expect!(
            tx_ctx,
            set balance at wallet_id to amount_expected
        );
    }

    // housekeeping should then set the processed_block_idx to the last processed block height
    // which in this case is height_end - 1
    expect!(tx_ctx, set_state_entry(
            addr if addr == PROCESSED_BLOCK_IDX.as_str(),
            state if state == &(height_end - 1).unwrap().to_string().into_bytes()
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
        block_idx: BlockNum(0),
    };

    let last_processed = CONFIRMATION_COUNT * 2 + BLOCK_REWARD_PROCESSING_COUNT;

    // Chain tip is far ahead
    let request = TpProcessRequest {
        tip: u64::from(last_processed * 4),
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
        get_setting(k if k == "sawtooth.validator.update1") -> Ok(None)
    );

    // the get_reward_block_signatures path iterates in reverse inclusively, so if last_processed = 5
    // and BLOCK_REWARD_PROCESSING_COUNT = 5, then the bounds
    // should be [10, 6] i.e. [last_processed + BLOCK_REWARD_PROCESSING_COUNT, last_processed+1]
    let last_pred = last_processed + 1;
    let first_pred = last_processed + BLOCK_REWARD_PROCESSING_COUNT;

    log::warn!("{}..{}", last_pred, first_pred);

    let signers: Vec<String> = (last_pred.0..first_pred.0)
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
        block_idx: BlockNum(0),
    };

    // no blocks have been processed
    let last_processed = 0;

    // Chain tip is not quite at the threshold for running because
    // the blocks have not yet gotten enough confirmations
    let request = TpProcessRequest {
        tip: u64::from(BLOCK_REWARD_PROCESSING_COUNT + 1),
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
        block_idx: BlockNum(0),
    };

    // pretend we've issued some rewards already
    let last_processed = 4 * CONFIRMATION_COUNT + BLOCK_REWARD_PROCESSING_COUNT;

    // Chain tip is not quite at the threshold for running because
    // fewer than BLOCK_REWARD_PROCESSING_COUNT additional blocks have been processed
    let request = TpProcessRequest {
        tip: (last_processed + BLOCK_REWARD_PROCESSING_COUNT.0 - 1)
            .unwrap()
            .into(),
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
