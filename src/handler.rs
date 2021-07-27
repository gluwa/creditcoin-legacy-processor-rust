pub mod constants;
pub mod context;
mod tests;
pub mod types;
pub mod utils;

use crate::{
    bail_transaction,
    ext::{ErrorExt, IntegerExt, MessageExt},
    handler::utils::{
        add_fee, get_integer, get_integer_string, get_signed_integer, get_string, get_u64,
        last_block,
    },
    protos, string,
};

use anyhow::Context;
#[cfg(not(all(test, feature = "mock")))]
use context::HandlerContext;

#[cfg(all(test, feature = "mock"))]
use context::mocked::MockHandlerContext as HandlerContext;

use constants::*;
use log::{debug, info};
use rug::{Assign, Integer};
use sawtooth_sdk::{
    messages::processor::TpProcessRequest,
    processor::handler::{ApplyError, TransactionContext, TransactionHandler},
};

use std::{convert::TryFrom, default::Default, ops::Deref};
use types::CCApplyError::InvalidTransaction;
use types::*;

use enum_dispatch::enum_dispatch;
use serde_cbor::Value;

use std::str;

use crate::protos::{DealOrder, RepaymentOrder, Wallet};
use prost::Message;

use self::utils::{add_fee_state, add_state, calc_interest, get_state_data, try_get_state_data};

#[enum_dispatch]
#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub enum CCCommand {
    SendFunds,
    RegisterAddress,
    RegisterTransfer,
    AddAskOrder,
    AddBidOrder,
    AddOffer,
    AddDealOrder,
    CompleteDealOrder,
    LockDealOrder,
    CloseDealOrder,
    Exempt,
    AddRepaymentOrder,
    CompleteRepaymentOrder,
    CloseRepaymentOrder,
    CollectCoins,
    Housekeeping,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct SendFunds {
    amount: Integer,
    sighash: SigHash,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct RegisterAddress {
    blockchain: String,
    address: String,
    network: String,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct RegisterTransfer {
    gain: Integer,
    order_id: String,
    blockchain_tx_id: String,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct AddAskOrder {
    address_id: String,
    amount_str: String,
    interest: String,
    maturity: String,
    fee: String,
    expiration: u64,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct AddBidOrder {
    address_id: String,
    amount_str: String,
    interest: String,
    maturity: String,
    fee: String,
    expiration: u64,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct AddOffer {
    ask_order_id: String,
    bid_order_id: String,
    expiration: u64,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct AddDealOrder {
    offer_id: String,
    expiration: u64,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct CompleteDealOrder {
    deal_order_id: String,
    transfer_id: String,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct LockDealOrder {
    deal_order_id: String,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct CloseDealOrder {
    deal_order_id: String,
    transfer_id: String,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct Exempt {
    deal_order_id: String,
    transfer_id: String,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct AddRepaymentOrder {
    deal_order_id: String,
    address_id: String,
    amount: String,
    expiration: u64,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct CompleteRepaymentOrder {
    repayment_order_id: String,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct CloseRepaymentOrder {
    repayment_order_id: String,
    transfer_id: String,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct CollectCoins {
    eth_address: String,
    amount: Integer,
    blockchain_tx_id: String,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub struct Housekeeping {
    block_idx: Integer,
}

impl TryFrom<Value> for CCCommand {
    type Error = anyhow::Error;

    fn try_from(value: Value) -> TxnResult<Self, Self::Error> {
        if let Value::Map(map) = value {
            let verb = get_string(&map, "v", "verb")?;
            debug!("verb = {}", verb);
            Ok(match verb.to_uppercase().as_str() {
                "SENDFUNDS" => {
                    let amount = get_integer(&map, "p1", "amount")?;
                    let sighash = SigHash(get_string(&map, "p2", "sighash")?.clone());
                    SendFunds { amount, sighash }.into()
                }

                "REGISTERADDRESS" => {
                    let blockchain = get_string(&map, "p1", "blockchain")?.to_lowercase();
                    let address = get_string(&map, "p2", "address")?.clone();
                    let network = get_string(&map, "p3", "network")?.to_lowercase();
                    RegisterAddress {
                        blockchain,
                        address,
                        network,
                    }
                    .into()
                }

                "REGISTERTRANSFER" => {
                    let gain = get_signed_integer(&map, "p1", "gain")?;
                    let order_id = get_string(&map, "p2", "orderID")?.to_lowercase();
                    let blockchain_tx_id = get_string(&map, "p3", "blockchainTxId")?.to_lowercase();
                    RegisterTransfer {
                        gain,
                        order_id,
                        blockchain_tx_id,
                    }
                    .into()
                }

                "ADDASKORDER" => {
                    let address_id = get_string(&map, "p1", "addressId")?.to_lowercase();
                    let amount_str = get_integer_string(&map, "p2", "amount")?.clone();
                    let interest = get_integer_string(&map, "p3", "interest")?.clone();
                    let maturity = get_integer_string(&map, "p4", "maturity")?.clone();
                    let fee = get_integer_string(&map, "p5", "fee")?.clone();
                    let expiration = get_u64(&map, "p6", "expiration")?;
                    AddAskOrder {
                        address_id,
                        amount_str,
                        interest,
                        maturity,
                        fee,
                        expiration,
                    }
                    .into()
                }

                "ADDBIDORDER" => {
                    let address_id = get_string(&map, "p1", "addressId")?.to_lowercase();
                    let amount_str = get_integer_string(&map, "p2", "amount")?.clone();
                    let interest = get_integer_string(&map, "p3", "interest")?.clone();
                    let maturity = get_integer_string(&map, "p4", "maturity")?.clone();
                    let fee = get_integer_string(&map, "p5", "fee")?.to_owned();
                    let expiration = get_u64(&map, "p6", "expiration")?;
                    AddBidOrder {
                        address_id,
                        amount_str,
                        interest,
                        maturity,
                        fee,
                        expiration,
                    }
                    .into()
                }

                "ADDOFFER" => {
                    let ask_order_id = get_string(&map, "p1", "askOrderId")?.to_lowercase();
                    let bid_order_id = get_string(&map, "p2", "bidOrderId")?.to_lowercase();
                    let expiration = get_u64(&map, "p3", "expiration")?;

                    AddOffer {
                        ask_order_id,
                        bid_order_id,
                        expiration,
                    }
                    .into()
                }

                "ADDDEALORDER" => {
                    let offer_id = get_string(&map, "p1", "offerId")?.to_lowercase();
                    let expiration = get_u64(&map, "p2", "expiration")?;

                    AddDealOrder {
                        offer_id,
                        expiration,
                    }
                    .into()
                }

                "COMPLETEDEALORDER" => {
                    let deal_order_id = get_string(&map, "p1", "dealOrderId")?.to_lowercase();
                    let transfer_id = get_string(&map, "p2", "transferId")?.to_lowercase();

                    CompleteDealOrder {
                        deal_order_id,
                        transfer_id,
                    }
                    .into()
                }

                "LOCKDEALORDER" => LockDealOrder {
                    deal_order_id: get_string(&map, "p1", "dealOrderId")?.to_lowercase(),
                }
                .into(),

                "CLOSEDEALORDER" => {
                    let deal_order_id = get_string(&map, "p1", "dealOrderId")?.to_lowercase();
                    let transfer_id = get_string(&map, "p2", "transferId")?.to_lowercase();

                    CloseDealOrder {
                        deal_order_id,
                        transfer_id,
                    }
                    .into()
                }

                "EXEMPT" => {
                    let deal_order_id = get_string(&map, "p1", "dealOrderId")?.to_lowercase();
                    let transfer_id = get_string(&map, "p2", "transferId")?.to_lowercase();

                    Exempt {
                        deal_order_id,
                        transfer_id,
                    }
                    .into()
                }

                "ADDREPAYMENTORDER" => {
                    let deal_order_id = get_string(&map, "p1", "dealOrderId")?.to_lowercase();
                    let address_id = get_string(&map, "p2", "addressId")?.to_lowercase();
                    let amount = get_integer_string(&map, "p3", "amount")?.clone();
                    let expiration = get_u64(&map, "p4", "expiration")?;

                    AddRepaymentOrder {
                        deal_order_id,
                        address_id,
                        amount,
                        expiration,
                    }
                    .into()
                }

                "COMPLETEREPAYMENTORDER" => CompleteRepaymentOrder {
                    repayment_order_id: get_string(&map, "p1", "repaymentOrderId")?.to_lowercase(),
                }
                .into(),

                "CLOSEREPAYMENTORDER" => CloseRepaymentOrder {
                    repayment_order_id: get_string(&map, "p1", "repaymentOrderId")?.to_lowercase(),
                    transfer_id: get_string(&map, "p2", "transferId")?.to_lowercase(),
                }
                .into(),

                "COLLECTCOINS" => CollectCoins {
                    eth_address: get_string(&map, "p1", "ethAddress")?.to_lowercase(),
                    amount: get_integer(&map, "p2", "amount")?,
                    blockchain_tx_id: get_string(&map, "p3", "blockchainTxId")?.to_lowercase(),
                }
                .into(),

                "HOUSEKEEPING" => Housekeeping {
                    block_idx: get_integer(&map, "p1", "blockIdx")?,
                }
                .into(),

                _ => bail_transaction!("Invalid verb in parameters: {:?}", verb),
            })
        } else {
            bail_transaction!(
                "Expected a Map at the top level of parameters, found {:?}",
                value
            )
        }
    }
}

fn charge(
    ctx: &HandlerContext,
    txn_ctx: &dyn TransactionContext,
    sighash: &SigHash,
) -> TxnResult<(WalletId, Wallet)> {
    let wallet_id = WalletId::from(sighash);
    let state_data = get_state_data(txn_ctx, &wallet_id).context("Failed to get wallet data")?;
    let mut wallet = Wallet::try_parse(&state_data)
        .context(format!("The wallet for {:?} is invalid", sighash))?;
    let balance = Integer::try_parse(&wallet.amount)
        .context(format!("The wallet balance for {:?} is malformed", sighash))?;

    let tx_fee = ctx.tx_fee()?;
    if tx_fee.gt(&balance) {
        bail_transaction!(
            "Insufficient funds",
            context = "Wallet balance at {:?} does not cover transaction fee",
            wallet_id
        );
    }

    wallet.amount = (balance - tx_fee).to_string_radix(10);
    Ok((wallet_id, wallet))
}

#[enum_dispatch(CCCommand)]
trait CCTransaction: Sized {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()>;
}

impl CCTransaction for SendFunds {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let my_sighash = ctx.sighash(request)?;
        if self.sighash == my_sighash {
            bail_transaction!(
                "Invalid destination",
                context = "Cannot send funds, the sender and receiver must be different"
            );
        }

        let src_wallet_id = my_sighash.to_wallet_id();
        let state_data = get_state_data(tx_ctx, &*src_wallet_id)?;

        let mut src_wallet = Wallet::try_parse(&state_data).context(format!(
            "Failed to parse source wallet at {:?} from state data",
            src_wallet_id
        ))?;
        let amount_plus_fee = self.amount.clone() + ctx.tx_fee()?;
        let mut src_balance = Integer::try_parse(&src_wallet.amount).context(format!(
            "Failed to parse wallet balance at {:?}, found {:?}",
            src_wallet_id, &src_wallet.amount
        ))?;

        if src_balance < amount_plus_fee {
            bail_transaction!(
                "Insufficient funds",
                context = "Failed to withdraw funds from source wallet"
            );
        }

        src_balance -= amount_plus_fee;
        src_wallet.amount = src_balance.to_string();

        let dest_wallet_id = self.sighash.to_wallet_id();
        let state_data = try_get_state_data(tx_ctx, &*dest_wallet_id)?;
        let dest_wallet = match state_data {
            Some(state_data) => {
                let mut dest_wallet = Wallet::try_parse(&state_data)?;
                let mut dest_balance = Integer::try_parse(&dest_wallet.amount)?;
                dest_balance += self.amount;
                dest_wallet.amount = dest_balance.to_string();
                dest_wallet
            }
            None => Wallet {
                amount: self.amount.to_string(),
            },
        };

        let mut states: StateVec = StateVec::new();
        add_state(&mut states, dest_wallet_id.into(), &dest_wallet)?;
        add_fee_state(
            ctx,
            request,
            &my_sighash,
            &mut states,
            &src_wallet_id,
            &src_wallet,
        )?;
        tx_ctx.set_state_entries(states)?;
        Ok(())
    }
}

impl CCTransaction for RegisterAddress {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let addr_str_lower = self.address.to_lowercase();

        let my_sighash = ctx.sighash(request)?;

        let (wallet_id, wallet) = charge(ctx, tx_ctx, &my_sighash)?;

        let key = string!(&self.blockchain, &addr_str_lower, &self.network);
        let id = Address::with_prefix_key(ADDR, &key);

        if try_get_state_data(tx_ctx, &id)?.is_some() {
            bail_transaction!(
                "The address has been already registered",
                context = "Could not register the address at id {:?}",
                id
            );
        }

        let address = crate::protos::Address {
            blockchain: self.blockchain,
            value: self.address,
            network: self.network,
            sighash: my_sighash.clone().into(),
        };

        let mut states = StateVec::new();
        add_state(&mut states, id.into(), &address)?;
        add_state(&mut states, wallet_id.into(), &wallet)?;
        add_fee(ctx, request, &my_sighash, &mut states)?;
        tx_ctx.set_state_entries(states)?;
        Ok(())
    }
}

impl CCTransaction for RegisterTransfer {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let RegisterTransfer {
            gain,
            order_id,
            blockchain_tx_id,
        } = self;
        let my_sighash = ctx.sighash(request)?;
        let (wallet_id, wallet) = charge(ctx, tx_ctx, &my_sighash)?;

        let src_address_id;
        let dest_address_id;
        let mut amount_str;

        let state_data = get_state_data(tx_ctx, order_id.as_str())?;
        if order_id.starts_with(DEAL_ORDER_PREFIX.as_str()) {
            let order = DealOrder::try_parse(&state_data)?;
            if gain == 0 {
                src_address_id = order.src_address;
                dest_address_id = order.dst_address;
            } else {
                dest_address_id = order.src_address;
                src_address_id = order.dst_address;
            }
            amount_str = order.amount;
        } else if order_id.starts_with(REPAYMENT_ORDER_PREFIX.as_str()) {
            if gain != 0 {
                bail_transaction!(
                    "gain must be 0 for repayment orders",
                    context = "The given order ID corresponds to a repayment order"
                );
            }
            let order = RepaymentOrder::try_parse(&state_data)?;
            src_address_id = order.src_address;
            dest_address_id = order.dst_address;
            amount_str = order.amount;
        } else {
            bail_transaction!(
                "Unexpected referred order",
                context = "The order ID for RegisterTransfer must be a deal or repayment order"
            );
        }

        let state_data = get_state_data(tx_ctx, &src_address_id)?;
        let src_address = crate::protos::Address::try_parse(&state_data)?;
        let state_data = get_state_data(tx_ctx, &dest_address_id)?;
        let dest_address = crate::protos::Address::try_parse(&state_data)?;

        if src_address.sighash != *my_sighash {
            bail_transaction!(
                "Only the owner can register",
                context = "The source address is owned by {:?}, not {:?}",
                { src_address.sighash },
                my_sighash
            );
        }
        let blockchain = src_address.blockchain;
        if dest_address.blockchain != blockchain {
            bail_transaction!(
                "Source and destination addresses must be on the same blockchain",
                context = "The destination is on the blockchain {:?}, but the source is on {:?}",
                { dest_address.blockchain },
                blockchain
            );
        }
        let network = src_address.network;
        if dest_address.network != network {
            bail_transaction!(
                "Source and destination addresses must be on the same network",
                context = "The destination is on the network {:?}, but the source is on {:?}",
                { dest_address.network },
                network
            );
        }
        let key = string!(&blockchain, &blockchain_tx_id, &network);
        let transfer_id = Address::with_prefix_key(TRANSFER, &key);
        let state_data = try_get_state_data(tx_ctx, &transfer_id)?;
        if state_data.is_some() {
            bail_transaction!(
                "The transfer has been already registered",
                context = "There is existing state data at address {:?}",
                transfer_id
            );
        }
        if blockchain_tx_id == "0" {
            amount_str = "0".into();
        } else {
            let mut amount = Integer::try_parse(&amount_str)?;
            amount += gain;
            amount_str = amount.to_string_radix(10);

            let gateway_command = [
                blockchain.as_str(),
                "verify",
                &src_address.value,
                &dest_address.value,
                &order_id,
                &amount_str,
                &blockchain_tx_id,
                &network,
            ]
            .join(" ");
            ctx.verify(&gateway_command)?;
        }
        let transfer = crate::protos::Transfer {
            blockchain,
            src_address: src_address_id,
            dst_address: dest_address_id,
            order: order_id,
            amount: amount_str,
            tx: blockchain_tx_id,
            block: last_block(request).to_string(),
            processed: false,
            sighash: my_sighash.clone().into(),
        };
        let mut states = StateVec::new();
        add_state(&mut states, transfer_id.into(), &transfer)?;
        add_fee_state(ctx, request, &my_sighash, &mut states, &wallet_id, &wallet)?;
        tx_ctx.set_state_entries(states)?;
        Ok(())
    }
}

impl CCTransaction for AddAskOrder {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let AddAskOrder {
            address_id,
            amount_str,
            interest,
            maturity,
            fee,
            expiration,
        } = self;
        let my_sighash = ctx.sighash(request)?;
        let (wallet_id, wallet) = charge(ctx, tx_ctx, &my_sighash)?;

        let guid = ctx.guid(request);

        let id = Address::with_prefix_key(ASK_ORDER, guid.as_str());
        if try_get_state_data(tx_ctx, &id)?.is_some() {
            bail_transaction!(
                "Duplicate id",
                context = "There is existing state data at address {:?}",
                id
            );
        }

        let state_data = get_state_data(tx_ctx, &address_id)?;

        let address = crate::protos::Address::try_parse(&state_data)?;

        if address.sighash != my_sighash.as_str() {
            bail_transaction!(
                "The address doesn't belong to the party",
                context = "The address is owned by {:?}, not {:?}",
                { address.sighash },
                my_sighash
            );
        }

        let ask_order = crate::protos::AskOrder {
            blockchain: address.blockchain,
            address: address_id,
            amount: amount_str,
            interest,
            maturity,
            fee,
            expiration,
            block: last_block(request).to_string(),
            sighash: my_sighash.deref().clone(),
        };

        let mut states = StateVec::new();
        add_state(&mut states, id.into(), &ask_order)?;
        add_fee_state(ctx, request, &my_sighash, &mut states, &wallet_id, &wallet)?;
        tx_ctx.set_state_entries(states)?;
        Ok(())
    }
}

impl CCTransaction for AddBidOrder {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let my_sighash = ctx.sighash(request)?;

        let (wallet_id, wallet) = charge(ctx, tx_ctx, &my_sighash)?;

        let guid = ctx.guid(request);
        let id = Address::with_prefix_key(BID_ORDER, &guid);
        let state_data = try_get_state_data(tx_ctx, &id)?;
        if state_data.is_some() {
            bail_transaction!(
                "Duplicate id",
                context = "There is existing state data at address {:?}",
                id
            );
        }

        let state_data = get_state_data(tx_ctx, &self.address_id)?;

        let address = crate::protos::Address::try_parse(&state_data)?;
        if address.sighash != my_sighash.as_str() {
            bail_transaction!(
                "The address doesn't belong to the party",
                context = "The address is owned by {:?}, not the party's sighash {:?}",
                { address.sighash },
                my_sighash
            );
        }

        let bid_order = crate::protos::BidOrder {
            blockchain: address.blockchain,
            address: self.address_id,
            amount: self.amount_str,
            interest: self.interest,
            maturity: self.maturity,
            fee: self.fee,
            expiration: self.expiration,
            block: last_block(request).to_string(),
            sighash: my_sighash.clone().into(),
        };

        let mut states = StateVec::new();
        add_state(&mut states, id.into(), &bid_order)?;
        add_fee_state(ctx, request, &my_sighash, &mut states, &wallet_id, &wallet)?;
        tx_ctx.set_state_entries(states)?;
        Ok(())
    }
}

impl CCTransaction for AddOffer {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let my_sighash = ctx.sighash(request)?;

        let (wallet_id, wallet) = charge(ctx, tx_ctx, &my_sighash)?;

        let id = Address::with_prefix_key(
            OFFER,
            &string!(self.ask_order_id.as_str(), self.bid_order_id.as_str()),
        );

        let state_data = try_get_state_data(tx_ctx, &id)?;

        if state_data.is_some() {
            bail_transaction!(
                "Duplicate id",
                context = "There is an existing offer for the ask order {} and bid order {}; already state data at {:?}",
                {&self.ask_order_id},
                {&self.bid_order_id},
                id
            );
        }

        let state_data = get_state_data(tx_ctx, &self.ask_order_id)?;

        let ask_order = crate::protos::AskOrder::try_parse(&state_data)?;

        if ask_order.sighash != my_sighash.as_str() {
            bail_transaction!(
                "Only an investor can add an offer",
                context = "The sighash on the ask order is {:?}, not {:?}",
                { ask_order.sighash },
                my_sighash
            );
        }

        let head = last_block(request);
        let start = Integer::try_parse(&ask_order.block)?;
        let elapsed = head.clone() - start;

        if ask_order.expiration < elapsed {
            bail_transaction!(
                "The order has expired",
                context = "Cannot add offer, the ask order is invalid"
            );
        }

        let state_data = get_state_data(tx_ctx, &ask_order.address)?;

        let src_address = crate::protos::Address::try_parse(&state_data)?;

        let state_data = get_state_data(tx_ctx, &self.bid_order_id)?;
        let bid_order = crate::protos::BidOrder::try_parse(&state_data)?;

        if bid_order.sighash == my_sighash.as_str() {
            bail_transaction!(
                "The ask and bid orders are from the same party",
                context = "Cannot add offer"
            );
        }

        let start = Integer::try_parse(&bid_order.block)?;
        let elapsed = head - start;

        if bid_order.expiration < elapsed {
            bail_transaction!(
                "The order has expired",
                context = "Cannot add offer, the bid order is invalid"
            );
        }

        let state_data = get_state_data(tx_ctx, &bid_order.address)?;
        let dst_address = crate::protos::Address::try_parse(&state_data)?;

        if src_address.blockchain != dst_address.blockchain
            || src_address.network != dst_address.network
        {
            bail_transaction!(
                "The ask and bid orders must be on the same blockchain and network",
                context = "Cannot add offer, there is a mismatch between the ask and bid order"
            );
        }

        let ask_fee = Integer::try_parse(&ask_order.fee)?;
        let bid_fee = Integer::try_parse(&bid_order.fee)?;

        let ask_interest = Integer::try_parse(&ask_order.interest)?;
        let ask_maturity = Integer::try_parse(&ask_order.maturity)?;

        let bid_interest = Integer::try_parse(&bid_order.interest)?;
        let bid_maturity = Integer::try_parse(&bid_order.maturity)?;

        if ask_order.amount != bid_order.amount
            || ask_fee > bid_fee
            || (ask_interest / ask_maturity) > (bid_interest / bid_maturity)
        {
            bail_transaction!(
                "The ask and bid orders do not match",
                context = "Cannot add offer, the parameters of the ask and bid orders are invalid"
            );
        }

        let offer = crate::protos::Offer {
            blockchain: src_address.blockchain,
            ask_order: self.ask_order_id,
            bid_order: self.bid_order_id,
            expiration: self.expiration,
            block: last_block(request).to_string(),
            sighash: my_sighash.clone().into(),
        };

        let mut states = vec![];

        add_state(&mut states, id.into(), &offer)?;
        add_fee_state(ctx, request, &my_sighash, &mut states, &wallet_id, &wallet)?;
        tx_ctx.set_state_entries(states)?;
        Ok(())
    }
}

impl CCTransaction for AddDealOrder {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let id = Address::with_prefix_key(DEAL_ORDER, &self.offer_id);

        let state_data = try_get_state_data(tx_ctx, &id)?;

        if state_data.is_some() {
            bail_transaction!(
                "Duplicate id",
                context = "Cannot add deal order, the id is invalid"
            );
        }

        let my_sighash = ctx.sighash(request)?;

        let state_data = get_state_data(tx_ctx, &self.offer_id)?;

        let offer = crate::protos::Offer::try_parse(&state_data)?;

        let head = last_block(request);
        let start = Integer::try_parse(&offer.block)?;
        let elapsed = head - start;

        if offer.expiration < elapsed {
            bail_transaction!(
                "The order has expired",
                context = "Cannot add deal order, invalid offer"
            );
        }

        let state_data = get_state_data(tx_ctx, &offer.bid_order)?;
        let bid_order = crate::protos::BidOrder::try_parse(&state_data)?;
        if bid_order.sighash != my_sighash.as_str() {
            bail_transaction!(
                "Only a fundraiser can add a deal order",
                context = "The sighash on the bid order is {:?}, not {:?}",
                { bid_order.sighash },
                my_sighash
            );
        }

        let state_data = get_state_data(tx_ctx, &offer.ask_order)?;
        let ask_order = crate::protos::AskOrder::try_parse(&state_data)?;

        let wallet_id = string!(NAMESPACE_PREFIX.as_str(), WALLET, my_sighash.as_str());
        let state_data = get_state_data(tx_ctx, &wallet_id)?;

        let mut wallet = crate::protos::Wallet::try_parse(&state_data)?;

        let mut balance = Integer::try_parse(&wallet.amount)?;
        let fee = Integer::try_parse(&bid_order.fee)? + ctx.tx_fee()?;
        if balance < fee {
            bail_transaction!(
                "Insufficient funds",
                context = "The wallet balance at {:?} cannot cover the total fee amount {:?}",
                wallet_id,
                fee
            );
        }
        balance -= fee;

        wallet.amount = balance.to_string();

        let deal_order = crate::protos::DealOrder {
            blockchain: offer.blockchain,
            src_address: ask_order.address,
            dst_address: bid_order.address,
            amount: bid_order.amount,
            interest: bid_order.interest,
            maturity: bid_order.maturity,
            fee: bid_order.fee,
            expiration: self.expiration,
            block: last_block(request).to_string(),
            sighash: my_sighash.clone().into(),
            ..protos::DealOrder::default()
        };

        let mut states = StateVec::new();

        add_state(&mut states, id.into(), &deal_order)?;
        add_fee_state(
            ctx,
            request,
            &my_sighash,
            &mut states,
            &wallet_id.into(),
            &wallet,
        )?;

        tx_ctx.set_state_entries(states)?;
        tx_ctx.delete_state_entries(&[offer.ask_order, offer.bid_order, self.offer_id])?;

        Ok(())
    }
}

impl CCTransaction for CompleteDealOrder {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let my_sighash = ctx.sighash(request)?;

        let state_data = get_state_data(tx_ctx, &self.deal_order_id)?;
        let mut deal_order = crate::protos::DealOrder::try_parse(&state_data)?;

        if !deal_order.loan_transfer.is_empty() {
            bail_transaction!(
                "The deal has been already completed",
                context = "The loan transfer is empty on the deal order with ID {:?}",
                { self.deal_order_id }
            );
        }

        let state_data = get_state_data(tx_ctx, &deal_order.src_address)?;
        let src_address = crate::protos::Address::try_parse(&state_data)?;

        if src_address.sighash != my_sighash.as_str() {
            bail_transaction!(
                "Only an investor can complete a deal",
                context = "The source address is owned by {:?}, not {:?}",
                { src_address.sighash },
                my_sighash
            );
        }

        let head = last_block(request);
        let start = Integer::try_parse(&deal_order.block)?;
        let elapsed = head - &start;

        if deal_order.expiration < elapsed {
            bail_transaction!(
                "The order has expired",
                context = "The deal order specified an expiration of {} blocks, and started at block {}; Now {} blocks have elapsed",
                { deal_order.expiration },
                start,
                elapsed
            );
        }

        let state_data = get_state_data(tx_ctx, &self.transfer_id)?;
        let mut transfer = protos::Transfer::try_parse(&state_data)?;

        if transfer.order != self.deal_order_id {
            bail_transaction!(
                "The transfer doesn't match the deal order",
                context = "The transfer order ID is {:?} but the deal order ID is {:?}",
                { transfer.order },
                { self.deal_order_id }
            );
        }
        if transfer.amount != deal_order.amount {
            bail_transaction!(
                "The transfer doesn't match the deal order",
                context = "The transfer amount is {} but the deal order is for the amount {}",
                { transfer.amount },
                { deal_order.amount }
            );
        }
        if transfer.sighash != my_sighash.as_str() {
            bail_transaction!(
                "The transfer doesn't match the signer",
                context = "The sighash on the transfer is {:?}, not {:?}",
                { transfer.sighash },
                my_sighash
            );
        }
        if transfer.processed {
            bail_transaction!(
                "The transfer has been already processed",
                context = "The transfer with ID {} is marked as processed",
                { self.transfer_id }
            );
        }

        transfer.processed = true;

        let wallet_id = string!(NAMESPACE_PREFIX.as_str(), WALLET, my_sighash.as_str());
        let state_data = get_state_data(tx_ctx, &wallet_id)?;

        let fee = Integer::try_parse(&deal_order.fee)? - ctx.tx_fee()?;

        let mut wallet = protos::Wallet::default();

        if state_data.is_empty() {
            if fee < 0 {
                bail_transaction!("Insufficient funds", context = "The submitter with sighash {:?} has no wallet, and the deal order's fee of {} cannot cover the transaction fee", my_sighash, {deal_order.fee});
            }
            wallet.amount = fee.to_string();
        } else {
            wallet = Wallet::try_parse(&state_data)?;
            let mut balance = Integer::try_parse(&wallet.amount)?;
            balance += fee;
            if balance < 0 {
                bail_transaction!("Insufficient funds", context = "The wallet balance at {:?} plus the deal order fee of {} does not cover the transaction fee", wallet_id, {deal_order.fee});
            }
            wallet.amount = balance.to_string();
        }

        deal_order.loan_transfer = self.transfer_id.clone();
        deal_order.block = last_block(request).to_string();

        let mut states = StateVec::new();
        add_state(&mut states, self.deal_order_id, &deal_order)?;
        add_state(&mut states, self.transfer_id, &transfer)?;
        add_fee_state(
            ctx,
            request,
            &my_sighash,
            &mut states,
            &wallet_id.into(),
            &wallet,
        )?;
        tx_ctx.set_state_entries(states)?;

        Ok(())
    }
}

impl CCTransaction for LockDealOrder {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let my_sighash = ctx.sighash(request)?;

        let (wallet_id, wallet) = charge(ctx, tx_ctx, &my_sighash)?;

        let state_data = get_state_data(tx_ctx, &self.deal_order_id)?;
        let mut deal_order = protos::DealOrder::try_parse(&state_data)?;

        if !deal_order.lock.is_empty() {
            bail_transaction!(
                "The deal has been already locked",
                context = "The deal order with ID {} cannot be locked",
                { self.deal_order_id }
            );
        }

        if deal_order.loan_transfer.is_empty() {
            bail_transaction!(
                "The deal has not been completed yet",
                context = "The deal order with ID {} does not have a completed loan transfer",
                { self.deal_order_id }
            );
        }

        if deal_order.sighash != my_sighash.as_str() {
            bail_transaction!(
                "Only a fundraiser can lock a deal",
                context = "The sighash on the deal order is {}, not {:?}",
                { deal_order.sighash },
                my_sighash
            );
        }

        deal_order.lock = my_sighash.clone().into();

        let mut states = StateVec::new();
        add_state(&mut states, self.deal_order_id, &deal_order)?;
        add_fee_state(ctx, request, &my_sighash, &mut states, &wallet_id, &wallet)?;

        tx_ctx.set_state_entries(states)?;

        Ok(())
    }
}

impl CCTransaction for CloseDealOrder {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let my_sighash = ctx.sighash(request)?;

        let (wallet_id, wallet) = charge(ctx, tx_ctx, &my_sighash)?;

        let state_data = get_state_data(tx_ctx, &self.deal_order_id)?;

        let mut deal_order = protos::DealOrder::try_parse(&state_data)?;

        if !deal_order.repayment_transfer.is_empty() {
            bail_transaction!(
                "The deal has been already closed",
                context = "The deal order with ID {} has already completed the repayment transfer",
                { self.deal_order_id }
            );
        }

        if deal_order.sighash != my_sighash.as_str() {
            bail_transaction!(
                "Only a fundraiser can close a deal",
                context = "The sighash on the deal order is {}, not {:?}",
                { deal_order.sighash },
                my_sighash
            );
        }

        if deal_order.lock != my_sighash.as_str() {
            bail_transaction!(
                "The deal must be locked first",
                context = "The lock on the deal order is {:?}, not the submitter sighash {:?}",
                { deal_order.lock },
                my_sighash
            );
        }

        let state_data = get_state_data(tx_ctx, &self.transfer_id)?;
        let mut repayment_transfer = protos::Transfer::try_parse(&state_data)?;

        if repayment_transfer.order != self.deal_order_id {
            bail_transaction!(
                "The transfer doesn't match the order",
                context = "The order on the repayment transfer with ID {:?} is {}, not the expected deal order with ID {:?}",
                { self.transfer_id },
                { repayment_transfer.order },
                { self.deal_order_id }
            );
        }
        if repayment_transfer.sighash != my_sighash.as_str() {
            bail_transaction!(
                "The transfer doesn't match the signer",
                context =
                    "The sighash on the repayment transfer {:?} is {:?}, not the submitter sighash {:?}",
                { self.transfer_id },
                { repayment_transfer.sighash },
                my_sighash
            );
        }
        if repayment_transfer.processed {
            bail_transaction!(
                "The transfer has been already processed",
                context = "The repayment transfer with ID {:?} is already marked as processed",
                { self.transfer_id }
            );
        }
        repayment_transfer.processed = true;

        let state_data = get_state_data(tx_ctx, &deal_order.loan_transfer)?;
        let loan_transfer = protos::Transfer::try_parse(&state_data)?;

        let head = last_block(request);
        let start = Integer::try_parse(&loan_transfer.block)?;
        let maturity = Integer::try_parse(&deal_order.maturity)?;

        let ticks = ((head - start) + &maturity) / maturity;

        let deal_amount = Integer::try_parse(&deal_order.amount)?;
        let deal_interest = Integer::try_parse(&deal_order.interest)?;
        let amount = calc_interest(&deal_amount, &ticks, &deal_interest);

        let repay_amount = Integer::try_parse(&repayment_transfer.amount)?;

        if repay_amount < amount {
            bail_transaction!("The transfer doesn't match the order", context = "The amount on the repayment transfer is {}, but the total expected amount is {}", repay_amount, amount);
        }

        deal_order.repayment_transfer = self.transfer_id.clone();

        let mut states = StateVec::new();

        add_state(&mut states, self.deal_order_id, &deal_order)?;
        add_state(&mut states, self.transfer_id, &repayment_transfer)?;
        add_fee_state(ctx, request, &my_sighash, &mut states, &wallet_id, &wallet)?;

        tx_ctx.set_state_entries(states)?;

        Ok(())
    }
}

impl CCTransaction for Exempt {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let my_sighash = ctx.sighash(request)?;

        let (wallet_id, wallet) = charge(ctx, tx_ctx, &my_sighash)?;

        let state_data = get_state_data(tx_ctx, &self.deal_order_id)?;
        let mut deal_order = protos::DealOrder::try_parse(&state_data)?;
        if !deal_order.repayment_transfer.is_empty() {
            bail_transaction!(
                "The deal has been already closed",
                context =
                    "The repayment transfer is already filled for the deal order with ID {:?}",
                { self.deal_order_id }
            );
        }

        let state_data = get_state_data(tx_ctx, &self.transfer_id)?;
        let mut transfer = protos::Transfer::try_parse(&state_data)?;

        if transfer.order != self.deal_order_id {
            bail_transaction!(
                "The transfer doesn't match the order",
                context =
                    "The order ID on the transfer {} is {:?}, not the given deal order ID {:?}",
                { self.transfer_id },
                { transfer.order },
                { self.deal_order_id }
            );
        }
        if transfer.processed {
            bail_transaction!(
                "The transfer has been already processed",
                context = "The transfer with ID {} is already marked as complete",
                { self.transfer_id }
            );
        }
        transfer.processed = true;

        let state_data = get_state_data(tx_ctx, &deal_order.src_address)?;
        let address = protos::Address::try_parse(&state_data)?;

        if address.sighash != my_sighash.as_str() {
            bail_transaction!(
                "Only an investor can exempt a deal",
                context = "The owner of the source address {} on the deal order {} is {:?}, not the submitter {:?}",
                { deal_order.src_address },
                { self.deal_order_id },
                { address.sighash },
                my_sighash
            );
        }

        deal_order.repayment_transfer = self.transfer_id.clone();

        let mut states = vec![];

        add_state(&mut states, self.deal_order_id, &deal_order)?;
        add_state(&mut states, self.transfer_id, &transfer)?;
        add_fee_state(ctx, request, &my_sighash, &mut states, &wallet_id, &wallet)?;

        tx_ctx.set_state_entries(states)?;

        Ok(())
    }
}

impl CCTransaction for AddRepaymentOrder {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let my_sighash = ctx.sighash(request)?;

        let (wallet_id, wallet) = charge(ctx, tx_ctx, &my_sighash)?;

        let guid = ctx.guid(request);

        let id = Address::with_prefix_key(REPAYMENT_ORDER, &guid);

        let state_data = try_get_state_data(tx_ctx, &id)?;

        if state_data.is_some() {
            bail_transaction!(
                "Duplicated id",
                context = "There is existing state data at the address {:?}",
                id
            );
        }

        let state_data = get_state_data(tx_ctx, &self.deal_order_id)?;
        let deal_order = protos::DealOrder::try_parse(&state_data)?;
        if deal_order.sighash == my_sighash.as_str() {
            bail_transaction!(
                "Fundraisers cannot create repayment orders",
                context = "The sighash on the deal order {} is {}, not the submitter sighash {:?}",
                { self.deal_order_id },
                { deal_order.sighash },
                my_sighash
            );
        }
        if deal_order.loan_transfer.is_empty() {
            bail_transaction!(
                "A repayment order can be created only for a deal with an active loan",
                context = "The loan transfer is emptry on the deal order with ID {:?}",
                { self.deal_order_id }
            );
        } else if !deal_order.repayment_transfer.is_empty() {
            bail_transaction!(
                "A repayment order can be created only for a deal with an active loan",
                context =
                    "The repayment transfer is still present ({:?}) on the deal order with ID {}",
                { deal_order.repayment_transfer },
                { self.deal_order_id }
            );
        }

        let state_data = get_state_data(tx_ctx, &deal_order.src_address)?;
        let src_address = protos::Address::try_parse(&state_data)?;
        if src_address.sighash == my_sighash.as_str() {
            bail_transaction!(
                "Investors cannot create repayment orders",
                context =
                    "The source address {:?} for the deal order {:?} is owned by the submitter {:?}",
                { &src_address },
                { self.deal_order_id },
                my_sighash
            );
        }

        let state_data = get_state_data(tx_ctx, &self.address_id)?;
        let new_address = protos::Address::try_parse(&state_data)?;

        if src_address.blockchain != new_address.blockchain {
            bail_transaction!(
                "Invalid address",
                context = "The source address {:?} is on blockchain {}, but the new address {:?} is on blockchain {}; they must match",
                src_address,
                { &src_address.blockchain },
                new_address,
                { &new_address.blockchain }
            );
        } else if src_address.network != new_address.network {
            bail_transaction!(
                "Invalid address",
                context = "The source address {:?} is on network {}, but the new address {:?} is on network {}; they must match",
                src_address,
                { &src_address.network },
                new_address,
                { &new_address.network }
            );
        } else if src_address.value == new_address.value {
            bail_transaction!(
                "Invalid address",
                context = "The value at address {:?} is {:?}, but the value at the new address {:?} is {:?}; they must differ",
                src_address,
                { &src_address.value },
                new_address,
                { &new_address.value }
            );
        }

        let repayment_order = protos::RepaymentOrder {
            blockchain: src_address.blockchain,
            src_address: self.address_id,
            dst_address: deal_order.src_address,
            amount: self.amount,
            expiration: self.expiration,
            block: last_block(request).to_string(),
            deal: self.deal_order_id,
            sighash: my_sighash.clone().into(),
            ..protos::RepaymentOrder::default()
        };

        let mut states = vec![];
        add_state(&mut states, id.into(), &repayment_order)?;
        add_fee_state(ctx, request, &my_sighash, &mut states, &wallet_id, &wallet)?;

        tx_ctx.set_state_entries(states)?;

        Ok(())
    }
}

impl CCTransaction for CompleteRepaymentOrder {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let my_sighash = ctx.sighash(request)?;

        let (wallet_id, wallet) = charge(ctx, tx_ctx, &my_sighash)?;

        let state_data = get_state_data(tx_ctx, &self.repayment_order_id)?;
        let mut repayment_order = protos::RepaymentOrder::try_parse(&state_data)?;

        let state_data = get_state_data(tx_ctx, &repayment_order.dst_address)?;
        let address = protos::Address::try_parse(&state_data)?;
        if address.sighash != my_sighash.as_str() {
            bail_transaction!(
                "Only an investor can complete a repayment order",
                context = "The owner of the destination address {:?} for the repayment order {} is {}, not the submitter {:?}",
                { &address },
                { self.repayment_order_id },
                { &address.sighash },
                { my_sighash }
            );
        }

        let state_data = get_state_data(tx_ctx, &repayment_order.deal)?;
        let mut deal_order = protos::DealOrder::try_parse(&state_data)?;
        if !deal_order.lock.is_empty() {
            bail_transaction!(
                "The deal has been already locked",
                context = "The deal order {:?} on repayment order {} is already locked by {:?}",
                { repayment_order.deal },
                { self.repayment_order_id },
                { deal_order.lock }
            );
        }

        repayment_order.previous_owner = (*my_sighash).clone();
        deal_order.lock = (*my_sighash).clone();

        let mut states = vec![];
        add_state(&mut states, self.repayment_order_id, &repayment_order)?;
        add_state(&mut states, repayment_order.deal, &deal_order)?;
        add_fee_state(ctx, request, &my_sighash, &mut states, &wallet_id, &wallet)?;

        tx_ctx.set_state_entries(states)?;

        Ok(())
    }
}

impl CCTransaction for CloseRepaymentOrder {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let my_sighash = ctx.sighash(request)?;

        let (wallet_id, wallet) = charge(ctx, tx_ctx, &my_sighash)?;

        let state_data = get_state_data(tx_ctx, &self.repayment_order_id)?;
        let mut repayment_order = protos::RepaymentOrder::try_parse(&state_data)?;
        if repayment_order.sighash != my_sighash.as_str() {
            bail_transaction!(
                "Only a collector can close a repayment order",
                context = "The sighash on the repayment order {} is {}, not the submitter {:?}",
                { self.repayment_order_id },
                { repayment_order.sighash },
                my_sighash
            );
        }

        let state_data = get_state_data(tx_ctx, &self.transfer_id)?;
        let mut transfer = protos::Transfer::try_parse(&state_data)?;

        if transfer.order != self.repayment_order_id {
            bail_transaction!(
                "The transfer doesn't match the order",
                context = "The repayment order on the transfer {} is {}, not the expected order {}",
                { self.transfer_id },
                { transfer.order },
                { self.repayment_order_id }
            );
        } else if transfer.amount != repayment_order.amount {
            bail_transaction!(
                "The transfer doesn't match the order",
                context =
                    "The amount on the transfer {} is {}, but the repayment order amount is {}",
                { self.transfer_id },
                { transfer.amount },
                { repayment_order.amount }
            );
        }
        if transfer.sighash != my_sighash.as_str() {
            bail_transaction!(
                "The transfer doesn't match the signer",
                context = "The sighash on the transfer {} is {}, not the submitter sighash {:?}",
                { self.transfer_id },
                { transfer.sighash },
                my_sighash
            );
        }
        if transfer.processed {
            bail_transaction!(
                "The transfer has been already processed",
                context = "The transfer with ID {} is already marked complete",
                { self.transfer_id }
            );
        }
        transfer.processed = true;

        let state_data = get_state_data(tx_ctx, &repayment_order.deal)?;
        let mut deal_order = protos::DealOrder::try_parse(&state_data)?;

        let state_data = get_state_data(tx_ctx, &deal_order.src_address)?;
        let src_address = protos::Address::try_parse(&state_data)?;

        if deal_order.lock != src_address.sighash {
            bail_transaction!(
                "The deal must be locked",
                context = "The lock on the deal order {} is {:?}, but it must match the source address sighash {:?}",
                { repayment_order.deal },
                { deal_order.lock },
                { src_address.sighash }
            );
        }

        deal_order.src_address = repayment_order.src_address.clone();
        deal_order.lock = "".into();
        repayment_order.transfer = self.transfer_id.clone();

        let mut states = vec![];
        add_state(&mut states, self.repayment_order_id, &repayment_order)?;
        add_state(&mut states, repayment_order.deal, &deal_order)?;
        add_state(&mut states, self.transfer_id, &transfer)?;
        add_fee_state(ctx, request, &my_sighash, &mut states, &wallet_id, &wallet)?;

        tx_ctx.set_state_entries(states)?;

        Ok(())
    }
}

impl CCTransaction for CollectCoins {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let id = Address::with_prefix_key(ERC20, &self.blockchain_tx_id);
        let state_data = try_get_state_data(tx_ctx, &id)?;

        if state_data.is_some() {
            bail_transaction!(
                "Already collected",
                context = "There is existing state data at address {:?}, indicating the coins have been collected already",
                id
            );
        }

        let my_sighash = ctx.sighash(request)?;

        let gateway_command = [
            "ethereum verify",
            &self.eth_address,
            "creditcoin",
            my_sighash.as_str(),
            &self.amount.to_string(),
            &self.blockchain_tx_id,
            "unused",
        ]
        .join(" ");

        //  FOR DEVELOPMENT, REMOVE FOR DEPLOYMENT
        if self.eth_address != "unused_if_hacked" {
            ctx.verify(&gateway_command)?;
        }

        let wallet_id = WalletId::from(&my_sighash);

        let state_data = try_get_state_data(tx_ctx, &wallet_id)?.unwrap_or_default();
        let wallet = if state_data.is_empty() {
            protos::Wallet {
                amount: self.amount.to_string(),
            }
        } else {
            let wallet = Wallet::try_parse(&state_data)?;
            let mut balance = Integer::try_parse(&wallet.amount)?;
            balance += &self.amount;
            info!("New amount = {}", balance);
            protos::Wallet {
                amount: balance.to_string(),
            }
        };

        info!("Wallet id = {:?}", wallet_id);

        let mut states = vec![];
        add_state(&mut states, wallet_id.into(), &wallet)?;
        states.push((id.into(), self.amount.to_string().as_bytes().to_owned()));

        tx_ctx.set_state_entries(states)?;

        Ok(())
    }
}

fn award(
    tx_ctx: &dyn TransactionContext,
    new_formula: bool,
    block_idx: &Integer,
    signer: &str,
) -> TxnResult<()> {
    let mut buf = Integer::new();
    let mut reward = Integer::new();

    if new_formula {
        let mut reward = Integer::new();
        buf.assign(block_idx / BLOCKS_IN_PERIOD_UPDATE1);

        let period = buf.to_i32().ok_or_else(|| {
            InvalidTransaction("Block number is too large to fit in an i32".into())
        })?;
        let fraction = (19.0f64 / 20.0f64).powi(period);
        let fraction_str = format!("{:.6}", fraction);
        let pos = fraction_str.find('.').unwrap();
        assert!(pos > 0);

        let fraction_in_wei_str = if fraction_str.starts_with('0') {
            format!("{}{:0<18}", &fraction_str[..pos], &fraction_str[pos + 1..])
        } else {
            let mut pos = 2;
            for c in fraction_str.bytes().skip(pos) {
                if c == b'0' {
                    pos += 1;
                } else {
                    break;
                }
            }
            format!("{:0<width$}", &fraction_str[pos..], width = 20 - pos)
        };

        reward.assign(28 * Integer::try_parse(&fraction_in_wei_str)?);
    } else {
        reward.assign(&*REWARD_AMOUNT);
    }

    let reward_str = reward.to_string();

    if reward > 0 {
        let signer_sighash = utils::sha512_id(signer.as_bytes());
        let wallet_id = string!(NAMESPACE_PREFIX.as_str(), WALLET, &signer_sighash);
        info!("checking wallet with id {}", wallet_id);
        let state_data = try_get_state_data(tx_ctx, &wallet_id)?.unwrap_or_default();
        info!("got state data");
        let wallet = if state_data.is_empty() {
            Wallet { amount: reward_str }
        } else {
            let wallet = Wallet::try_parse(&state_data)?;
            let balance = Integer::try_parse(&wallet.amount)? + reward;
            Wallet {
                amount: balance.to_string(),
            }
        };

        let mut buf = Vec::with_capacity(wallet.encoded_len());
        wallet
            .encode(&mut buf)
            .map_err(|e| InvalidTransaction(format!("Failed to add state : {}", e)))?;
        info!("parsed proto");
        tx_ctx.set_state_entry(wallet_id, buf)?;
        info!("set entry");
    }
    Ok(())
}

fn reward(
    request: &TpProcessRequest,
    tx_ctx: &dyn TransactionContext,
    ctx: &mut HandlerContext,
    processed_block_idx: &Integer,
    up_to_block_idx: &Integer,
) -> TxnResult<()> {
    info!("rewarding!");
    assert!(up_to_block_idx == &0 || up_to_block_idx > processed_block_idx);

    let mut new_formula = false;

    // TODO: transitioning
    let s = ctx.get_setting("sawtooth.validator.update1")?;
    if let Some(val) = s {
        let update_block = Integer::try_parse(&*val)?;
        if update_block + 500 < *processed_block_idx {
            new_formula = true;
        }
    }

    let mut last_block_idx = Integer::new();
    if *up_to_block_idx == 0 {
        last_block_idx.assign(processed_block_idx + BLOCK_REWARD_PROCESSING_COUNT)
    } else {
        last_block_idx.assign(up_to_block_idx)
    }

    let sig = request.get_block_signature();

    if sig.is_empty() {
        let mut i = Integer::from(processed_block_idx + 1);

        while i <= last_block_idx {
            let height = i.to_u64().ok_or_else(|| {
                InvalidTransaction("Block number is too large to fit in a u64".into())
            })?;

            let signer = tx_ctx.get_sig_by_num(height)?;

            info!("rewarding signer {} for block {}", signer, height);

            award(tx_ctx, new_formula, &i, &signer)?;
            i += 1;
        }
    } else {
        let first = last_block_idx.to_u64().ok_or_else(|| {
            InvalidTransaction("Block number is too large to fit in a u64".into())
        })?;
        let last = Integer::from(processed_block_idx + 1)
            .to_u64()
            .ok_or_else(|| {
                InvalidTransaction("Block number is too large to fit in a u64".into())
            })?;

        let signatures = tx_ctx.get_reward_block_signatures(sig, first, last)?;

        info!("Rewarding {} signatures", signatures.len());

        let mut i = last_block_idx;
        for signature in &signatures {
            award(tx_ctx, new_formula, &i, signature)?;
            i -= 1;
        }
    }

    Ok(())
}

fn filter(
    tx_ctx: &dyn TransactionContext,
    prefix: &str,
    mut lister: impl FnMut(&str, &[u8]) -> TxnResult<()>,
) -> TxnResult<()> {
    // TODO: Transitioning

    let states = tx_ctx.get_state_entries_by_prefix(prefix)?;
    for (address, data) in states {
        lister(&address, &data)?;
    }

    Ok(())
}

impl CCTransaction for Housekeeping {
    fn execute(
        self,
        request: &TpProcessRequest,
        tx_ctx: &dyn TransactionContext,
        ctx: &mut HandlerContext,
    ) -> TxnResult<()> {
        let Housekeeping { block_idx } = self;

        let processed_block_idx = string!(
            NAMESPACE_PREFIX.as_str(),
            PROCESSED_BLOCK,
            PROCESSED_BLOCK_ID,
        );
        let state_data = try_get_state_data(tx_ctx, &processed_block_idx)?.unwrap_or_default();
        let mut last_processed_block_idx = Integer::new();

        if !state_data.is_empty() {
            last_processed_block_idx.assign(Integer::try_parse(
                str::from_utf8(&state_data).map_err(|e| {
                    InvalidTransaction(format!("State data is not valid UTF-8 : {}", e))
                })?,
            )?);
        }

        if block_idx == 0 {
            let head = last_block(request);

            if last_processed_block_idx.clone()
                + CONFIRMATION_COUNT * 2
                + BLOCK_REWARD_PROCESSING_COUNT
                < head
            {
                reward(
                    request,
                    tx_ctx,
                    ctx,
                    &last_processed_block_idx,
                    &Integer::new(),
                )?;
                tx_ctx.set_state_entry(
                    processed_block_idx,
                    (last_processed_block_idx + BLOCK_REWARD_PROCESSING_COUNT)
                        .to_string()
                        .into_bytes(),
                )?;
            }
            return Ok(());
        }

        if block_idx < CONFIRMATION_COUNT * 2 || block_idx <= last_processed_block_idx {
            return Ok(());
        }

        let tip = last_block(request);

        if block_idx >= tip - CONFIRMATION_COUNT {
            info!("Premature processing");
            return Ok(());
        }

        let mut elapsed_buf = Integer::new();

        let ask = string!(NAMESPACE_PREFIX, ASK_ORDER);
        filter(tx_ctx, &ask, |addr, proto| {
            let ask_order = protos::AskOrder::try_parse(proto)?;
            let start = Integer::try_parse(&ask_order.block)?;
            elapsed_buf.assign(&block_idx - &start);
            if ask_order.expiration < elapsed_buf {
                tx_ctx.delete_state_entry(addr)?;
            }
            Ok(())
        })?;

        let bid = string!(NAMESPACE_PREFIX, BID_ORDER);
        filter(tx_ctx, &bid, |addr, proto| {
            let bid_order = protos::BidOrder::try_parse(proto)?;
            let start = Integer::try_parse(&bid_order.block)?;
            elapsed_buf.assign(&block_idx - &start);
            if bid_order.expiration < elapsed_buf {
                tx_ctx.delete_state_entry(addr)?;
            }
            Ok(())
        })?;

        let offer = string!(NAMESPACE_PREFIX, OFFER);
        filter(tx_ctx, &offer, |addr, proto| {
            let offer = protos::Offer::try_parse(proto)?;
            let start = Integer::try_parse(&offer.block)?;
            elapsed_buf.assign(&block_idx - &start);
            if offer.expiration < elapsed_buf {
                tx_ctx.delete_state_entry(addr)?;
            }
            Ok(())
        })?;

        let deal = string!(NAMESPACE_PREFIX, DEAL_ORDER);
        filter(tx_ctx, &deal, |addr, proto| {
            let deal_order = protos::DealOrder::try_parse(proto)?;
            let start = Integer::try_parse(&deal_order.block)?;
            elapsed_buf.assign(&block_idx - &start);
            if deal_order.expiration < elapsed_buf && deal_order.loan_transfer.is_empty() {
                if ctx.tip() == 0 || ctx.tip() > DEAL_EXP_FIX_BLOCK {
                    let wallet_id = string!(NAMESPACE_PREFIX, WALLET, &deal_order.sighash);
                    let state_data = get_state_data(tx_ctx, &wallet_id)?;
                    let mut wallet = protos::Wallet::try_parse(&state_data)?;
                    let mut balance = Integer::try_parse(&wallet.amount)?;
                    balance += Integer::try_parse(&deal_order.fee)?;
                    wallet.amount = balance.to_string();

                    let mut states = vec![];
                    add_state(&mut states, wallet_id, &wallet)?;
                    tx_ctx.set_state_entries(states)?;
                }
                tx_ctx.delete_state_entry(addr)?;
            }
            Ok(())
        })?;

        let repay = string!(NAMESPACE_PREFIX, REPAYMENT_ORDER);
        filter(tx_ctx, &repay, |addr, proto| {
            let repayment_order = protos::RepaymentOrder::try_parse(proto)?;
            let start = Integer::try_parse(&repayment_order.block)?;
            elapsed_buf.assign(&block_idx - &start);
            if repayment_order.expiration < elapsed_buf && repayment_order.previous_owner.is_empty()
            {
                tx_ctx.delete_state_entry(addr)?;
            }
            Ok(())
        })?;

        let fee = string!(NAMESPACE_PREFIX, FEE);
        filter(tx_ctx, &fee, |addr, proto| {
            let fee = protos::Fee::try_parse(proto)?;
            let start = Integer::try_parse(&fee.block)?;
            elapsed_buf.assign(&block_idx - &start);

            if elapsed_buf > YEAR_OF_BLOCKS {
                let wallet_id = string!(NAMESPACE_PREFIX, WALLET, &fee.sighash);
                let state_data = get_state_data(tx_ctx, &wallet_id)?;
                let mut wallet = protos::Wallet::try_parse(&state_data)?;
                wallet.amount = (Integer::try_parse(&wallet.amount)? + ctx.tx_fee()?).to_string();

                let mut state_data = state_data.0;
                state_data.clear();
                state_data.reserve(wallet.encoded_len());
                wallet
                    .encode(&mut state_data)
                    .map_err(|e| InvalidTransaction(format!("Failed to encode wallet : {}", e)))?;

                tx_ctx.set_state_entry(wallet_id, state_data)?;
                tx_ctx.delete_state_entry(addr)?;
            }
            Ok(())
        })?;

        reward(request, tx_ctx, ctx, &last_processed_block_idx, &block_idx)?;
        tx_ctx.set_state_entry(processed_block_idx, block_idx.to_string().into_bytes())?;

        Ok(())
    }
}

pub struct CCTransactionHandler {
    zmq_context: zmq::Context,
    gateway_endpoint: String,
}

impl CCTransactionHandler {
    pub fn new<S: Into<String>>(gateway: S) -> Self {
        let gateway_endpoint: String = gateway.into();
        let context = zmq::Context::new();

        Self {
            zmq_context: context,
            gateway_endpoint,
        }
    }
}

impl TransactionHandler for CCTransactionHandler {
    fn family_name(&self) -> String {
        NAMESPACE.into()
    }

    fn family_versions(&self) -> Vec<String> {
        vec![
            "1.0".into(),
            "1.1".into(),
            "1.2".into(),
            "1.3".into(),
            "1.4".into(),
            "1.5".into(),
            "1.6".into(),
            "1.7".into(),
        ]
    }

    fn namespaces(&self) -> Vec<String> {
        vec![NAMESPACE_PREFIX.clone()]
    }

    fn apply(
        &self,
        request: &TpProcessRequest,
        context: &mut dyn TransactionContext,
    ) -> TxnResult<(), ApplyError> {
        let params = utils::params_from_bytes(&request.payload)
            .log_err()
            .map_err(|e| ApplyError::InvalidTransaction(format!("Malformed payload : {}", e)))?;

        let command = CCCommand::try_from(params).log_err().to_apply_error()?;

        let mut handler_context = HandlerContext::create(
            self.zmq_context.clone(),
            self.gateway_endpoint.clone(),
            &*context,
        )
        .log_err()
        .to_apply_error()?;

        command
            .execute(request, context, &mut handler_context)
            .log_err()
            .to_apply_error()?;
        Ok(())
    }
}
