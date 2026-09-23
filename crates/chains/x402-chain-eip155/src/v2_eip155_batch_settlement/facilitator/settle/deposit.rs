//! Deposit settlement through the canonical collectors.
//!
//! Only one request for each authorization can run the checks and broadcast
//! at a time. An identical request waits for it. A broadcast that ends as
//! `settlement_pending` or as a mined success goes into [`PendingDeposits`].
//! A retry of the identical request reads the receipt of that transaction and
//! never broadcasts again. A different request that spends the same
//! authorization fails with no broadcast.

use alloy_primitives::{Address, B256, U128};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionReceipt;

use super::with_receipt_state;
use crate::chain::{Eip155MetaTransactionProvider, MetaTransactionSendError};
use crate::v2_eip155_batch_settlement::constants::BATCH_SETTLEMENT_ADDRESS;
use crate::v2_eip155_batch_settlement::errors as err;
use crate::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::Deposited;
use crate::v2_eip155_batch_settlement::facilitator::channel::validate_channel_config;
use crate::v2_eip155_batch_settlement::facilitator::deposit::build_deposit_calldata;
use crate::v2_eip155_batch_settlement::facilitator::pending::{
    Claim, PendingDeposit, PendingDeposits, Reservation, authorization_key, pending_hash,
    request_hash,
};
use crate::v2_eip155_batch_settlement::facilitator::response::BatchSettlementSettleResponse;
use crate::v2_eip155_batch_settlement::facilitator::rpc_error::log_rpc_error;
use crate::v2_eip155_batch_settlement::facilitator::submit::{
    ContractWrite, SettleContext, contract_events, simulate_and_submit,
};
use crate::v2_eip155_batch_settlement::facilitator::verify::{
    VerifyContext, check_deposit, deposit_amount,
};
use crate::v2_eip155_batch_settlement::types::{
    DepositPayload, PaymentPayload, PaymentRequirements,
};

/// One deposit settle request.
#[derive(Clone, Copy)]
pub struct DepositSettle<'a> {
    pub payment: &'a PaymentPayload,
    pub deposit: &'a DepositPayload,
    pub requirements: &'a PaymentRequirements,
}

/// The store slot of one authorization.
#[derive(Clone, Copy)]
struct Slot<'a> {
    store: &'a PendingDeposits,
    key: B256,
}

/// What the `Deposited` event of this deposit must say.
#[derive(Clone, Copy)]
struct ExpectedDeposit {
    channel_id: B256,
    token: Address,
    amount: u128,
    sender: Address,
}

pub async fn settle_deposit<P>(
    context: &SettleContext<'_, P>,
    store: &PendingDeposits,
    request: DepositSettle<'_>,
) -> BatchSettlementSettleResponse
where
    P: Eip155MetaTransactionProvider,
    P::Error: Into<MetaTransactionSendError>,
{
    let network = context.network;
    let payer: Address = request.deposit.channel_config.payer.into();
    let amount = match local_checks(context.chain_id, request) {
        Ok(amount) => amount,
        Err(reason) => {
            return BatchSettlementSettleResponse::failure(network, reason).with_payer(payer);
        }
    };
    let slot = Slot {
        store,
        key: authorization_key(context.chain_id, request.deposit),
    };
    let request_hash = request_hash(context.chain_id, request.payment, request.requirements);
    let (reason, message) = match store.claim(slot.key, request_hash).await {
        Claim::Broadcast(reservation) => {
            return broadcast(context, reservation, request)
                .await
                .with_payer(payer);
        }
        Claim::Recorded(record) => {
            let expected = expected_deposit(request.deposit, amount, record.sender);
            return reconcile(context, slot, record, expected)
                .await
                .with_payer(payer);
        }
        Claim::Taken => (err::ERR_DEPOSIT_PAYLOAD, OTHER_REQUEST),
        Claim::Full => (err::ERR_DEPOSIT_TRANSACTION_FAILED, STORE_FULL),
    };
    BatchSettlementSettleResponse::failure_with_message(network, reason, message.into())
        .with_payer(payer)
}

const OTHER_REQUEST: &str = "a different request already holds this deposit authorization";
const STORE_FULL: &str = "too many deposits are in progress";

/// The RPC-free deposit checks. They run before the store lookup. Every
/// other check ran for the identical request before its broadcast.
fn local_checks(chain_id: u64, request: DepositSettle<'_>) -> Result<U128, &'static str> {
    let deposit = request.deposit;
    let channel_id = deposit.voucher.channel_id;
    validate_channel_config(
        &deposit.channel_config,
        channel_id,
        request.requirements,
        chain_id,
    )?;
    deposit_amount(deposit.deposit.amount.0)
}

/// Every return without [`Reservation::record`] frees the authorization for
/// the next request. A mined revert leaves the authorization unspent.
async fn broadcast<P>(
    context: &SettleContext<'_, P>,
    reservation: Reservation<'_>,
    request: DepositSettle<'_>,
) -> BatchSettlementSettleResponse
where
    P: Eip155MetaTransactionProvider,
    P::Error: Into<MetaTransactionSendError>,
{
    let network = context.network;
    let verify_context = VerifyContext {
        chain_id: context.chain_id,
        sender: context.sender,
    };
    let inner = context.provider.inner();
    let (payload, requirements) = (request.deposit, request.requirements);
    let amount = match check_deposit(inner, verify_context, payload, requirements).await {
        Ok((_, amount)) => amount,
        Err((reason, Some(message))) => {
            return BatchSettlementSettleResponse::failure_with_message(network, reason, message);
        }
        Err((reason, None)) => return BatchSettlementSettleResponse::failure(network, reason),
    };
    let write = ContractWrite {
        calldata: build_deposit_calldata(payload, amount),
        gas_limit: None,
        simulation_failed: err::ERR_DEPOSIT_SIMULATION_FAILED,
        transaction_failed: err::ERR_DEPOSIT_TRANSACTION_FAILED,
    };
    let expected = expected_deposit(payload, amount, context.sender);
    match simulate_and_submit(context, write).await {
        Ok(receipt) => {
            reservation.record(receipt.transaction_hash, context.sender);
            finish(context, expected, &receipt).await
        }
        Err(response) => {
            if let Some(tx_hash) = pending_hash(&response) {
                reservation.record(tx_hash, context.sender);
            }
            response
        }
    }
}

/// Reads the receipt of the recorded transaction. Only a revert removes the
/// record, because only a revert leaves the authorization unspent.
async fn reconcile<P>(
    context: &SettleContext<'_, P>,
    slot: Slot<'_>,
    record: PendingDeposit,
    expected: ExpectedDeposit,
) -> BatchSettlementSettleResponse
where
    P: Eip155MetaTransactionProvider,
{
    let network = context.network;
    let pending = |message: &str| {
        BatchSettlementSettleResponse::settlement_pending(network, record.tx_hash, message.into())
    };
    let receipt = match context
        .provider
        .inner()
        .get_transaction_receipt(record.tx_hash)
        .await
    {
        Ok(Some(receipt)) => receipt,
        Ok(None) => return pending(NOT_MINED),
        Err(error) => {
            log_rpc_error(&error);
            return pending(RECEIPT_READ_FAILED);
        }
    };
    if !is_receipt_of(&receipt, &record) {
        return pending(OTHER_RECEIPT);
    }
    if !receipt.status() {
        slot.store.remove(slot.key, record.tx_hash);
        return BatchSettlementSettleResponse::mined_failure(
            network,
            err::ERR_DEPOSIT_TRANSACTION_FAILED,
            record.tx_hash,
            "transaction reverted".into(),
        );
    }
    finish(context, expected, &receipt).await
}

const NOT_MINED: &str = "the earlier deposit transaction has no receipt yet";
const RECEIPT_READ_FAILED: &str = "the receipt read for the earlier deposit transaction failed";
const OTHER_RECEIPT: &str = "the RPC returned a receipt for a different transaction";

/// The RPC must return the receipt of the recorded transaction, sent by the
/// recorded signer to the canonical contract.
fn is_receipt_of(receipt: &TransactionReceipt, record: &PendingDeposit) -> bool {
    receipt.transaction_hash == record.tx_hash
        && receipt.from == record.sender
        && receipt.to == Some(BATCH_SETTLEMENT_ADDRESS)
}

fn expected_deposit(payload: &DepositPayload, amount: U128, sender: Address) -> ExpectedDeposit {
    ExpectedDeposit {
        channel_id: payload.voucher.channel_id,
        token: payload.channel_config.token.into(),
        amount: amount.to::<u128>(),
        sender,
    }
}

async fn finish<P>(
    context: &SettleContext<'_, P>,
    expected: ExpectedDeposit,
    receipt: &TransactionReceipt,
) -> BatchSettlementSettleResponse
where
    P: Eip155MetaTransactionProvider,
{
    let deposited = contract_events::<Deposited>(receipt)
        .into_iter()
        .any(|event| {
            event.channelId == expected.channel_id
                && event.amount == expected.amount
                && event.sender == expected.sender
        });
    if !deposited {
        return BatchSettlementSettleResponse::mined_failure(
            context.network,
            err::ERR_DEPOSIT_TRANSACTION_FAILED,
            receipt.transaction_hash,
            "receipt has no Deposited event for this deposit".into(),
        );
    }
    let response = BatchSettlementSettleResponse::success(
        context.network,
        receipt.transaction_hash,
        expected.amount.to_string(),
    )
    .with_asset(expected.token);
    let inner = context.provider.inner();
    with_receipt_state(inner, response, receipt, expected.channel_id).await
}
