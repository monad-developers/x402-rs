//! `/settle` for deposit, claim, settle, and server-completed refund payloads.
//!
//! Claim and refund need a receiver-authorizer signature in the payload. The
//! facilitator holds no authorizer key and never signs for the server.

mod claim;
mod deposit;
mod refund;
mod transfer;

use alloy_primitives::{Address, B256, Bytes};
use alloy_provider::Provider;

use super::channel::{OnchainChannelState, read_channel_state_at};
use super::pending::PendingDeposits;
use super::response::{BatchSettlementSettleExtra, BatchSettlementSettleResponse};
use super::signature::{
    EcdsaRules, SignatureCheckError, SignedDigest, SignerCheck, check_signature_checker,
};
use super::submit::{SettleContext, receipt_block};
use super::verify::check_networks;
use crate::chain::{Eip155MetaTransactionProvider, MetaTransactionSendError};
use crate::v2_eip155_batch_settlement::errors as err;
use crate::v2_eip155_batch_settlement::types::{
    BatchSettlementPayload, BatchSettlementRefundPayload, PaymentPayload, PaymentRequirements,
};
use alloy_rpc_types_eth::TransactionReceipt;
use deposit::DepositSettle;

pub async fn settle<P>(
    context: &SettleContext<'_, P>,
    pending: &PendingDeposits,
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> BatchSettlementSettleResponse
where
    P: Eip155MetaTransactionProvider,
    P::Error: Into<MetaTransactionSendError>,
{
    if let Err(reason) = check_networks(context.chain_id, payload, requirements) {
        return BatchSettlementSettleResponse::failure(context.network, reason);
    }
    match &payload.payload {
        BatchSettlementPayload::Deposit(deposit) => {
            let request = DepositSettle {
                payment: payload,
                deposit,
                requirements,
            };
            deposit::settle_deposit(context, pending, request).await
        }
        BatchSettlementPayload::Claim(claim) => claim::settle_claim(context, claim).await,
        BatchSettlementPayload::Settle(transfer) => {
            transfer::settle_transfer(context, transfer).await
        }
        BatchSettlementPayload::Refund(BatchSettlementRefundPayload::Enriched(refund)) => {
            refund::settle_refund(context, refund).await
        }
        BatchSettlementPayload::Voucher(_)
        | BatchSettlementPayload::Refund(BatchSettlementRefundPayload::Client(_)) => {
            BatchSettlementSettleResponse::failure(context.network, err::ERR_INVALID_PAYLOAD_TYPE)
        }
    }
}

/// The facilitator holds no authorizer key, so a missing signature is final.
fn required_signature(signature: Option<&Bytes>) -> Result<&Bytes, &'static str> {
    signature.ok_or(err::ERR_AUTHORIZER_NOT_CONFIGURED)
}

/// The contract checks authorizer signatures with `SignatureChecker`. An
/// authorizer with code gets no local verdict: the write simulation from the
/// broadcast sender runs the contract's own ERC-1271 check before any gas.
async fn verify_authorizer_signature<P: Provider>(
    provider: &P,
    signature: &Bytes,
    digest: B256,
    authorizer: Address,
) -> Result<(), &'static str> {
    let signed = SignedDigest {
        signature,
        digest,
        signer: authorizer,
    };
    match check_signature_checker(provider, &signed, EcdsaRules::Strict).await {
        Ok(SignerCheck::Ecdsa | SignerCheck::Contract) => Ok(()),
        Err(SignatureCheckError::RpcReadFailed) => Err(err::ERR_RPC_READ_FAILED),
        Err(_) => Err(err::ERR_AUTHORIZER_ADDRESS_MISMATCH),
    }
}

/// Adds end-of-block channel state for the receipt's block. A failed read
/// keeps the success but says so; no projected state is reported.
async fn with_receipt_state<P: Provider>(
    provider: &P,
    response: BatchSettlementSettleResponse,
    receipt: &TransactionReceipt,
    channel_id: B256,
) -> BatchSettlementSettleResponse {
    let state: Result<OnchainChannelState, &str> = match receipt_block(receipt) {
        Some(block) => read_channel_state_at(provider, channel_id, block).await,
        None => Err("receipt has no block number"),
    };
    match state {
        Ok(state) => {
            response.with_channel_state(BatchSettlementSettleExtra::from_state(channel_id, &state))
        }
        Err(reason) => response.without_channel_state(reason),
    }
}
