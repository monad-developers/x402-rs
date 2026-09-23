//! `claimWithSignature` settlement and batch accounting.
//!
//! Rows may target different receivers and tokens; the contract only requires
//! one shared `receiverAuthorizer`. A row whose `totalClaimed` does not exceed
//! the running channel total is a no-op onchain.
//!
//! A claim is idempotent. When every row is a no-op, the chain already holds
//! the signed totals. The facilitator then runs the canonical call as an
//! `eth_call` at the read block, so the contract checks the authorizer
//! signature, and reports success with no broadcast. A claim that mines with
//! no `Claimed` event is also a success: another claim reached the totals
//! first. The SDK channel managers record their totals only on success.

use std::collections::{HashMap, HashSet};

use alloy_primitives::{B256, Bytes, U128};
use alloy_provider::Provider;
use alloy_rpc_types_eth::{BlockId, TransactionRequest};
use alloy_sol_types::SolCall;

use super::{required_signature, verify_authorizer_signature};
use crate::chain::{Eip155MetaTransactionProvider, MetaTransactionSendError};
use crate::v2_eip155_batch_settlement::constants::BATCH_SETTLEMENT_ADDRESS;
use crate::v2_eip155_batch_settlement::errors as err;
use crate::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement;
use crate::v2_eip155_batch_settlement::facilitator::channel::{
    ChannelTotals, pinned_block, read_channel_totals_at,
};
use crate::v2_eip155_batch_settlement::facilitator::digest::{
    compute_channel_id, compute_claim_batch_digest, shared_claim_authorizer, to_abi_voucher_claims,
};
use crate::v2_eip155_batch_settlement::facilitator::response::BatchSettlementSettleResponse;
use crate::v2_eip155_batch_settlement::facilitator::rpc_error::client_message;
use crate::v2_eip155_batch_settlement::facilitator::submit::{
    ContractWrite, SettleContext, simulate_and_submit,
};
use crate::v2_eip155_batch_settlement::facilitator::voucher::{
    ChannelVoucher, check_voucher_signature,
};
use crate::v2_eip155_batch_settlement::types::{ClaimPayload, VoucherClaim, VoucherFields};

/// Per-channel `totalClaimed` after the batch runs, plus the rows that move it.
#[derive(Debug, Default)]
pub struct ClaimProjection {
    pub totals: HashMap<B256, U128>,
    pub effective_rows: Vec<usize>,
}

/// A checked claim batch, its calldata, and the block of its channel read.
pub struct PreparedClaims {
    pub projection: ClaimProjection,
    pub calldata: Bytes,
    pub block: BlockId,
}

/// Replays `_processVoucherClaim` accounting over the batch, in order.
pub fn project_claims(
    claims: &[VoucherClaim],
    states: &HashMap<B256, ChannelTotals>,
    chain_id: u64,
) -> Result<ClaimProjection, &'static str> {
    let mut projection = ClaimProjection::default();
    for (index, claim) in claims.iter().enumerate() {
        let channel_id = compute_channel_id(&claim.voucher.channel, chain_id);
        let state = states
            .get(&channel_id)
            .ok_or(err::ERR_CHANNEL_STATE_READ_FAILED)?;
        let current = *projection
            .totals
            .entry(channel_id)
            .or_insert(state.total_claimed);
        let total = claim.total_claimed.0;
        if total <= current {
            continue;
        }
        if total > claim.voucher.max_claimable_amount.0 {
            return Err(err::ERR_CLAIM_PAYLOAD);
        }
        if total > state.balance {
            return Err(err::ERR_CUMULATIVE_EXCEEDS_BALANCE);
        }
        projection.totals.insert(channel_id, total);
        projection.effective_rows.push(index);
    }
    Ok(projection)
}

/// Reads every distinct channel of the batch in one call at `block`.
async fn read_claim_totals<P: Provider>(
    provider: &P,
    claims: &[VoucherClaim],
    chain_id: u64,
    block: BlockId,
) -> Result<HashMap<B256, ChannelTotals>, &'static str> {
    let mut seen = HashSet::new();
    let ids: Vec<B256> = claims
        .iter()
        .map(|claim| compute_channel_id(&claim.voucher.channel, chain_id))
        .filter(|id| seen.insert(*id))
        .collect();
    let totals = read_channel_totals_at(provider, &ids, block).await?;
    Ok(ids.into_iter().zip(totals).collect())
}

/// Checks the payer voucher of every row that moves `totalClaimed`. These are
/// the only rows the contract verifies. A payer with code gets no local
/// verdict; the claim simulation from the broadcast sender decides.
async fn check_effective_vouchers<P: Provider>(
    provider: &P,
    claims: &[VoucherClaim],
    projection: &ClaimProjection,
    chain_id: u64,
) -> Result<(), &'static str> {
    for index in &projection.effective_rows {
        let claim = &claims[*index];
        let fields = VoucherFields {
            channel_id: compute_channel_id(&claim.voucher.channel, chain_id),
            max_claimable_amount: claim.voucher.max_claimable_amount,
            signature: claim.signature.clone(),
        };
        let voucher = ChannelVoucher {
            config: &claim.voucher.channel,
            voucher: &fields,
            chain_id,
        };
        check_voucher_signature(provider, voucher).await?;
    }
    Ok(())
}

/// Checks a claim batch and returns its projection and calldata.
pub async fn prepare_claims<P: Provider>(
    provider: &P,
    claims: &[VoucherClaim],
    authorizer_signature: &Bytes,
    chain_id: u64,
) -> Result<PreparedClaims, &'static str> {
    let authorizer = shared_claim_authorizer(claims).ok_or(err::ERR_CLAIM_PAYLOAD)?;
    let digest = compute_claim_batch_digest(claims, chain_id);
    verify_authorizer_signature(provider, authorizer_signature, digest, authorizer).await?;

    let block = pinned_block(provider).await?;
    let totals = read_claim_totals(provider, claims, chain_id, block).await?;
    let projection = project_claims(claims, &totals, chain_id)?;
    check_effective_vouchers(provider, claims, &projection, chain_id).await?;
    let calldata = X402BatchSettlement::claimWithSignatureCall {
        voucherClaims: to_abi_voucher_claims(claims),
        authorizerSignature: authorizer_signature.clone(),
    }
    .abi_encode()
    .into();
    Ok(PreparedClaims {
        projection,
        calldata,
        block,
    })
}

/// An empty batch reverts with `EmptyBatch`, so it is rejected.
async fn prepare_claim_payload<P>(
    context: &SettleContext<'_, P>,
    payload: &ClaimPayload,
) -> Result<PreparedClaims, &'static str>
where
    P: Eip155MetaTransactionProvider,
{
    if payload.claims.is_empty() {
        return Err(err::ERR_CLAIM_PAYLOAD);
    }
    let signature = required_signature(payload.claim_authorizer_signature.as_ref())?;
    let provider = context.provider.inner();
    prepare_claims(provider, &payload.claims, signature, context.chain_id).await
}

/// Every row is already claimed at the read block. At that block the
/// canonical call checks only the authorizer signature and the shared
/// authorizer, and changes nothing. A signature that the contract rejects
/// fails here, also for an authorizer with code.
async fn confirm_claimed<P>(
    context: &SettleContext<'_, P>,
    prepared: PreparedClaims,
) -> BatchSettlementSettleResponse
where
    P: Eip155MetaTransactionProvider,
{
    let network = context.network;
    let request = TransactionRequest::default()
        .from(context.sender)
        .to(BATCH_SETTLEMENT_ADDRESS)
        .input(prepared.calldata.into());
    let call = context.provider.inner().call(request).block(prepared.block);
    match call.await {
        Ok(_) => BatchSettlementSettleResponse::success_without_transaction(network, String::new()),
        Err(error) => BatchSettlementSettleResponse::failure_with_message(
            network,
            err::ERR_CLAIM_SIMULATION_FAILED,
            client_message(&error),
        ),
    }
}

pub async fn settle_claim<P>(
    context: &SettleContext<'_, P>,
    payload: &ClaimPayload,
) -> BatchSettlementSettleResponse
where
    P: Eip155MetaTransactionProvider,
    P::Error: Into<MetaTransactionSendError>,
{
    let network = context.network;
    let prepared = match prepare_claim_payload(context, payload).await {
        Ok(prepared) => prepared,
        Err(reason) => return BatchSettlementSettleResponse::failure(network, reason),
    };
    if prepared.projection.effective_rows.is_empty() {
        return confirm_claimed(context, prepared).await;
    }
    let write = ContractWrite {
        calldata: prepared.calldata,
        gas_limit: None,
        simulation_failed: err::ERR_CLAIM_SIMULATION_FAILED,
        transaction_failed: err::ERR_CLAIM_TRANSACTION_FAILED,
    };
    match simulate_and_submit(context, write).await {
        // Claim only updates accounting, so no amount is reported. A receipt
        // with no `Claimed` event still leaves each channel at or above its
        // row total.
        Ok(receipt) => {
            BatchSettlementSettleResponse::success(network, receipt.transaction_hash, String::new())
        }
        Err(response) => response,
    }
}

#[cfg(test)]
#[path = "claim_tests.rs"]
mod tests;
