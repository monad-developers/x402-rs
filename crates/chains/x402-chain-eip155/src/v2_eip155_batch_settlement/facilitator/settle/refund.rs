//! Cooperative refund through `refundWithSignature`, optionally bundled with
//! a claim batch in one `multicall`.
//!
//! The contract bumps `refundNonce` before it caps the amount, so a refund
//! with no available escrow still spends gas and the nonce while moving no
//! tokens. The facilitator rejects that case before broadcast.

use alloy_primitives::{Address, B256, Bytes, U128};
use alloy_sol_types::SolCall;

use super::claim::prepare_claims;
use super::{required_signature, verify_authorizer_signature, with_receipt_state};
use crate::chain::{Eip155MetaTransactionProvider, MetaTransactionSendError};
use crate::v2_eip155_batch_settlement::errors as err;
use crate::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::{
    Refunded, multicallCall, refundWithSignatureCall,
};
use crate::v2_eip155_batch_settlement::facilitator::channel::{
    OnchainChannelState, read_channel_state, validate_channel_id,
};
use crate::v2_eip155_batch_settlement::facilitator::digest::{
    compute_channel_id, compute_refund_digest, to_abi_channel_config,
};
use crate::v2_eip155_batch_settlement::facilitator::response::BatchSettlementSettleResponse;
use crate::v2_eip155_batch_settlement::facilitator::submit::{
    ContractWrite, SettleContext, contract_events, simulate_and_submit,
};
use crate::v2_eip155_batch_settlement::types::{EnrichedRefundPayload, u256_to_u128};

/// The merchant's refund signature is the consent, so the refund reads no
/// requirement field. The SDK channel managers send placeholder requirements.
pub async fn settle_refund<P>(
    context: &SettleContext<'_, P>,
    payload: &EnrichedRefundPayload,
) -> BatchSettlementSettleResponse
where
    P: Eip155MetaTransactionProvider,
    P::Error: Into<MetaTransactionSendError>,
{
    let network = context.network;
    let payer: Address = payload.channel_config.payer.into();
    let channel_id = compute_channel_id(&payload.channel_config, context.chain_id);
    let calldata = match prepare_refund(context, payload, channel_id).await {
        Ok(calldata) => calldata,
        Err(reason) => {
            return BatchSettlementSettleResponse::failure(network, reason).with_payer(payer);
        }
    };
    let write = ContractWrite {
        calldata,
        gas_limit: None,
        simulation_failed: err::ERR_REFUND_SIMULATION_FAILED,
        transaction_failed: err::ERR_REFUND_TRANSACTION_FAILED,
    };
    let receipt = match simulate_and_submit(context, write).await {
        Ok(receipt) => receipt,
        Err(response) => return response.with_payer(payer),
    };
    let refunded = contract_events::<Refunded>(&receipt)
        .into_iter()
        .find(|event| event.channelId == channel_id);
    let Some(event) = refunded else {
        // The nonce advanced but no tokens moved; a concurrent claim or
        // withdrawal took the escrow after simulation.
        return BatchSettlementSettleResponse::mined_failure(
            network,
            err::ERR_REFUND_NO_BALANCE,
            receipt.transaction_hash,
            "receipt has no Refunded event for this channel".into(),
        )
        .with_payer(payer);
    };
    let response = BatchSettlementSettleResponse::success(
        network,
        receipt.transaction_hash,
        event.amount.to_string(),
    )
    .with_payer(payer);
    with_receipt_state(context.provider.inner(), response, &receipt, channel_id).await
}

/// Validates the refund and returns the calldata to submit.
async fn prepare_refund<P>(
    context: &SettleContext<'_, P>,
    payload: &EnrichedRefundPayload,
    channel_id: B256,
) -> Result<Bytes, &'static str>
where
    P: Eip155MetaTransactionProvider,
{
    let provider = context.provider.inner();
    let chain_id = context.chain_id;
    let config = &payload.channel_config;
    validate_channel_id(config, payload.voucher.channel_id, chain_id)?;
    let amount = refund_amount(payload)?;
    let state = read_channel_state(provider, channel_id).await?;
    if payload.refund_nonce.0 != state.refund_nonce {
        return Err(err::ERR_REFUND_PAYLOAD);
    }
    let signature = required_signature(payload.refund_authorizer_signature.as_ref())?;
    let digest = compute_refund_digest(channel_id, payload.refund_nonce.0, amount, chain_id);
    let authorizer: Address = config.receiver_authorizer.into();
    verify_authorizer_signature(provider, signature, digest, authorizer).await?;

    let refund_call = refund_calldata(payload, amount, signature.clone());
    if payload.claims.is_empty() {
        assert_refundable(&state, state.total_claimed)?;
        return Ok(refund_call);
    }
    let claim_signature = required_signature(payload.claim_authorizer_signature.as_ref())?;
    let claims = prepare_claims(provider, &payload.claims, claim_signature, chain_id).await?;
    // Claims for other channels may ride along; only this channel's total
    // limits the refund.
    let post_claim_total = claims
        .projection
        .totals
        .get(&channel_id)
        .copied()
        .unwrap_or(state.total_claimed);
    assert_refundable(&state, post_claim_total)?;
    Ok(multicallCall {
        data: vec![claims.calldata, refund_call],
    }
    .abi_encode()
    .into())
}

/// `refundWithSignature` reverts with `ZeroRefund` on zero and takes a `uint128`.
fn refund_amount(payload: &EnrichedRefundPayload) -> Result<U128, &'static str> {
    match u256_to_u128(payload.amount.0) {
        Some(amount) if amount != U128::ZERO => Ok(amount),
        _ => Err(err::ERR_REFUND_AMOUNT_INVALID),
    }
}

/// Rejects a refund that would move no tokens.
fn assert_refundable(
    state: &OnchainChannelState,
    post_claim_total: U128,
) -> Result<(), &'static str> {
    if state.balance.saturating_sub(post_claim_total) == U128::ZERO {
        return Err(err::ERR_REFUND_NO_BALANCE);
    }
    Ok(())
}

fn refund_calldata(payload: &EnrichedRefundPayload, amount: U128, signature: Bytes) -> Bytes {
    refundWithSignatureCall {
        config: to_abi_channel_config(&payload.channel_config),
        amount: amount.to::<u128>(),
        nonce: payload.refund_nonce.0,
        receiverAuthorizerSignature: signature,
    }
    .abi_encode()
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    fn state(balance: u128, total_claimed: u128) -> OnchainChannelState {
        OnchainChannelState {
            balance: U128::from(balance),
            total_claimed: U128::from(total_claimed),
            withdraw_requested_at: 0,
            refund_nonce: U256::ZERO,
        }
    }

    #[test]
    fn refund_with_no_escrow_left_is_rejected() {
        assert_eq!(
            assert_refundable(&state(1_000, 1_000), U128::from(1_000u128)),
            Err(err::ERR_REFUND_NO_BALANCE)
        );
    }

    /// Bundled claims shrink what the refund can return.
    #[test]
    fn bundled_claim_that_takes_all_escrow_is_rejected() {
        assert_eq!(
            assert_refundable(&state(1_000, 200), U128::from(1_000u128)),
            Err(err::ERR_REFUND_NO_BALANCE)
        );
        assert_eq!(
            assert_refundable(&state(1_000, 200), U128::from(900u128)),
            Ok(())
        );
    }
}
