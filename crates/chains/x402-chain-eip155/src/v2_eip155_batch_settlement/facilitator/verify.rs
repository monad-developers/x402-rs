//! `/verify` for deposit, voucher, and client refund payloads.
//!
//! Check order follows the TypeScript reference, so both return the same
//! error code when several checks fail. One difference: for a payer with code,
//! the voucher verdict comes from a claim simulation, which runs after the
//! channel read and the bounds checks (see [`super::voucher`]).

use alloy_primitives::{Address, Bytes, U128, U256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::BlockId;

use super::abi::IERC20View;
use super::channel::{
    OnchainChannelState, pinned_block, read_channel_state_at, validate_channel_config,
};
use super::deposit::{DepositCheck, build_deposit_calldata, verify_deposit_authorization};
use super::response::{BatchSettlementVerifyExtra, BatchSettlementVerifyResponse};
use super::signature::SignerCheck;
use super::submit::simulate;
use super::voucher::{
    ChannelVoucher, SimulationRejection, VoucherClaimCall, check_contract_voucher,
    check_voucher_signature, check_zero_charge_voucher, deposit_then_claim_calldata,
    simulate_voucher_claim,
};
use crate::v2_eip155_batch_settlement::errors as err;
use crate::v2_eip155_batch_settlement::types::{
    BatchSettlementPayload, BatchSettlementRefundPayload, DepositPayload, PaymentPayload,
    PaymentRequirements, u256_to_u128,
};

/// Chain and simulation sender for one request.
#[derive(Debug, Clone, Copy)]
pub struct VerifyContext {
    pub chain_id: u64,
    pub sender: Address,
}

/// `accepted`, the requirements, and the provider must name one chain.
pub fn check_networks(
    chain_id: u64,
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> Result<(), &'static str> {
    let expected = format!("eip155:{chain_id}");
    if payload.accepted.network != requirements.network
        || requirements.network.to_string() != expected
    {
        return Err(err::ERR_NETWORK_MISMATCH);
    }
    Ok(())
}

pub async fn verify<P: Provider>(
    provider: &P,
    context: VerifyContext,
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> BatchSettlementVerifyResponse {
    if let Err(reason) = check_networks(context.chain_id, payload, requirements) {
        return BatchSettlementVerifyResponse::invalid(None, reason);
    }
    let check = VoucherCheck {
        requirements,
        is_refund: false,
    };
    let chain_id = context.chain_id;
    match &payload.payload {
        BatchSettlementPayload::Deposit(deposit) => {
            verify_deposit(provider, context, deposit, requirements).await
        }
        BatchSettlementPayload::Voucher(payload) => {
            let voucher = ChannelVoucher {
                config: &payload.channel_config,
                voucher: &payload.voucher,
                chain_id,
            };
            verify_voucher(provider, check, voucher).await
        }
        BatchSettlementPayload::Refund(BatchSettlementRefundPayload::Client(refund)) => {
            let check = VoucherCheck {
                is_refund: true,
                ..check
            };
            let voucher = ChannelVoucher {
                config: &refund.channel_config,
                voucher: &refund.voucher,
                chain_id,
            };
            verify_voucher(provider, check, voucher).await
        }
        _ => BatchSettlementVerifyResponse::invalid(None, err::ERR_INVALID_PAYLOAD_TYPE),
    }
}

#[derive(Clone, Copy)]
struct VoucherCheck<'a> {
    requirements: &'a PaymentRequirements,
    is_refund: bool,
}

async fn verify_voucher<P: Provider>(
    provider: &P,
    check: VoucherCheck<'_>,
    voucher: ChannelVoucher<'_>,
) -> BatchSettlementVerifyResponse {
    let payer: Address = voucher.config.payer.into();
    match check_voucher(provider, check, voucher).await {
        Ok(state) => BatchSettlementVerifyResponse::valid(
            payer,
            BatchSettlementVerifyExtra::from_state(voucher.voucher.channel_id, &state),
        ),
        Err(rejection) => invalid_response(payer, rejection),
    }
}

/// A refund voucher is zero-charge: it asks for escrow back and pays for
/// nothing. When it equals `totalClaimed`, no contract call checks it.
async fn check_voucher<P: Provider>(
    provider: &P,
    check: VoucherCheck<'_>,
    voucher: ChannelVoucher<'_>,
) -> Result<OnchainChannelState, SimulationRejection> {
    let fields = voucher.voucher;
    validate_channel_config(
        voucher.config,
        fields.channel_id,
        check.requirements,
        voucher.chain_id,
    )
    .map_err(plain)?;
    let signer = check_voucher_signature(provider, voucher)
        .await
        .map_err(plain)?;
    let block = state_block(provider, signer).await.map_err(plain)?;
    let state = read_channel_state_at(provider, fields.channel_id, block)
        .await
        .map_err(plain)?;
    assert_voucher_bounds(&state, fields.max_claimable_amount.0, check.is_refund).map_err(plain)?;
    if signer == SignerCheck::Contract {
        check_contract_voucher(provider, voucher, state.total_claimed, block).await?;
    }
    Ok(state)
}

/// A contract-wallet verdict needs the read and the simulation on one block.
async fn state_block<P: Provider>(
    provider: &P,
    signer: SignerCheck,
) -> Result<BlockId, &'static str> {
    match signer {
        SignerCheck::Ecdsa => Ok(BlockId::latest()),
        SignerCheck::Contract => pinned_block(provider).await,
    }
}

fn plain(reason: &'static str) -> SimulationRejection {
    (reason, None)
}

fn invalid_response(
    payer: Address,
    rejection: SimulationRejection,
) -> BatchSettlementVerifyResponse {
    match rejection {
        (reason, None) => BatchSettlementVerifyResponse::invalid(Some(payer), reason),
        (reason, Some(message)) => {
            BatchSettlementVerifyResponse::invalid_with_message(Some(payer), reason, message)
        }
    }
}

/// Spec rules 7, 9, and 10. A refund voucher is zero-charge and may equal
/// `totalClaimed`; a paid voucher must exceed it.
fn assert_voucher_bounds(
    state: &OnchainChannelState,
    max_claimable: U128,
    is_refund: bool,
) -> Result<(), &'static str> {
    if state.is_empty() {
        return Err(err::ERR_CHANNEL_NOT_FOUND);
    }
    if max_claimable > state.balance {
        return Err(err::ERR_CUMULATIVE_EXCEEDS_BALANCE);
    }
    let below = if is_refund {
        max_claimable < state.total_claimed
    } else {
        max_claimable <= state.total_claimed
    };
    if below {
        return Err(err::ERR_CUMULATIVE_AMOUNT_BELOW_CLAIMED);
    }
    Ok(())
}

async fn verify_deposit<P: Provider>(
    provider: &P,
    context: VerifyContext,
    payload: &DepositPayload,
    requirements: &PaymentRequirements,
) -> BatchSettlementVerifyResponse {
    let payer: Address = payload.channel_config.payer.into();
    match check_deposit(provider, context, payload, requirements).await {
        Ok((state, _)) => BatchSettlementVerifyResponse::valid(
            payer,
            BatchSettlementVerifyExtra::from_state(payload.voucher.channel_id, &state),
        ),
        Err(rejection) => invalid_response(payer, rejection),
    }
}

/// Returns the pre-deposit channel state. The facilitator never reports a
/// projected post-deposit balance from `/verify`.
pub async fn check_deposit<P: Provider>(
    provider: &P,
    context: VerifyContext,
    payload: &DepositPayload,
    requirements: &PaymentRequirements,
) -> Result<(OnchainChannelState, U128), SimulationRejection> {
    let chain_id = context.chain_id;
    let channel_id = payload.voucher.channel_id;
    validate_channel_config(&payload.channel_config, channel_id, requirements, chain_id)
        .map_err(plain)?;
    let amount = deposit_amount(payload.deposit.amount.0).map_err(plain)?;
    let check = DepositCheck {
        payload,
        requirements,
        chain_id,
    };
    verify_deposit_authorization(provider, check)
        .await
        .map_err(plain)?;
    let voucher = ChannelVoucher {
        config: &payload.channel_config,
        voucher: &payload.voucher,
        chain_id,
    };
    let reads = check_deposit_state(provider, check, voucher, amount)
        .await
        .map_err(plain)?;
    let calldata = build_deposit_calldata(payload, amount);
    simulate(provider, context.sender, &calldata, None)
        .await
        .map_err(|message| (err::ERR_DEPOSIT_SIMULATION_FAILED, Some(message)))?;
    if reads.signer == SignerCheck::Contract {
        check_contract_deposit_voucher(provider, voucher, calldata, &reads).await?;
    }
    Ok((reads.state, amount))
}

/// Deposit is a `uint128`; zero reverts with `ZeroDeposit`.
pub fn deposit_amount(amount: U256) -> Result<U128, &'static str> {
    match u256_to_u128(amount) {
        Some(amount) if amount != U128::ZERO => Ok(amount),
        _ => Err(err::ERR_DEPOSIT_PAYLOAD),
    }
}

/// Pre-deposit reads and the local voucher verdict.
struct DepositReads {
    state: OnchainChannelState,
    signer: SignerCheck,
    block: BlockId,
}

async fn check_deposit_state<P: Provider>(
    provider: &P,
    check: DepositCheck<'_>,
    voucher: ChannelVoucher<'_>,
    amount: U128,
) -> Result<DepositReads, &'static str> {
    let signer = check_voucher_signature(provider, voucher).await?;
    let block = state_block(provider, signer).await?;
    let payer: Address = voucher.config.payer.into();
    let token = IERC20View::new(check.requirements.asset.into(), provider);
    let balance_call = token.balanceOf(payer).block(block);
    let (state, payer_balance) = tokio::join!(
        read_channel_state_at(provider, voucher.voucher.channel_id, block),
        balance_call.call(),
    );
    let state = state?;
    if payer_balance.map_err(|_| err::ERR_RPC_READ_FAILED)? < U256::from(amount) {
        return Err(err::ERR_INSUFFICIENT_BALANCE);
    }
    assert_deposit_bounds(&state, amount, voucher.voucher.max_claimable_amount.0)?;
    Ok(DepositReads {
        state,
        signer,
        block,
    })
}

/// The claim must see the deposited balance, so it runs after the deposit in
/// one `multicall`. The deposit alone already passed its own simulation from
/// the broadcast sender, so another revert here is a deposit-and-claim failure.
async fn check_contract_deposit_voucher<P: Provider>(
    provider: &P,
    voucher: ChannelVoucher<'_>,
    deposit: Bytes,
    reads: &DepositReads,
) -> Result<(), SimulationRejection> {
    if voucher.voucher.max_claimable_amount.0 <= reads.state.total_claimed {
        return check_zero_charge_voucher(provider, voucher).await;
    }
    let call = VoucherClaimCall {
        calldata: deposit_then_claim_calldata(deposit, voucher.config, voucher.voucher),
        block: reads.block,
        other_revert: err::ERR_DEPOSIT_SIMULATION_FAILED,
    };
    simulate_voucher_claim(provider, voucher.config, call).await
}

/// Spec rules 9 and 10 for a deposit. Equality with `totalClaimed` is
/// allowed: the spec table and the Go reference permit a top-up that carries
/// the current cumulative voucher.
fn assert_deposit_bounds(
    state: &OnchainChannelState,
    amount: U128,
    max_claimable: U128,
) -> Result<(), &'static str> {
    // `deposit` reverts with `DepositOverflow` past `uint128::MAX`.
    let effective = state
        .balance
        .checked_add(amount)
        .ok_or(err::ERR_DEPOSIT_PAYLOAD)?;
    if max_claimable > effective {
        return Err(err::ERR_CUMULATIVE_EXCEEDS_BALANCE);
    }
    if max_claimable < state.total_claimed {
        return Err(err::ERR_CUMULATIVE_AMOUNT_BELOW_CLAIMED);
    }
    Ok(())
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
