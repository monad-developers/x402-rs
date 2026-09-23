//! Voucher signature checks with the rules of `_processVoucherClaim`.
//!
//! - Nonzero `payerAuthorizer`: strict ECDSA against it, with no RPC call,
//!   even when that address has code.
//! - Zero `payerAuthorizer`, payer without code: strict ECDSA against the payer.
//! - Zero `payerAuthorizer`, payer with code: the contract checks the voucher
//!   with ERC-1271 from its own address in a static call. No direct call to
//!   the wallet has that caller and context. The facilitator therefore runs
//!   the canonical `claim([row])` as a read-only `eth_call`. The call needs no
//!   key, carries no state override, and is never broadcast.
//!
//! The `from` of that call is also `tx.origin`, and a wallet can read it. So
//! the call runs from a receiver-side account that can send a real claim (see
//! [`claim_origin`]). The result holds for that one origin at that block. It
//! does not prove that a later relayed `claimWithSignature` succeeds.
//!
//! `claim` checks the signature only when the row raises `totalClaimed`, and
//! the row claims `maxClaimableAmount`. A voucher at the claimed total pays
//! nothing, and no contract call ever checks its signature. For that case
//! only, the facilitator calls the wallet directly (see
//! [`check_contract_voucher`]).

use alloy_primitives::{Address, Bytes, U128};
use alloy_provider::Provider;
use alloy_rpc_types_eth::{BlockId, TransactionRequest};
use alloy_sol_types::{SolCall, SolError};

use super::abi::X402BatchSettlement::{
    ClaimExceedsBalance, InvalidSignature, claimCall, multicallCall,
};
use super::abi::{VoucherClaim, VoucherClaimInner};
use super::digest::{compute_voucher_digest, to_abi_channel_config};
use super::rpc_error::{as_revert, log_rpc_error};
use super::signature::{
    EcdsaRules, SignatureCheckError, SignedDigest, SignerCheck, call_is_valid_signature,
    check_signature_checker, verify_ecdsa,
};
use crate::v2_eip155_batch_settlement::constants::BATCH_SETTLEMENT_ADDRESS;
use crate::v2_eip155_batch_settlement::errors as err;
use crate::v2_eip155_batch_settlement::types::{ChannelConfig, VoucherFields};

/// A rejection code and, for a revert, its client-safe detail.
pub type SimulationRejection = (&'static str, Option<String>);

/// A voucher and the channel it names.
#[derive(Debug, Clone, Copy)]
pub struct ChannelVoucher<'a> {
    pub config: &'a ChannelConfig,
    pub voucher: &'a VoucherFields,
    pub chain_id: u64,
}

impl ChannelVoucher<'_> {
    fn signed(&self, signer: Address) -> SignedDigest<'_> {
        let voucher = self.voucher;
        SignedDigest {
            signature: &voucher.signature,
            digest: compute_voucher_digest(
                voucher.channel_id,
                voucher.max_claimable_amount.0,
                self.chain_id,
            ),
            signer,
        }
    }
}

/// The local part of the voucher check. [`SignerCheck::Contract`] means the
/// caller must still run [`check_contract_voucher`] or a canonical write.
pub async fn check_voucher_signature<P: Provider>(
    provider: &P,
    voucher: ChannelVoucher<'_>,
) -> Result<SignerCheck, &'static str> {
    let payer_authorizer: Address = voucher.config.payer_authorizer.into();
    let result = if payer_authorizer == Address::ZERO {
        let signed = voucher.signed(voucher.config.payer.into());
        check_signature_checker(provider, &signed, EcdsaRules::Strict).await
    } else {
        let signed = voucher.signed(payer_authorizer);
        verify_ecdsa(&signed, EcdsaRules::Strict).map(|()| SignerCheck::Ecdsa)
    };
    result.map_err(signature_reason)
}

/// Decides a payer-with-code voucher against channel state read at `block`.
pub async fn check_contract_voucher<P: Provider>(
    provider: &P,
    voucher: ChannelVoucher<'_>,
    total_claimed: U128,
    block: BlockId,
) -> Result<(), SimulationRejection> {
    if voucher.voucher.max_claimable_amount.0 > total_claimed {
        let call = VoucherClaimCall {
            calldata: claim_calldata(voucher.config, voucher.voucher),
            block,
            other_revert: err::ERR_CLAIM_SIMULATION_FAILED,
        };
        return simulate_voucher_claim(provider, voucher.config, call).await;
    }
    check_zero_charge_voucher(provider, voucher).await
}

/// A voucher at the claimed total authorizes no payment above what is already
/// claimed, and `claim` skips its row, so no canonical check exists. The
/// direct wallet call only catches a malformed or plainly wrong signature.
pub async fn check_zero_charge_voucher<P: Provider>(
    provider: &P,
    voucher: ChannelVoucher<'_>,
) -> Result<(), SimulationRejection> {
    let signed = voucher.signed(voucher.config.payer.into());
    call_is_valid_signature(provider, &signed)
        .await
        .map_err(|error| (signature_reason(error), None))
}

fn signature_reason(error: SignatureCheckError) -> &'static str {
    match error {
        SignatureCheckError::RpcReadFailed => err::ERR_RPC_READ_FAILED,
        _ => err::ERR_INVALID_VOUCHER_SIGNATURE,
    }
}

/// `claim([row])` with `totalClaimed = maxClaimableAmount`.
pub fn claim_calldata(config: &ChannelConfig, voucher: &VoucherFields) -> Bytes {
    let max_claimable = voucher.max_claimable_amount.0.to::<u128>();
    let row = VoucherClaim {
        voucher: VoucherClaimInner {
            channel: to_abi_channel_config(config),
            maxClaimableAmount: max_claimable,
        },
        signature: voucher.signature.clone(),
        totalClaimed: max_claimable,
    };
    claimCall {
        voucherClaims: vec![row],
    }
    .abi_encode()
    .into()
}

/// `multicall([deposit, claim([row])])`: the claim sees the deposited balance.
pub fn deposit_then_claim_calldata(
    deposit: Bytes,
    config: &ChannelConfig,
    voucher: &VoucherFields,
) -> Bytes {
    multicallCall {
        data: vec![deposit, claim_calldata(config, voucher)],
    }
    .abi_encode()
    .into()
}

/// One read-only claim simulation.
pub struct VoucherClaimCall {
    pub calldata: Bytes,
    /// The block of the channel read that showed the row raises `totalClaimed`.
    pub block: BlockId,
    /// The code for a revert that is not a voucher or balance failure.
    pub other_revert: &'static str,
}

/// Runs the call against the settlement contract from [`claim_origin`].
///
/// `InvalidSignature()` rejects the voucher, and `ClaimExceedsBalance()`
/// rejects its amount. An RPC failure that is not a revert is retryable, so it
/// maps to `rpc_read_failed`.
pub async fn simulate_voucher_claim<P: Provider>(
    provider: &P,
    config: &ChannelConfig,
    call: VoucherClaimCall,
) -> Result<(), SimulationRejection> {
    let from = claim_origin(provider, config, call.block)
        .await
        .map_err(|reason| (reason, None))?
        .ok_or_else(|| (call.other_revert, Some(NO_CLAIM_ORIGIN.to_string())))?;
    let request = TransactionRequest::default()
        .from(from)
        .to(BATCH_SETTLEMENT_ADDRESS)
        .input(call.calldata.into());
    let Err(error) = provider.call(request).block(call.block).await else {
        return Ok(());
    };
    let Some(revert) = as_revert(&error) else {
        log_rpc_error(&error);
        return Err((err::ERR_RPC_READ_FAILED, None));
    };
    let data = revert.data.clone().unwrap_or_default();
    if InvalidSignature::abi_decode(&data).is_ok() {
        return Err((err::ERR_INVALID_VOUCHER_SIGNATURE, None));
    }
    if ClaimExceedsBalance::abi_decode(&data).is_ok() {
        return Err((err::ERR_CUMULATIVE_EXCEEDS_BALANCE, None));
    }
    Err((call.other_revert, Some(revert.client_message())))
}

/// The client detail when neither receiver-side account can send a claim.
const NO_CLAIM_ORIGIN: &str = "no receiver-side account can send a claim transaction";

/// EIP-7702 delegation code: `0xef0100` and a 20-byte address.
const DELEGATION_PREFIX: [u8; 3] = [0xef, 0x01, 0x00];
const DELEGATION_LENGTH: usize = 23;

/// An account with no code, or with EIP-7702 delegation code, keeps its key.
/// Other code has no known key, so it is never the origin of a transaction.
fn can_originate(code: &[u8]) -> bool {
    code.is_empty() || (code.len() == DELEGATION_LENGTH && code.starts_with(&DELEGATION_PREFIX))
}

/// The `claim` caller for the simulation: the receiver authorizer if it can
/// send a transaction, else the receiver if it can. `claim` accepts both.
/// `None` when both hold other code. The code reads use `block`, which is the
/// block of the channel read and of the simulation.
async fn claim_origin<P: Provider>(
    provider: &P,
    config: &ChannelConfig,
    block: BlockId,
) -> Result<Option<Address>, &'static str> {
    for address in [config.receiver_authorizer, config.receiver].map(Address::from) {
        let code = provider
            .get_code_at(address)
            .block_id(block)
            .await
            .map_err(|error| {
                log_rpc_error(&error);
                err::ERR_RPC_READ_FAILED
            })?;
        if can_originate(&code) {
            return Ok(Some(address));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::can_originate;

    #[test]
    fn only_empty_code_and_delegation_code_can_originate() {
        let mut delegation = vec![0xef, 0x01, 0x00];
        delegation.extend([0x42; 20]);
        assert!(can_originate(&[]));
        assert!(can_originate(&delegation));
        assert!(!can_originate(&delegation[..22]), "one byte short");
        assert!(
            !can_originate(&[delegation.as_slice(), &[0]].concat()),
            "one byte long"
        );
        let mut other_version = delegation.clone();
        other_version[2] = 0x01;
        assert!(!can_originate(&other_version), "not the 0xef0100 prefix");
        assert!(!can_originate(&[0x60, 0x00]), "ordinary contract code");
    }
}
