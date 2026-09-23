//! EIP-712 digests and ABI conversions for the batch-settlement scheme.
//!
//! Every signed structure shares one chain-bound domain, so a digest computed
//! here matches the digest the deployed contract computes on the same chain.
//! The functions are public so a resource server that holds the receiver
//! authorizer key can sign the exact bytes this facilitator submits, without
//! handing any key to the facilitator.

use alloy_primitives::{Address, B256, U128, U256};
use alloy_sol_types::{Eip712Domain, SolStruct, eip712_domain};

use super::abi::{
    ChannelConfig as AbiChannelConfig, ClaimBatch, ClaimEntry, Refund, Voucher,
    VoucherClaim as AbiVoucherClaim, VoucherClaimInner,
};
use crate::v2_eip155_batch_settlement::constants::{
    BATCH_SETTLEMENT_ADDRESS, BATCH_SETTLEMENT_DOMAIN_NAME, BATCH_SETTLEMENT_DOMAIN_VERSION,
};
use crate::v2_eip155_batch_settlement::types::{
    ChannelConfig as WireChannelConfig, VoucherClaim as WireVoucherClaim,
};

/// The chain-bound EIP-712 domain shared by every batch-settlement structure.
pub fn batch_settlement_domain(chain_id: u64) -> Eip712Domain {
    eip712_domain! {
        name: BATCH_SETTLEMENT_DOMAIN_NAME,
        version: BATCH_SETTLEMENT_DOMAIN_VERSION,
        chain_id: chain_id,
        verifying_contract: BATCH_SETTLEMENT_ADDRESS,
    }
}

/// Converts a wire channel config into the contract tuple.
pub fn to_abi_channel_config(config: &WireChannelConfig) -> AbiChannelConfig {
    AbiChannelConfig {
        payer: config.payer.into(),
        payerAuthorizer: config.payer_authorizer.into(),
        receiver: config.receiver.into(),
        receiverAuthorizer: config.receiver_authorizer.into(),
        token: config.token.into(),
        withdrawDelay: config.withdraw_delay.into(),
        salt: config.salt,
    }
}

/// Computes `channelId = EIP712Hash(ChannelConfig)`.
///
/// The domain binds the hash to the chain id and the deployed contract, so the
/// same config yields a different channel id on a different chain.
pub fn compute_channel_id(config: &WireChannelConfig, chain_id: u64) -> B256 {
    to_abi_channel_config(config).eip712_signing_hash(&batch_settlement_domain(chain_id))
}

/// Computes the digest a voucher signer commits to.
pub fn compute_voucher_digest(channel_id: B256, max_claimable_amount: U128, chain_id: u64) -> B256 {
    Voucher {
        channelId: channel_id,
        maxClaimableAmount: max_claimable_amount.to::<u128>(),
    }
    .eip712_signing_hash(&batch_settlement_domain(chain_id))
}

/// Computes the digest a receiver authorizer signs for `refundWithSignature`.
pub fn compute_refund_digest(channel_id: B256, nonce: U256, amount: U128, chain_id: u64) -> B256 {
    Refund {
        channelId: channel_id,
        nonce,
        amount: amount.to::<u128>(),
    }
    .eip712_signing_hash(&batch_settlement_domain(chain_id))
}

/// Computes the digest a receiver authorizer signs for `claimWithSignature`.
pub fn compute_claim_batch_digest(claims: &[WireVoucherClaim], chain_id: u64) -> B256 {
    let entries = claims
        .iter()
        .map(|claim| ClaimEntry {
            channelId: compute_channel_id(&claim.voucher.channel, chain_id),
            maxClaimableAmount: claim.voucher.max_claimable_amount.0.to::<u128>(),
            totalClaimed: claim.total_claimed.0.to::<u128>(),
        })
        .collect();
    ClaimBatch { claims: entries }.eip712_signing_hash(&batch_settlement_domain(chain_id))
}

pub fn to_abi_voucher_claims(claims: &[WireVoucherClaim]) -> Vec<AbiVoucherClaim> {
    claims
        .iter()
        .map(|claim| AbiVoucherClaim {
            voucher: VoucherClaimInner {
                channel: to_abi_channel_config(&claim.voucher.channel),
                maxClaimableAmount: claim.voucher.max_claimable_amount.0.to::<u128>(),
            },
            signature: claim.signature.clone(),
            totalClaimed: claim.total_claimed.0.to::<u128>(),
        })
        .collect()
}

/// The receiver authorizer shared by every row of a claim batch.
///
/// `claimWithSignature` reads the authorizer from the first row and rejects
/// any row that disagrees, so a batch with mixed authorizers can never settle.
pub fn shared_claim_authorizer(claims: &[WireVoucherClaim]) -> Option<Address> {
    let first: Address = claims.first()?.voucher.channel.receiver_authorizer.into();
    claims
        .iter()
        .all(|claim| Address::from(claim.voucher.channel.receiver_authorizer) == first)
        .then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, b256, keccak256};
    use alloy_sol_types::SolValue;

    use crate::v2_eip155_batch_settlement::types::{U128String, VoucherClaimVoucher};

    const CHAIN_ID: u64 = 84_532;

    fn config(receiver_authorizer: &str) -> WireChannelConfig {
        WireChannelConfig {
            payer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                .parse()
                .unwrap(),
            payer_authorizer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                .parse()
                .unwrap(),
            receiver: "0x19ee5100D3a1e687F85B952bd3FbEc108Ab6A8d7"
                .parse()
                .unwrap(),
            receiver_authorizer: receiver_authorizer.parse().unwrap(),
            token: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
                .parse()
                .unwrap(),
            withdraw_delay: 900u64.try_into().unwrap(),
            salt: B256::ZERO,
        }
    }

    fn claim(receiver_authorizer: &str, max_claimable: u128, total: u128) -> WireVoucherClaim {
        WireVoucherClaim {
            voucher: VoucherClaimVoucher {
                channel: config(receiver_authorizer),
                max_claimable_amount: U128String(U128::from(max_claimable)),
            },
            signature: Bytes::new(),
            total_claimed: U128String(U128::from(total)),
        }
    }

    /// Domain separator built by hand from the EIP-712 spec, so the derived
    /// domain cannot drift without this failing.
    fn expected_domain_separator(chain_id: u64) -> B256 {
        let type_hash = keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let encoded = (
            type_hash,
            keccak256(BATCH_SETTLEMENT_DOMAIN_NAME.as_bytes()),
            keccak256(BATCH_SETTLEMENT_DOMAIN_VERSION.as_bytes()),
            U256::from(chain_id),
            BATCH_SETTLEMENT_ADDRESS,
        )
            .abi_encode_sequence();
        keccak256(encoded)
    }

    #[test]
    fn domain_separator_matches_a_hand_built_encoding() {
        assert_eq!(
            batch_settlement_domain(CHAIN_ID).separator(),
            expected_domain_separator(CHAIN_ID)
        );
    }

    /// Reference vector produced with viem `hashTypedData` on Base Sepolia and
    /// reproduced independently. It pins the whole domain plus struct encoding
    /// against the library the official client signs with.
    #[test]
    fn channel_id_matches_the_viem_reference_vector() {
        assert_eq!(
            compute_channel_id(
                &config("0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf"),
                CHAIN_ID
            ),
            b256!("0x5fafb915f0dbee350d7f84d91802dea47e8e3a71929c3cd79da161c291fb28bd")
        );
    }

    #[test]
    fn voucher_digest_matches_the_viem_reference_vector() {
        let channel_id =
            b256!("0x5fafb915f0dbee350d7f84d91802dea47e8e3a71929c3cd79da161c291fb28bd");
        assert_eq!(
            compute_voucher_digest(channel_id, U128::from(1_000u128), CHAIN_ID),
            b256!("0xa2874adbecca0abb1884b4ac1c100e3906d25208ad0c9e6a8fcf9790ccfa2246")
        );
    }

    /// `refundWithSignature` and `claimWithSignature` read the nonce and the
    /// rows from calldata, so the digest must change with each of them.
    #[test]
    fn refund_digest_binds_the_nonce_and_the_amount() {
        let channel_id = B256::repeat_byte(0x42);
        let base = compute_refund_digest(channel_id, U256::ZERO, U128::from(500u128), CHAIN_ID);
        assert_ne!(
            base,
            compute_refund_digest(channel_id, U256::from(1u64), U128::from(500u128), CHAIN_ID)
        );
        assert_ne!(
            base,
            compute_refund_digest(channel_id, U256::ZERO, U128::from(501u128), CHAIN_ID)
        );
        assert_ne!(
            base,
            compute_refund_digest(channel_id, U256::ZERO, U128::from(500u128), 1)
        );
    }

    #[test]
    fn claim_batch_digest_changes_with_every_row_field() {
        let authorizer = "0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf";
        let base = compute_claim_batch_digest(&[claim(authorizer, 5_000, 5_000)], CHAIN_ID);
        assert_ne!(
            base,
            compute_claim_batch_digest(&[claim(authorizer, 5_000, 4_000)], CHAIN_ID)
        );
        assert_ne!(
            base,
            compute_claim_batch_digest(&[claim(authorizer, 6_000, 5_000)], CHAIN_ID)
        );
        assert_ne!(
            base,
            compute_claim_batch_digest(
                &[claim(authorizer, 5_000, 5_000), claim(authorizer, 1, 1)],
                CHAIN_ID
            )
        );
    }

    /// A voucher digest must never validate as a refund or a claim digest.
    #[test]
    fn digests_of_different_structures_never_collide() {
        let channel_id = B256::repeat_byte(0x42);
        let voucher = compute_voucher_digest(channel_id, U128::from(500u128), CHAIN_ID);
        let refund = compute_refund_digest(channel_id, U256::ZERO, U128::from(500u128), CHAIN_ID);
        assert_ne!(voucher, refund);
    }

    #[test]
    fn shared_claim_authorizer_rejects_a_mixed_batch() {
        let first = "0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf";
        let second = "0x19ee5100D3a1e687F85B952bd3FbEc108Ab6A8d7";
        assert!(shared_claim_authorizer(&[claim(first, 1, 1), claim(first, 2, 2)]).is_some());
        assert!(shared_claim_authorizer(&[claim(first, 1, 1), claim(second, 2, 2)]).is_none());
        assert!(shared_claim_authorizer(&[]).is_none());
    }
}
