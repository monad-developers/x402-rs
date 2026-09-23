//! Calldata encoding for the batch-settlement deposit collectors.
//!
//! `x402BatchSettlement.deposit(...)` forwards an opaque `bytes collectorData`
//! to the collector contract. Each collector decodes it as a plain ABI
//! parameter sequence, not as a wrapped struct value.

use alloy_primitives::{B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolValue, sol};

sol! {
    /// `abi.encode(channelId, salt)`, the preimage of the ERC-3009 nonce.
    struct Erc3009DepositNonceInput {
        bytes32 channelId;
        uint256 salt;
    }

    /// `collectorData` for `ERC3009DepositCollector.collect(...)`.
    struct Erc3009CollectorData {
        uint256 validAfter;
        uint256 validBefore;
        uint256 salt;
        bytes signature;
    }

    /// `collectorData` for `Permit2DepositCollector.collect(...)`.
    /// `eip2612PermitData` stays empty: this facilitator does not sponsor
    /// approvals, so the payer must approve canonical Permit2 in advance.
    struct Permit2CollectorData {
        uint256 nonce;
        uint256 deadline;
        bytes permit2Signature;
        bytes eip2612PermitData;
    }
}

/// Computes the ERC-3009 nonce the collector uses:
/// `keccak256(abi.encode(channelId, salt))`.
pub fn build_erc3009_deposit_nonce(channel_id: B256, salt: B256) -> B256 {
    let input = Erc3009DepositNonceInput {
        channelId: channel_id,
        salt: U256::from_be_bytes(salt.0),
    };
    keccak256(input.abi_encode())
}

/// Encodes `abi.encode(validAfter, validBefore, salt, signature)`.
pub fn build_erc3009_collector_data(
    valid_after: U256,
    valid_before: U256,
    salt: B256,
    signature: &Bytes,
) -> Bytes {
    // The collector decodes `(uint256,uint256,uint256,bytes)`, so encode a
    // parameter sequence. A wrapped struct value adds an outer offset word.
    Bytes::from(
        (
            valid_after,
            valid_before,
            U256::from_be_bytes(salt.0),
            signature.clone(),
        )
            .abi_encode_sequence(),
    )
}

/// Encodes `abi.encode(nonce, deadline, permit2Signature, "")`.
pub fn build_permit2_collector_data(
    nonce: U256,
    deadline: U256,
    permit2_signature: &Bytes,
) -> Bytes {
    Bytes::from((nonce, deadline, permit2_signature.clone(), Bytes::new()).abi_encode_sequence())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{b256, hex};

    #[test]
    fn erc3009_deposit_nonce_matches_keccak_of_the_encoded_pair() {
        // Build `abi.encode(bytes32,uint256)` by hand: two 32-byte big-endian
        // words. An independent preimage catches a change of encoder.
        let channel_id =
            b256!("0x1111111111111111111111111111111111111111111111111111111111111111");
        let salt = b256!("0x2222222222222222222222222222222222222222222222222222222222222222");
        let mut packed = [0u8; 64];
        packed[..32].copy_from_slice(channel_id.as_slice());
        packed[32..].copy_from_slice(salt.as_slice());

        assert_eq!(
            build_erc3009_deposit_nonce(channel_id, salt),
            keccak256(packed)
        );
    }

    #[test]
    fn erc3009_collector_data_decodes_as_a_parameter_sequence() {
        let bytes = build_erc3009_collector_data(
            U256::ZERO,
            U256::from(1_770_000_000u64),
            b256!("0x0000000000000000000000000000000000000000000000000000000000000077"),
            &Bytes::from_static(&hex!("deadbeef")),
        );
        assert_eq!(bytes.len(), 192);
        let decoded = Erc3009CollectorData::abi_decode_sequence(&bytes).unwrap();
        assert_eq!(decoded.validAfter, U256::ZERO);
        assert_eq!(decoded.validBefore, U256::from(1_770_000_000u64));
        assert_eq!(decoded.salt, U256::from(0x77u64));
        assert_eq!(decoded.signature, Bytes::from_static(&hex!("deadbeef")));
    }

    #[test]
    fn permit2_collector_data_decodes_as_a_parameter_sequence() {
        let bytes = build_permit2_collector_data(
            U256::from(42u64),
            U256::from(1_770_000_000u64),
            &Bytes::from_static(&hex!("abcd")),
        );
        assert_eq!(bytes.len(), 224);
        let decoded = Permit2CollectorData::abi_decode_sequence(&bytes).unwrap();
        assert_eq!(decoded.nonce, U256::from(42u64));
        assert_eq!(decoded.deadline, U256::from(1_770_000_000u64));
        assert_eq!(decoded.permit2Signature, Bytes::from_static(&hex!("abcd")));
        assert!(decoded.eip2612PermitData.is_empty());
    }
}
