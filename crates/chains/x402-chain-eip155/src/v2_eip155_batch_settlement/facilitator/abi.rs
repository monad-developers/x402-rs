//! Alloy bindings for `x402BatchSettlement` and its EIP-712 structures.
//!
//! The function set covers every entry point the facilitator calls, the view
//! calls it reads, and the success events it decodes from a receipt. The
//! EIP-712 structs sit beside the contract so `alloy_sol_types::SolStruct`
//! derives their typehashes from the same source of truth.

#![allow(missing_docs)]

use alloy_sol_types::sol;

sol! {
    /// Immutable channel parameters. Its EIP-712 hash is the `channelId`.
    #[derive(Debug)]
    struct ChannelConfig {
        address payer;
        address payerAuthorizer;
        address receiver;
        address receiverAuthorizer;
        address token;
        uint40 withdrawDelay;
        bytes32 salt;
    }

    /// Cumulative voucher signed by the payer side.
    #[derive(Debug)]
    struct Voucher {
        bytes32 channelId;
        uint128 maxClaimableAmount;
    }

    /// Cooperative refund authorization signed by the receiver authorizer.
    #[derive(Debug)]
    struct Refund {
        bytes32 channelId;
        uint256 nonce;
        uint128 amount;
    }

    /// One row of a signed claim batch.
    #[derive(Debug)]
    struct ClaimEntry {
        bytes32 channelId;
        uint128 maxClaimableAmount;
        uint128 totalClaimed;
    }

    /// Batch claim authorization signed by the receiver authorizer.
    #[derive(Debug)]
    struct ClaimBatch {
        ClaimEntry[] claims;
    }

    /// ERC-3009 `ReceiveWithAuthorization` typed data for a gasless deposit.
    #[derive(Debug)]
    struct ReceiveWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }

    /// Permit2 token-permissions segment.
    #[derive(Debug)]
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    /// Channel-bound witness for the Permit2 deposit collector.
    #[derive(Debug)]
    struct DepositWitness {
        bytes32 channelId;
    }

    /// Permit2 typed data for a channel-bound deposit.
    #[derive(Debug)]
    struct PermitWitnessTransferFrom {
        TokenPermissions permitted;
        address spender;
        uint256 nonce;
        uint256 deadline;
        DepositWitness witness;
    }

    /// Voucher claim row consumed by `claim` / `claimWithSignature`.
    #[derive(Debug)]
    struct VoucherClaim {
        VoucherClaimInner voucher;
        bytes signature;
        uint128 totalClaimed;
    }

    /// Inner voucher view of a `VoucherClaim`.
    #[derive(Debug)]
    struct VoucherClaimInner {
        ChannelConfig channel;
        uint128 maxClaimableAmount;
    }

    /// `x402BatchSettlement` contract bindings.
    #[allow(clippy::too_many_arguments)]
    #[derive(Debug)]
    #[sol(rpc)]
    contract X402BatchSettlement {
        function multicall(bytes[] data) external returns (bytes[] results);

        function deposit(
            ChannelConfig config,
            uint128 amount,
            address collector,
            bytes collectorData
        ) external;

        function claim(VoucherClaim[] voucherClaims) external;

        function claimWithSignature(
            VoucherClaim[] voucherClaims,
            bytes authorizerSignature
        ) external;

        function settle(address receiver, address token) external;

        function refundWithSignature(
            ChannelConfig config,
            uint128 amount,
            uint256 nonce,
            bytes receiverAuthorizerSignature
        ) external;

        function getChannelId(ChannelConfig config) external view returns (bytes32);

        function channels(bytes32 channelId)
            external
            view
            returns (uint128 balance, uint128 totalClaimed);

        function pendingWithdrawals(bytes32 channelId)
            external
            view
            returns (uint128 amount, uint40 initiatedAt);

        function receivers(address receiver, address token)
            external
            view
            returns (uint128 totalClaimed, uint128 totalSettled);

        function refundNonce(bytes32 channelId) external view returns (uint256);

        event Deposited(
            bytes32 indexed channelId,
            address indexed sender,
            uint128 amount,
            uint128 newBalance
        );

        event Claimed(
            bytes32 indexed channelId,
            address indexed sender,
            uint128 claimAmount,
            uint128 newTotalClaimed
        );

        event Settled(
            address indexed receiver,
            address indexed token,
            address indexed sender,
            uint128 amount
        );

        event Refunded(bytes32 indexed channelId, address indexed sender, uint128 amount);

        error InvalidSignature();
        error ClaimExceedsBalance();
    }

    /// Minimal ERC-20 view interface for balance and allowance reads.
    #[derive(Debug)]
    #[sol(rpc)]
    contract IERC20View {
        function balanceOf(address account) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
    }

    /// ERC-1271 signature validation entry point.
    function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4);
}

/// `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`, the value an
/// ERC-1271 wallet returns for a valid signature.
pub const EIP1271_MAGIC_VALUE: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;
    use alloy_sol_types::SolStruct;

    /// The EIP-712 type strings the deployed contract hashes into its
    /// typehash constants. A field rename or reorder in the bindings would
    /// silently invalidate every signature a TypeScript or Go client makes,
    /// so the strings stay pinned here.
    const CHANNEL_CONFIG_TYPE: &str = "ChannelConfig(address payer,address payerAuthorizer,\
address receiver,address receiverAuthorizer,address token,uint40 withdrawDelay,bytes32 salt)";
    const VOUCHER_TYPE: &str = "Voucher(bytes32 channelId,uint128 maxClaimableAmount)";
    const REFUND_TYPE: &str = "Refund(bytes32 channelId,uint256 nonce,uint128 amount)";
    const CLAIM_BATCH_TYPE: &str = "ClaimBatch(ClaimEntry[] claims)ClaimEntry(bytes32 channelId,\
uint128 maxClaimableAmount,uint128 totalClaimed)";

    #[test]
    fn eip712_type_strings_match_the_deployed_contract() {
        assert_eq!(ChannelConfig::eip712_encode_type(), CHANNEL_CONFIG_TYPE);
        assert_eq!(Voucher::eip712_encode_type(), VOUCHER_TYPE);
        assert_eq!(Refund::eip712_encode_type(), REFUND_TYPE);
        assert_eq!(ClaimBatch::eip712_encode_type(), CLAIM_BATCH_TYPE);
    }

    /// The four typehashes must stay distinct, which is what stops a
    /// signature for one structure from replaying as another.
    #[test]
    fn typehashes_are_distinct_across_the_signed_structures() {
        let hashes = [
            keccak256(CHANNEL_CONFIG_TYPE.as_bytes()),
            keccak256(VOUCHER_TYPE.as_bytes()),
            keccak256(REFUND_TYPE.as_bytes()),
            keccak256(CLAIM_BATCH_TYPE.as_bytes()),
        ];
        for (index, hash) in hashes.iter().enumerate() {
            for other in &hashes[index + 1..] {
                assert_ne!(hash, other);
            }
        }
    }

    #[test]
    fn eip1271_magic_value_matches_the_canonical_selector() {
        let selector = keccak256(b"isValidSignature(bytes32,bytes)");
        assert_eq!(EIP1271_MAGIC_VALUE, selector[..4]);
    }
}
