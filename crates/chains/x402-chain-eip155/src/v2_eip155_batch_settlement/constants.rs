//! Canonical addresses and protocol bounds for the `batch-settlement` EVM scheme.
//!
//! The `x402BatchSettlement`, `ERC3009DepositCollector`, and
//! `Permit2DepositCollector` contracts are deployed through CREATE2, so they
//! keep the same address on every supported EVM chain. See
//! `docs/specs/schemes/batch-settlement/scheme_batch_settlement_evm.md`.

use alloy_primitives::{Address, address};

/// Deployed address of the `x402BatchSettlement` contract.
pub const BATCH_SETTLEMENT_ADDRESS: Address =
    address!("0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003");

/// Deployed address of the `ERC3009DepositCollector` contract.
pub const ERC3009_DEPOSIT_COLLECTOR_ADDRESS: Address =
    address!("0x4020806089470a89826cB9fB1f4059150b550004");

/// Deployed address of the `Permit2DepositCollector` contract.
pub const PERMIT2_DEPOSIT_COLLECTOR_ADDRESS: Address =
    address!("0x4020425FAf3B746C082C2f942b4E5159887B0005");

/// Minimum withdraw delay in seconds (15 minutes). Mirrors the onchain bound.
pub const MIN_WITHDRAW_DELAY: u64 = 900;

/// Maximum withdraw delay in seconds (30 days). Mirrors the onchain bound.
pub const MAX_WITHDRAW_DELAY: u64 = 2_592_000;

/// EIP-712 domain name for every batch-settlement typed-data structure.
pub const BATCH_SETTLEMENT_DOMAIN_NAME: &str = "x402 Batch Settlement";

/// EIP-712 domain version for every batch-settlement typed-data structure.
pub const BATCH_SETTLEMENT_DOMAIN_VERSION: &str = "1";

/// Grace window applied to authorization expiry checks, in seconds. A payload
/// that expires inside this window cannot land before it expires.
pub const EXPIRY_GRACE_SECONDS: u64 = 6;

#[cfg(test)]
mod tests {
    use super::*;

    /// The addresses are part of the wire contract with every other
    /// implementation. Drift breaks interop and sends funds to the wrong place.
    #[test]
    fn canonical_addresses_match_the_spec() {
        assert_eq!(
            format!("{BATCH_SETTLEMENT_ADDRESS:#x}"),
            "0x4020074e9df2ce1dee5a9c1b5c3f541d02a10003"
        );
        assert_eq!(
            format!("{ERC3009_DEPOSIT_COLLECTOR_ADDRESS:#x}"),
            "0x4020806089470a89826cb9fb1f4059150b550004"
        );
        assert_eq!(
            format!("{PERMIT2_DEPOSIT_COLLECTOR_ADDRESS:#x}"),
            "0x4020425faf3b746c082c2f942b4e5159887b0005"
        );
    }

    #[test]
    fn withdraw_delay_bounds_match_the_spec() {
        assert_eq!(MIN_WITHDRAW_DELAY, 15 * 60);
        assert_eq!(MAX_WITHDRAW_DELAY, 30 * 24 * 60 * 60);
    }
}
