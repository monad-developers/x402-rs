//! V2 EIP-155 `batch-settlement` scheme.
//!
//! Clients fund an onchain channel once and sign cumulative vouchers per
//! request. The resource server claims vouchers in batches and sweeps claimed
//! funds with `settle`. See
//! `docs/specs/schemes/batch-settlement/scheme_batch_settlement_evm.md` and
//! `docs/batch-settlement-facilitator.md`.
//!
//! The scheme registers as `v2-eip155-batch-settlement`.

pub mod constants;
pub mod encoding;
pub mod errors;
pub mod types;

pub use types::*;

#[cfg(feature = "facilitator")]
pub mod facilitator;
#[cfg(feature = "facilitator")]
pub use facilitator::{V2Eip155BatchSettlementConfig, V2Eip155BatchSettlementFacilitator};

use x402_types::scheme::X402SchemeId;

/// Scheme blueprint for `v2-eip155-batch-settlement`.
pub struct V2Eip155BatchSettlement;

impl X402SchemeId for V2Eip155BatchSettlement {
    fn namespace(&self) -> &str {
        "eip155"
    }

    fn scheme(&self) -> &str {
        BatchSettlementScheme::VALUE
    }
}
