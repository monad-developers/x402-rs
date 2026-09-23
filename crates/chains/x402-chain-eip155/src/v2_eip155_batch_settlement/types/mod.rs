//! Wire-format types for the V2 EIP-155 `batch-settlement` scheme.

pub mod numbers;
pub mod wire;

#[cfg(test)]
mod tests;

pub use numbers::{U128String, U256String, WithdrawDelay, u256_to_u128};
pub use wire::{
    AssetTransferMethod, BatchSettlementPayload, BatchSettlementPaymentRequirementsExtra,
    BatchSettlementRefundPayload, BatchSettlementScheme, ChannelConfig, ChannelStateExtra,
    ClaimPayload, DepositAuthorization, DepositPayload, DepositSegment, EnrichedRefundPayload,
    Erc3009Authorization, PaymentPayload, PaymentRequirements, Permit2Authorization,
    Permit2Permitted, Permit2Witness, RefundPayload, SettlePayload, SettleRequest, VerifyRequest,
    VoucherClaim, VoucherClaimVoucher, VoucherFields, VoucherPayload, VoucherStateExtra,
};
