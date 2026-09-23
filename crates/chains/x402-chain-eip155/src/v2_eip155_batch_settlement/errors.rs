//! Wire-format error codes for the `batch-settlement` EVM scheme.
//!
//! The exact strings are part of the wire format. Facilitators, servers, and
//! clients in other languages match on them, so they must stay identical to
//! the spec error table and to
//! `typescript/packages/mechanisms/evm/src/batch-settlement/errors.ts`.

#![allow(missing_docs)]

/// Canonical prefix shared by every scheme error code.
pub const ERROR_PREFIX: &str = "invalid_batch_settlement_evm_";

// --- Payload shape and routing ---------------------------------------------

pub const ERR_INVALID_SCHEME: &str = "invalid_batch_settlement_evm_scheme";
pub const ERR_NETWORK_MISMATCH: &str = "invalid_batch_settlement_evm_network_mismatch";
pub const ERR_INVALID_PAYLOAD_TYPE: &str = "invalid_batch_settlement_evm_payload_type";
pub const ERR_DEPOSIT_PAYLOAD: &str = "invalid_batch_settlement_evm_deposit_payload";
pub const ERR_CLAIM_PAYLOAD: &str = "invalid_batch_settlement_evm_claim_payload";
pub const ERR_SETTLE_PAYLOAD: &str = "invalid_batch_settlement_evm_settle_payload";
pub const ERR_REFUND_PAYLOAD: &str = "invalid_batch_settlement_evm_refund_payload";

// --- Channel configuration --------------------------------------------------

pub const ERR_CHANNEL_ID_MISMATCH: &str = "invalid_batch_settlement_evm_channel_id_mismatch";
pub const ERR_CHANNEL_NOT_FOUND: &str = "invalid_batch_settlement_evm_channel_not_found";
pub const ERR_RECEIVER_MISMATCH: &str = "invalid_batch_settlement_evm_receiver_mismatch";
pub const ERR_RECEIVER_AUTHORIZER_MISMATCH: &str =
    "invalid_batch_settlement_evm_receiver_authorizer_mismatch";
pub const ERR_TOKEN_MISMATCH: &str = "invalid_batch_settlement_evm_token_mismatch";
pub const ERR_WITHDRAW_DELAY_MISMATCH: &str =
    "invalid_batch_settlement_evm_withdraw_delay_mismatch";
pub const ERR_WITHDRAW_DELAY_OUT_OF_RANGE: &str =
    "invalid_batch_settlement_evm_withdraw_delay_out_of_range";

// --- Voucher and cumulative accounting --------------------------------------

pub const ERR_INVALID_VOUCHER_SIGNATURE: &str = "invalid_batch_settlement_evm_voucher_signature";
pub const ERR_CUMULATIVE_EXCEEDS_BALANCE: &str =
    "invalid_batch_settlement_evm_cumulative_exceeds_balance";
pub const ERR_CUMULATIVE_AMOUNT_BELOW_CLAIMED: &str =
    "invalid_batch_settlement_evm_cumulative_below_claimed";
pub const ERR_INSUFFICIENT_BALANCE: &str = "invalid_batch_settlement_evm_insufficient_balance";

// --- Deposit authorizations -------------------------------------------------

pub const ERR_MISSING_EIP712_DOMAIN: &str = "invalid_batch_settlement_evm_missing_eip712_domain";
pub const ERR_VALID_BEFORE_EXPIRED: &str =
    "invalid_batch_settlement_evm_payload_authorization_valid_before";
pub const ERR_VALID_AFTER_IN_FUTURE: &str =
    "invalid_batch_settlement_evm_payload_authorization_valid_after";
pub const ERR_INVALID_RECEIVE_AUTHORIZATION_SIGNATURE: &str =
    "invalid_batch_settlement_evm_receive_authorization_signature";
pub const ERR_ERC3009_AUTHORIZATION_REQUIRED: &str =
    "invalid_batch_settlement_evm_erc3009_authorization_required";
pub const ERR_PERMIT2_AUTHORIZATION_REQUIRED: &str =
    "invalid_batch_settlement_evm_permit2_authorization_required";
pub const ERR_PERMIT2_INVALID_SPENDER: &str =
    "invalid_batch_settlement_evm_permit2_invalid_spender";
pub const ERR_PERMIT2_AMOUNT_MISMATCH: &str =
    "invalid_batch_settlement_evm_permit2_amount_mismatch";
pub const ERR_PERMIT2_DEADLINE_EXPIRED: &str =
    "invalid_batch_settlement_evm_permit2_deadline_expired";
pub const ERR_PERMIT2_INVALID_SIGNATURE: &str =
    "invalid_batch_settlement_evm_permit2_invalid_signature";
pub const ERR_PERMIT2_ALLOWANCE_REQUIRED: &str =
    "invalid_batch_settlement_evm_permit2_allowance_required";

// --- Authorizer signatures --------------------------------------------------

pub const ERR_AUTHORIZER_ADDRESS_MISMATCH: &str =
    "invalid_batch_settlement_evm_authorizer_address_mismatch";
pub const ERR_AUTHORIZER_NOT_CONFIGURED: &str =
    "invalid_batch_settlement_evm_authorizer_not_configured";

// --- Simulation, submission, and receipts -----------------------------------

pub const ERR_DEPOSIT_SIMULATION_FAILED: &str =
    "invalid_batch_settlement_evm_deposit_simulation_failed";
pub const ERR_DEPOSIT_TRANSACTION_FAILED: &str =
    "invalid_batch_settlement_evm_deposit_transaction_failed";
pub const ERR_CLAIM_SIMULATION_FAILED: &str =
    "invalid_batch_settlement_evm_claim_simulation_failed";
pub const ERR_CLAIM_TRANSACTION_FAILED: &str =
    "invalid_batch_settlement_evm_claim_transaction_failed";
pub const ERR_SETTLE_SIMULATION_FAILED: &str =
    "invalid_batch_settlement_evm_settle_simulation_failed";
pub const ERR_SETTLE_TRANSACTION_FAILED: &str =
    "invalid_batch_settlement_evm_settle_transaction_failed";
pub const ERR_NOTHING_TO_SETTLE: &str = "invalid_batch_settlement_evm_nothing_to_settle";
pub const ERR_REFUND_SIMULATION_FAILED: &str =
    "invalid_batch_settlement_evm_refund_simulation_failed";
pub const ERR_REFUND_TRANSACTION_FAILED: &str =
    "invalid_batch_settlement_evm_refund_transaction_failed";
pub const ERR_TRANSACTION_REVERTED: &str = "invalid_batch_settlement_evm_transaction_reverted";
pub const ERR_WAIT_FOR_RECEIPT_FAILED: &str =
    "invalid_batch_settlement_evm_wait_for_receipt_failed";
pub const ERR_RPC_READ_FAILED: &str = "invalid_batch_settlement_evm_rpc_read_failed";
pub const ERR_CHANNEL_STATE_READ_FAILED: &str =
    "invalid_batch_settlement_evm_channel_state_read_failed";

/// Reported when the facilitator broadcast a transaction but could not confirm
/// the receipt. The response carries the transaction hash so the caller can
/// reconcile instead of re-submitting. This code has no scheme prefix: it is
/// shared with the `exact` scheme across every x402 implementation.
pub const ERR_SETTLEMENT_PENDING: &str = "settlement_pending";

// --- Refund accounting ------------------------------------------------------

pub const ERR_REFUND_NO_BALANCE: &str = "invalid_batch_settlement_evm_refund_no_balance";
pub const ERR_REFUND_AMOUNT_INVALID: &str = "invalid_batch_settlement_evm_refund_amount_invalid";

#[cfg(test)]
mod tests {
    use super::*;

    /// Every scheme code carries the canonical prefix. `settlement_pending` is
    /// the one shared code and is excluded on purpose.
    #[test]
    fn scheme_error_codes_use_the_canonical_prefix() {
        for code in [
            ERR_INVALID_SCHEME,
            ERR_NETWORK_MISMATCH,
            ERR_INVALID_PAYLOAD_TYPE,
            ERR_DEPOSIT_PAYLOAD,
            ERR_CLAIM_PAYLOAD,
            ERR_SETTLE_PAYLOAD,
            ERR_REFUND_PAYLOAD,
            ERR_CHANNEL_ID_MISMATCH,
            ERR_CHANNEL_NOT_FOUND,
            ERR_RECEIVER_MISMATCH,
            ERR_RECEIVER_AUTHORIZER_MISMATCH,
            ERR_TOKEN_MISMATCH,
            ERR_WITHDRAW_DELAY_MISMATCH,
            ERR_WITHDRAW_DELAY_OUT_OF_RANGE,
            ERR_INVALID_VOUCHER_SIGNATURE,
            ERR_CUMULATIVE_EXCEEDS_BALANCE,
            ERR_CUMULATIVE_AMOUNT_BELOW_CLAIMED,
            ERR_INSUFFICIENT_BALANCE,
            ERR_MISSING_EIP712_DOMAIN,
            ERR_VALID_BEFORE_EXPIRED,
            ERR_VALID_AFTER_IN_FUTURE,
            ERR_INVALID_RECEIVE_AUTHORIZATION_SIGNATURE,
            ERR_ERC3009_AUTHORIZATION_REQUIRED,
            ERR_PERMIT2_AUTHORIZATION_REQUIRED,
            ERR_PERMIT2_INVALID_SPENDER,
            ERR_PERMIT2_AMOUNT_MISMATCH,
            ERR_PERMIT2_DEADLINE_EXPIRED,
            ERR_PERMIT2_INVALID_SIGNATURE,
            ERR_PERMIT2_ALLOWANCE_REQUIRED,
            ERR_AUTHORIZER_ADDRESS_MISMATCH,
            ERR_AUTHORIZER_NOT_CONFIGURED,
            ERR_DEPOSIT_SIMULATION_FAILED,
            ERR_DEPOSIT_TRANSACTION_FAILED,
            ERR_CLAIM_SIMULATION_FAILED,
            ERR_CLAIM_TRANSACTION_FAILED,
            ERR_SETTLE_SIMULATION_FAILED,
            ERR_SETTLE_TRANSACTION_FAILED,
            ERR_NOTHING_TO_SETTLE,
            ERR_REFUND_SIMULATION_FAILED,
            ERR_REFUND_TRANSACTION_FAILED,
            ERR_TRANSACTION_REVERTED,
            ERR_WAIT_FOR_RECEIPT_FAILED,
            ERR_RPC_READ_FAILED,
            ERR_CHANNEL_STATE_READ_FAILED,
            ERR_REFUND_NO_BALANCE,
            ERR_REFUND_AMOUNT_INVALID,
        ] {
            assert!(code.starts_with(ERROR_PREFIX), "bad prefix on {code}");
        }
    }

    #[test]
    fn settlement_pending_stays_unprefixed() {
        assert_eq!(ERR_SETTLEMENT_PENDING, "settlement_pending");
    }
}
