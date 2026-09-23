//! Log events for vouchers with a zero `payerAuthorizer`.
//!
//! With a zero `payerAuthorizer`, the contract checks each voucher against the
//! `payer`: ECDSA for an account without code, ERC-1271 for a wallet. A wallet
//! can pass `/verify` and then fail the claim. These events let an operator see
//! the outcomes of this path. They read only the typed request and the finished
//! response. They make no RPC call and do not change the response.
//!
//! - A success is a `debug` event. A failure is one `warn` event per request,
//!   also for a claim batch with many rows.
//! - A zero address does not show that the payer is a contract wallet or that
//!   the request is an attack. An account without code can also use it.
//! - `channel_id` and `payer` are present only when the request has one
//!   voucher. The contract reverts a failed batch as a whole, so the event
//!   names no failed row. It also does not show that a row passed `/verify`.
//! - The fields hold typed public values and the canonical error code. They
//!   never hold a signature, a payload, calldata, `invalidMessage`,
//!   `errorMessage`, or RPC error text.

use alloy_primitives::Address;
use tracing::Level;
use tracing::field::display;

use super::digest::compute_channel_id;
use super::response::{BatchSettlementSettleResponse, BatchSettlementVerifyResponse};
use crate::v2_eip155_batch_settlement::types::{
    BatchSettlementPayload, BatchSettlementRefundPayload, ChannelConfig,
};

/// The result of one request, as its response reports it.
struct Outcome<'a> {
    operation: &'static str,
    success: bool,
    reason: Option<&'a str>,
    transaction: Option<&'a str>,
}

pub fn log_verify(
    chain_id: u64,
    payload: &BatchSettlementPayload,
    response: &BatchSettlementVerifyResponse,
) {
    let outcome = Outcome {
        operation: "verify",
        success: response.is_valid,
        reason: response.invalid_reason.as_deref(),
        transaction: None,
    };
    emit(chain_id, payload, &outcome);
}

pub fn log_settle(
    chain_id: u64,
    payload: &BatchSettlementPayload,
    response: &BatchSettlementSettleResponse,
) {
    let transaction = response.transaction.as_str();
    let outcome = Outcome {
        operation: "settle",
        success: response.success,
        reason: response.error_reason.as_deref(),
        transaction: (!transaction.is_empty()).then_some(transaction),
    };
    emit(chain_id, payload, &outcome);
}

/// The payload type and the channel config of each voucher in the request.
fn voucher_channels(payload: &BatchSettlementPayload) -> (&'static str, Vec<&ChannelConfig>) {
    match payload {
        BatchSettlementPayload::Deposit(deposit) => ("deposit", vec![&deposit.channel_config]),
        BatchSettlementPayload::Voucher(voucher) => ("voucher", vec![&voucher.channel_config]),
        BatchSettlementPayload::Refund(BatchSettlementRefundPayload::Client(refund)) => {
            ("refund", vec![&refund.channel_config])
        }
        BatchSettlementPayload::Refund(BatchSettlementRefundPayload::Enriched(refund)) => {
            let rows = refund.claims.iter().map(|row| &row.voucher.channel);
            let configs = std::iter::once(&refund.channel_config).chain(rows);
            ("refund", configs.collect())
        }
        BatchSettlementPayload::Claim(claim) => {
            let rows = claim.claims.iter().map(|row| &row.voucher.channel);
            ("claim", rows.collect())
        }
        BatchSettlementPayload::Settle(_) => ("settle", Vec::new()),
    }
}

fn emit(chain_id: u64, payload: &BatchSettlementPayload, outcome: &Outcome<'_>) {
    let (payload_type, channels) = voucher_channels(payload);
    let zero_authorizer = channels
        .iter()
        .filter(|config| Address::from(config.payer_authorizer).is_zero())
        .count();
    if zero_authorizer == 0 {
        return;
    }
    let single = match channels.as_slice() {
        [config] => Some(*config),
        _ => None,
    };
    let channel_id = single.map(|config| display(compute_channel_id(config, chain_id)));
    let payer = single.map(|config| display(Address::from(config.payer)));
    // `tracing` needs a constant level at each call site.
    macro_rules! outcome_event {
        ($level:expr, $message:literal) => {
            tracing::event!(
                $level,
                operation = outcome.operation,
                payload_type,
                chain_id,
                vouchers = channels.len(),
                zero_authorizer_vouchers = zero_authorizer,
                channel_id,
                payer,
                reason = outcome.reason,
                transaction = outcome.transaction,
                $message
            )
        };
    }
    if outcome.success {
        outcome_event!(
            Level::DEBUG,
            "batch-settlement zero payerAuthorizer request succeeded"
        );
    } else {
        outcome_event!(
            Level::WARN,
            "batch-settlement zero payerAuthorizer request failed"
        );
    }
}
