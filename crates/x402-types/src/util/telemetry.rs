//! Shared tracing helpers for x402 telemetry.

use std::fmt::Display;

use crate::chain::ChainId;

/// Records the chain, payer, and payment destination on the current tracing span.
pub fn record_payment_context(chain_id: &ChainId, payer: impl Display, pay_to: impl Display) {
    let span = tracing::Span::current();
    span.record("chain_id", tracing::field::display(chain_id));
    span.record("payer", tracing::field::display(payer));
    span.record("pay_to", tracing::field::display(pay_to));
}

/// Records the chain and payment destination before the payer has been decoded.
pub fn record_chain_and_pay_to(chain_id: &ChainId, pay_to: impl Display) {
    let span = tracing::Span::current();
    span.record("chain_id", tracing::field::display(chain_id));
    span.record("pay_to", tracing::field::display(pay_to));
}

/// Records the payer on the current tracing span once it becomes known.
pub fn record_payer(payer: impl Display) {
    tracing::Span::current().record("payer", tracing::field::display(payer));
}
