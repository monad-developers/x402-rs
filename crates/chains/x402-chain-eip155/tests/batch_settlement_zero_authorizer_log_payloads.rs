//! Log events for a deposit, a server-completed refund, and a pending
//! broadcast with a zero `payerAuthorizer`, recorded from the public
//! facilitator. Each request runs twice, with and without a recorder, and must
//! get the same response both times.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;
mod batch_settlement_log;

use std::sync::Arc;

use alloy_primitives::{Address, B256, U128, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolValue;
use alloy_transport::mock::Asserter;
use batch_settlement_common::rpc::push_revert;
use batch_settlement_common::*;
use batch_settlement_log::*;
use serde_json::json;
use tracing::Level;
use x402_chain_eip155::chain::MetaTransactionSendError;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::{
    compute_claim_batch_digest, compute_refund_digest, compute_voucher_digest,
};
use x402_chain_eip155::v2_eip155_batch_settlement::{ChannelConfig, VoucherClaim};

/// A deposit on a new channel whose vouchers the payer signs directly.
fn zero_authorizer_deposit() -> (ChannelConfig, String) {
    let payer = PrivateKeySigner::random();
    let config = channel_config(payer.address(), Address::ZERO, AUTHORIZER);
    let payload = erc3009_deposit_on(&payer, &config);
    (config, request(payload, &requirements(AUTHORIZER)))
}

/// The deposit checks of an account without code: the ERC-3009 signer, the
/// voucher signer, the channel, the payer balance, then the simulation.
fn queue_deposit_checks(asserter: &Asserter) {
    no_code(asserter);
    no_code(asserter);
    push_channel_state(asserter, 0, 0, 0);
    push_bytes(asserter, U256::from(5_000u64).abi_encode());
    push_bytes(asserter, Vec::new());
}

#[test]
fn valid_zero_authorizer_deposit_is_a_debug_event() {
    let (config, body) = zero_authorizer_deposit();
    let (response, events) = send_logged(verify, &body, || {
        let asserter = Asserter::new();
        queue_deposit_checks(&asserter);
        Arc::new(MockProvider::new(asserter))
    });
    assert_eq!(response["isValid"], true, "{response}");
    let expected = one_voucher("verify", "deposit", &config);
    assert_only_event(&events, Level::DEBUG, &expected);
}

/// The event keeps the canonical reason and the hash, not the send error.
#[test]
fn pending_zero_authorizer_deposit_logs_the_reason_and_the_hash() {
    let (config, body) = zero_authorizer_deposit();
    let tx_hash = B256::repeat_byte(0x99);
    let (response, events) = send_logged(settle, &body, || {
        let asserter = Asserter::new();
        queue_deposit_checks(&asserter);
        push_bytes(&asserter, Vec::new());
        let pending = MetaTransactionSendError::Unconfirmed {
            tx_hash,
            message: "timeout".into(),
        };
        Arc::new(MockProvider::new(asserter).with_outcome(Err(pending)))
    });
    assert_eq!(response["errorReason"], "settlement_pending", "{response}");
    assert_eq!(response["transaction"], format!("{tx_hash:#x}"));
    let expected = one_voucher("settle", "deposit", &config);
    let expected = format!("{expected} reason=settlement_pending transaction={tx_hash:#x}");
    assert_only_event(&events, Level::WARN, &expected);
}

/// A refund of 500 on `target` that also claims `claims`.
fn refund_body(
    payer: &PrivateKeySigner,
    target: &ChannelConfig,
    claims: &[VoucherClaim],
) -> String {
    let authorizer = &claim_authorizer();
    let id = channel_id(target);
    let refund = compute_refund_digest(id, U256::ZERO, U128::from(500u128), CHAIN_ID);
    let claim = compute_claim_batch_digest(claims, CHAIN_ID);
    let payload = json!({
        "type": "refund",
        "channelConfig": target,
        "voucher": {
            "channelId": id,
            "maxClaimableAmount": "0",
            "signature": sign(payer, compute_voucher_digest(id, U128::ZERO, CHAIN_ID)),
        },
        "amount": "500",
        "refundNonce": "0",
        "claims": claims,
        "refundAuthorizerSignature": sign(authorizer, refund),
        "claimAuthorizerSignature": sign(authorizer, claim),
    });
    request(payload, &requirements(authorizer.address()))
}

/// The target has a nonzero `payerAuthorizer`. Only a claim row has a zero
/// one, so the event exists only because the claim rows count. The multicall
/// reverts as a whole, so the event names no channel and no payer.
#[test]
fn failed_refund_counts_its_zero_authorizer_claim_row_and_names_no_row() {
    let (payer, zero, other) = (
        PrivateKeySigner::random(),
        PrivateKeySigner::random(),
        PrivateKeySigner::random(),
    );
    let target = channel_config(
        payer.address(),
        payer.address(),
        claim_authorizer().address(),
    );
    let claims = [
        claim_row(&zero, Address::ZERO, 1),
        claim_row(&other, other.address(), 2),
    ];
    let body = refund_body(&payer, &target, &claims);
    let (response, events) = send_logged(settle, &body, || {
        let asserter = Asserter::new();
        push_channel_state(&asserter, 1_000, 0, 0);
        no_code(&asserter);
        no_code(&asserter);
        push_claim_totals(&asserter, "0x10", &[(1_000, 0); 2]);
        no_code(&asserter);
        push_revert(&asserter, &REVERT_DATA);
        Arc::new(MockProvider::new(asserter))
    });
    let reason = "invalid_batch_settlement_evm_refund_simulation_failed";
    assert_eq!(response["errorReason"], reason, "{response}");
    let message = response["errorMessage"].as_str().unwrap();
    assert!(message.contains("deadbeef"), "{message}");
    let expected = format!(
        "operation=settle payload_type=refund chain_id=143 vouchers=3 \
         zero_authorizer_vouchers=1 reason={reason}"
    );
    assert_only_event(&events, Level::WARN, &expected);
}
