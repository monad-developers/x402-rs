//! Log events for vouchers with a zero `payerAuthorizer`, recorded from the
//! public facilitator. Each request runs twice, with and without a recorder,
//! and must get the same response both times.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;
mod batch_settlement_log;

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use alloy_transport::mock::Asserter;
use batch_settlement_common::rpc::{Request, Route, push_revert, revert, success};
use batch_settlement_common::*;
use batch_settlement_log::*;
use serde_json::{Value, json};
use tracing::Level;
use x402_chain_eip155::v2_eip155_batch_settlement::constants::BATCH_SETTLEMENT_ADDRESS;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::claimCall;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::compute_claim_batch_digest;
use x402_chain_eip155::v2_eip155_batch_settlement::{ChannelConfig, VoucherClaim};

const WALLET: Address = Address::repeat_byte(0x11);

fn voucher_body(config: &ChannelConfig, signature: Bytes) -> String {
    let payload = json!({
        "type": "voucher",
        "channelConfig": config,
        "voucher": {
            "channelId": channel_id(config),
            "maxClaimableAmount": "300",
            "signature": signature,
        },
    });
    request(payload, &requirements(AUTHORIZER))
}

/// Queues the reads of an account without code and a channel with 1000.
fn eoa_voucher_provider() -> Arc<MockProvider> {
    let asserter = Asserter::new();
    no_code(&asserter);
    push_channel_state(&asserter, 1_000, 0, 0);
    Arc::new(MockProvider::new(asserter))
}

#[test]
fn valid_zero_authorizer_voucher_is_a_debug_event() {
    let payer = PrivateKeySigner::random();
    let config = channel_config(payer.address(), Address::ZERO, AUTHORIZER);
    let body = voucher_body(&config, voucher_signature(&payer, &config));
    let (response, events) = send_logged(verify, &body, eoa_voucher_provider);
    assert_eq!(response["isValid"], true, "{response}");
    let expected = one_voucher("verify", "voucher", &config);
    assert_only_event(&events, Level::DEBUG, &expected);
}

#[test]
fn rejected_zero_authorizer_voucher_is_one_warning_with_its_reason() {
    let payer = PrivateKeySigner::random();
    let config = channel_config(payer.address(), Address::ZERO, AUTHORIZER);
    let other = PrivateKeySigner::random();
    let body = voucher_body(&config, voucher_signature(&other, &config));
    let (response, events) = send_logged(verify, &body, || {
        let asserter = Asserter::new();
        no_code(&asserter);
        Arc::new(MockProvider::new(asserter))
    });
    let reason = "invalid_batch_settlement_evm_voucher_signature";
    assert_eq!(response["invalidReason"], reason);
    let expected = one_voucher("verify", "voucher", &config);
    assert_only_event(&events, Level::WARN, &format!("{expected} reason={reason}"));
}

#[test]
fn nonzero_authorizer_voucher_is_not_logged() {
    let payer = PrivateKeySigner::random();
    let config = channel_config(payer.address(), payer.address(), AUTHORIZER);
    let body = voucher_body(&config, voucher_signature(&payer, &config));
    let (response, events) = send_logged(verify, &body, || {
        let asserter = Asserter::new();
        push_channel_state(&asserter, 1_000, 0, 0);
        Arc::new(MockProvider::new(asserter))
    });
    assert_eq!(response["isValid"], true, "{response}");
    assert!(events.is_empty(), "{events:?}");
}

/// A wallet with code. The canonical `claim` simulation accepts or reverts.
fn wallet_provider(accepts: bool) -> Arc<MockProvider> {
    let route: Route = Arc::new(move |request: &Request| {
        if request.method == "eth_blockNumber" {
            return Some(success("0x10"));
        }
        let is_claim = request.method == "eth_call"
            && request.to() == Some(BATCH_SETTLEMENT_ADDRESS)
            && request.input().starts_with(&claimCall::SELECTOR);
        is_claim.then(|| match accepts {
            true => success(Bytes::new()),
            false => revert(&REVERT_DATA),
        })
    });
    let asserter = Asserter::new();
    push_bytes(&asserter, vec![0x60, 0x00]);
    push_channel_state(&asserter, 1_000, 0, 0);
    no_code(&asserter);
    Arc::new(MockProvider::routed(asserter, Some(route)))
}

#[test]
fn valid_contract_wallet_voucher_is_not_a_warning() {
    let config = channel_config(WALLET, Address::ZERO, AUTHORIZER);
    let body = voucher_body(&config, Bytes::from(vec![0xab; 65]));
    let (response, events) = send_logged(verify, &body, || wallet_provider(true));
    assert_eq!(response["isValid"], true, "{response}");
    let expected = one_voucher("verify", "voucher", &config);
    assert_only_event(&events, Level::DEBUG, &expected);
}

/// The response keeps the revert detail. The event keeps only the code.
#[test]
fn failed_contract_wallet_simulation_logs_the_code_without_the_revert() {
    let config = channel_config(WALLET, Address::ZERO, AUTHORIZER);
    let body = voucher_body(&config, Bytes::from(vec![0xab; 65]));
    let (response, events) = send_logged(verify, &body, || wallet_provider(false));
    let reason = "invalid_batch_settlement_evm_claim_simulation_failed";
    assert_eq!(response["invalidReason"], reason);
    let message = response["invalidMessage"].as_str().unwrap();
    assert!(message.contains("deadbeef"), "{message}");
    let expected = one_voucher("verify", "voucher", &config);
    assert_only_event(&events, Level::WARN, &format!("{expected} reason={reason}"));
}

fn claim_body(claims: &[VoucherClaim]) -> String {
    let authorizer = &claim_authorizer();
    let digest = compute_claim_batch_digest(claims, CHAIN_ID);
    let payload = json!({
        "type": "claim",
        "claims": claims,
        "claimAuthorizerSignature": sign(authorizer, digest),
    });
    request(payload, &requirements(authorizer.address()))
}

/// Two rows with a zero `payerAuthorizer` and one without, all claimable.
/// The contract reverts the full batch, so the event names no row.
#[test]
fn failed_mixed_claim_batch_is_one_warning_that_names_no_row() {
    let (zero, other) = (PrivateKeySigner::random(), PrivateKeySigner::random());
    let claims = [
        claim_row(&zero, Address::ZERO, 1),
        claim_row(&other, other.address(), 2),
        claim_row(&zero, Address::ZERO, 3),
    ];
    let body = claim_body(&claims);
    let (response, events) = send_logged(settle, &body, || {
        let asserter = Asserter::new();
        no_code(&asserter);
        push_claim_totals(&asserter, "0x10", &[(1_000, 0); 3]);
        no_code(&asserter);
        no_code(&asserter);
        push_revert(&asserter, &REVERT_DATA);
        Arc::new(MockProvider::new(asserter))
    });
    let reason = "invalid_batch_settlement_evm_claim_simulation_failed";
    assert_eq!(response["errorReason"], reason, "{response}");
    let message = response["errorMessage"].as_str().unwrap();
    assert!(message.contains("deadbeef"), "{message}");
    let expected = format!(
        "operation=settle payload_type=claim chain_id=143 vouchers=3 \
         zero_authorizer_vouchers=2 reason={reason}"
    );
    assert_only_event(&events, Level::WARN, &expected);
}

/// Claims one zero-authorizer row. The receipt has `status`.
fn settle_one_zero_row(status: bool) -> (Value, Vec<Captured>, String) {
    let row = claim_row(&PrivateKeySigner::random(), Address::ZERO, 1);
    let body = claim_body(std::slice::from_ref(&row));
    let (response, events) = send_logged(settle, &body, || {
        let asserter = Asserter::new();
        no_code(&asserter);
        push_claim_totals(&asserter, "0x10", &[(1_000, 0)]);
        no_code(&asserter);
        push_bytes(&asserter, Vec::new());
        Arc::new(MockProvider::new(asserter).with_outcome(Ok(receipt(status, &[]))))
    });
    let expected = one_voucher("settle", "claim", &row.voucher.channel);
    let hash = B256::repeat_byte(1);
    (
        response,
        events,
        format!("{expected} transaction={hash:#x}"),
    )
}

#[test]
fn mined_claim_revert_is_a_warning_with_the_hash() {
    let (response, events, expected) = settle_one_zero_row(false);
    let reason = "invalid_batch_settlement_evm_claim_transaction_failed";
    assert_eq!(response["errorReason"], reason, "{response}");
    let hash = format!("{:#x}", B256::repeat_byte(1));
    assert_eq!(response["transaction"], hash);
    assert_only_event(&events, Level::WARN, &format!("{expected} reason={reason}"));
}

#[test]
fn successful_zero_authorizer_claim_is_a_debug_event() {
    let (response, events, expected) = settle_one_zero_row(true);
    assert_eq!(response["success"], true, "{response}");
    assert_only_event(&events, Level::DEBUG, &expected);
}
