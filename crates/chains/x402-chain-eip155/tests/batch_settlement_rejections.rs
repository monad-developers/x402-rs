//! Strict input and client-safe errors: a `withdrawDelay` wider than `uint40`
//! never parses, no response carries transport text, and a `settle` that runs
//! out of gas at its broadcast limit is not broadcast.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes, U128, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolValue};
use alloy_transport::TransportErrorKind;
use alloy_transport::mock::{Asserter, MockResponse};
use batch_settlement_common::*;
use serde_json::{Value, json};
use x402_chain_eip155::V2Eip155BatchSettlement;
use x402_chain_eip155::chain::MetaTransactionSendError;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::{
    abi::X402BatchSettlement::settleCall, compute_claim_batch_digest, compute_refund_digest,
    compute_voucher_digest,
};
use x402_chain_eip155::v2_eip155_batch_settlement::{
    U128String, VoucherClaim, VoucherClaimVoucher,
};
use x402_types::proto;
use x402_types::scheme::{X402SchemeFacilitatorBuilder, X402SchemeFacilitatorError};

/// Stands in for transport text; a real one can hold an RPC URL and its key.
const MARKER: &str = "transport-detail-marker";

fn settle(provider: Arc<MockProvider>, body: String) -> Result<Value, X402SchemeFacilitatorError> {
    let facilitator = V2Eip155BatchSettlement.build(provider, None).unwrap();
    let raw = serde_json::value::RawValue::from_string(body).unwrap();
    run(facilitator.settle(&proto::SettleRequest::from(raw))).map(|response| response.0)
}

fn claim_row(authorizer: Address) -> VoucherClaim {
    let payer = PrivateKeySigner::random();
    let config = channel_config(Address::repeat_byte(0x11), payer.address(), authorizer);
    let digest = compute_voucher_digest(channel_id(&config), U128::from(500u128), CHAIN_ID);
    VoucherClaim {
        voucher: VoucherClaimVoucher {
            channel: config,
            max_claimable_amount: U128String(U128::from(500u128)),
        },
        signature: sign(&payer, digest),
        total_claimed: U128String(U128::from(500u128)),
    }
}

fn claim_payload(authorizer: &PrivateKeySigner) -> Value {
    let claims = vec![claim_row(authorizer.address())];
    let digest = compute_claim_batch_digest(&claims, CHAIN_ID);
    json!({
        "type": "claim",
        "claims": claims,
        "claimAuthorizerSignature": sign(authorizer, digest),
    })
}

fn refund_payload(authorizer: &PrivateKeySigner) -> Value {
    let config = channel_config(
        Address::repeat_byte(0x11),
        Address::ZERO,
        authorizer.address(),
    );
    let id = channel_id(&config);
    let digest = compute_refund_digest(id, U256::ZERO, U128::from(100u128), CHAIN_ID);
    let claims = vec![claim_row(authorizer.address())];
    let claim_digest = compute_claim_batch_digest(&claims, CHAIN_ID);
    json!({
        "type": "refund",
        "channelConfig": config,
        "voucher": { "channelId": id, "maxClaimableAmount": "0", "signature": "0x" },
        "amount": "100",
        "refundNonce": "0",
        "refundAuthorizerSignature": sign(authorizer, digest),
        "claims": claims,
        "claimAuthorizerSignature": sign(authorizer, claim_digest),
    })
}

/// Clamping an oversized delay would change the channel id and could make a
/// malformed row match another channel.
#[test]
fn a_delay_wider_than_uint40_is_rejected_on_every_claim_path() {
    let authorizer = PrivateKeySigner::random();
    for delay in [1u64 << 40, u64::MAX] {
        let mut claim = claim_payload(&authorizer);
        claim["claims"][0]["voucher"]["channel"]["withdrawDelay"] = json!(delay);
        let mut bundled = refund_payload(&authorizer);
        bundled["claims"][0]["voucher"]["channel"]["withdrawDelay"] = json!(delay);
        let mut refund = refund_payload(&authorizer);
        refund["channelConfig"]["withdrawDelay"] = json!(delay);
        for payload in [claim, bundled, refund] {
            let provider = Arc::new(MockProvider::new(Asserter::new()));
            let body = request(payload, &requirements(authorizer.address()));
            assert!(settle(provider.clone(), body).is_err(), "{delay}");
            assert!(provider.requests().is_empty(), "no RPC call for {delay}");
            assert!(provider.sent().is_empty());
        }
    }
}

/// `refundWithSignature` takes a nonzero `uint128`. Zero and values above
/// `u128::MAX` fail before any RPC call. `2^128 + 100` catches a wrapping
/// narrowing. `u128::MAX` is the control: it passes to the channel read.
#[test]
fn a_refund_amount_outside_nonzero_uint128_is_rejected_before_any_rpc_call() {
    let invalid = "invalid_batch_settlement_evm_refund_amount_invalid";
    let read_failed = "invalid_batch_settlement_evm_channel_state_read_failed";
    let above = U256::from(u128::MAX) + U256::from(1u64);
    let cases = [
        (U256::ZERO, invalid),
        (above, invalid),
        (above + U256::from(100u64), invalid),
        (U256::from(u128::MAX), read_failed),
    ];
    let authorizer = PrivateKeySigner::random();
    for (amount, reason) in cases {
        let mut payload = refund_payload(&authorizer);
        payload["amount"] = json!(amount.to_string());
        let provider = Arc::new(MockProvider::new(Asserter::new()));
        let body = request(payload, &requirements(authorizer.address()));
        let response = settle(provider.clone(), body).unwrap();
        assert_eq!(response["success"], false, "{amount}");
        assert_eq!(response["errorReason"], reason, "{amount}: {response}");
        assert_eq!(
            provider.requests().is_empty(),
            reason == invalid,
            "{amount}"
        );
        assert!(provider.sent().is_empty(), "{amount}");
    }
}

fn settle_body() -> String {
    let payload = json!({ "type": "settle", "receiver": RECEIVER, "token": TOKEN });
    request(payload, &requirements(Address::repeat_byte(0x44)))
}

fn assert_no_transport_text(response: &Value) {
    assert!(!response.to_string().contains(MARKER), "{response}");
}

/// Block number, `receivers`, and the gas estimate of a `settle` each fail in
/// the transport in turn.
#[test]
fn transfer_reads_never_return_transport_text() {
    for failing in 0..3 {
        let asserter = Asserter::new();
        let replies: [&dyn Fn(&Asserter); 3] = [
            &|a: &Asserter| a.push_success(&"0x10"),
            &|a: &Asserter| push_bytes(a, (900u128, 400u128).abi_encode_params()),
            &|a: &Asserter| a.push_success(&"0x1ebbc"),
        ];
        for reply in &replies[..failing] {
            reply(&asserter);
        }
        rpc::push_transport_failure(&asserter, MARKER);
        let provider = Arc::new(MockProvider::new(asserter));
        let response = settle(provider.clone(), settle_body()).unwrap();
        assert_eq!(response["success"], false);
        assert_no_transport_text(&response);
        assert!(provider.sent().is_empty());
    }
}

#[test]
fn a_reverted_gas_estimate_keeps_the_revert_detail() {
    let asserter = Asserter::new();
    asserter.push_success(&"0x10");
    push_bytes(&asserter, (900u128, 400u128).abi_encode_params());
    rpc::push_revert(&asserter, &[0xde, 0xad]);
    let response = settle(Arc::new(MockProvider::new(asserter)), settle_body()).unwrap();
    assert_eq!(response["errorMessage"], "execution reverted: 0xdead");
}

/// The modeled gas cost of a USDC payout to a receiver without a balance.
const TRANSFER_GAS: u64 = 124_843;

/// A node that runs the `settle` simulation: out of gas below `TRANSFER_GAS`.
/// With no `gas` in the call, the node uses its cap and the call passes.
fn out_of_gas_below_transfer_gas(request: &rpc::Request) -> Option<MockResponse> {
    if request.method != "eth_call" || !request.input().starts_with(&settleCall::SELECTOR) {
        return None;
    }
    if request.gas().is_some_and(|gas| gas < TRANSFER_GAS) {
        let payload = json!({ "code": -32000, "message": "out of gas" });
        let error = serde_json::from_value(payload).unwrap();
        return Some(MockResponse::Failure(error));
    }
    Some(rpc::success(Bytes::new()))
}

/// An estimate that is too low for the transfer makes the final simulation
/// fail at the broadcast limit, so the facilitator sends nothing.
#[test]
fn a_settle_out_of_gas_at_the_broadcast_limit_is_not_broadcast() {
    for (estimate, broadcast) in [(100_000u64, false), (125_884, true)] {
        let asserter = Asserter::new();
        asserter.push_success(&"0x10");
        push_bytes(&asserter, (900u128, 400u128).abi_encode_params());
        asserter.push_success(&format!("{estimate:#x}"));
        let route: rpc::Route = Arc::new(out_of_gas_below_transfer_gas);
        let provider = MockProvider::routed(asserter, Some(route));
        let provider = Arc::new(provider.with_outcome(Ok(receipt(true, &[]))));
        let response = settle(provider.clone(), settle_body()).unwrap();
        assert_eq!(provider.sent().len(), usize::from(broadcast), "{response}");
        let simulation = provider.requests_for("eth_call").pop().unwrap();
        assert_eq!(simulation.gas(), Some(estimate));
        if !broadcast {
            let reason = "invalid_batch_settlement_evm_settle_simulation_failed";
            assert_eq!(response["errorReason"], reason);
        }
    }
}

fn claim_asserter(simulation: impl FnOnce(&Asserter)) -> Asserter {
    let asserter = Asserter::new();
    no_code(&asserter);
    push_claim_totals(&asserter, "0x10", &[(1_000, 100)]);
    simulation(&asserter);
    asserter
}

#[test]
fn claim_simulation_never_returns_transport_text() {
    let authorizer = PrivateKeySigner::random();
    let body = request(
        claim_payload(&authorizer),
        &requirements(authorizer.address()),
    );
    let asserter = claim_asserter(|a| rpc::push_transport_failure(a, MARKER));
    let provider = Arc::new(MockProvider::new(asserter));
    let response = settle(provider.clone(), body).unwrap();
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_claim_simulation_failed"
    );
    assert_eq!(response["errorMessage"], "RPC request failed");
    assert!(provider.sent().is_empty());
}

/// A send that fails before or after the broadcast returns fixed text. The
/// pending case still carries its hash.
#[test]
fn send_failures_never_return_transport_text() {
    let authorizer = PrivateKeySigner::random();
    let tx_hash = B256::repeat_byte(0x99);
    let outcomes = [
        MetaTransactionSendError::Transport(TransportErrorKind::custom_str(MARKER)),
        MetaTransactionSendError::Unconfirmed {
            tx_hash,
            message: MARKER.into(),
        },
    ];
    for outcome in outcomes {
        let body = request(
            claim_payload(&authorizer),
            &requirements(authorizer.address()),
        );
        let asserter = claim_asserter(|a| push_bytes(a, Vec::new()));
        let provider = MockProvider::new(asserter).with_outcome(Err(outcome));
        let response = settle(Arc::new(provider), body).unwrap();
        assert_eq!(response["success"], false);
        assert_no_transport_text(&response);
        if response["errorReason"] == "settlement_pending" {
            assert_eq!(response["transaction"], format!("{tx_hash:#x}"));
        }
    }
}
