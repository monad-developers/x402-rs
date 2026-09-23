//! `/settle` through the public facilitator, against a mock RPC and a
//! recording broadcaster.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;

use std::sync::Arc;

use alloy_primitives::{Address, B256, U128, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolEvent, SolValue};
use alloy_transport::mock::Asserter;
use batch_settlement_common::*;
use serde_json::{Value, json};
use x402_chain_eip155::V2Eip155BatchSettlement;
use x402_chain_eip155::chain::MetaTransactionSendError;
use x402_chain_eip155::v2_eip155_batch_settlement::constants::BATCH_SETTLEMENT_ADDRESS;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::{
    Claimed, Refunded, Settled, claimWithSignatureCall, settleCall,
};
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::{
    compute_claim_batch_digest, compute_refund_digest, compute_voucher_digest,
};
use x402_chain_eip155::v2_eip155_batch_settlement::{
    U128String, VoucherClaim, VoucherClaimVoucher,
};
use x402_types::proto;
use x402_types::scheme::X402SchemeFacilitatorBuilder;

fn settle(provider: Arc<MockProvider>, body: String) -> Value {
    let facilitator = V2Eip155BatchSettlement.build(provider, None).unwrap();
    let request =
        proto::SettleRequest::from(serde_json::value::RawValue::from_string(body).unwrap());
    run(facilitator.settle(&request)).unwrap().0
}

struct ClaimFixture {
    authorizer: PrivateKeySigner,
    claims: Vec<VoucherClaim>,
}

fn claim_fixture(total: u128) -> ClaimFixture {
    let authorizer = PrivateKeySigner::random();
    let payer = PrivateKeySigner::random();
    let config = channel_config(
        Address::repeat_byte(0x11),
        payer.address(),
        authorizer.address(),
    );
    let digest = compute_voucher_digest(channel_id(&config), U128::from(total), CHAIN_ID);
    let claim = VoucherClaim {
        voucher: VoucherClaimVoucher {
            channel: config,
            max_claimable_amount: U128String(U128::from(total)),
        },
        signature: sign(&payer, digest),
        total_claimed: U128String(U128::from(total)),
    };
    ClaimFixture {
        authorizer,
        claims: vec![claim],
    }
}

fn claim_body(fixture: &ClaimFixture, signed: bool) -> String {
    let mut payload = json!({ "type": "claim", "claims": fixture.claims });
    if signed {
        let digest = compute_claim_batch_digest(&fixture.claims, CHAIN_ID);
        payload["claimAuthorizerSignature"] = json!(sign(&fixture.authorizer, digest));
    }
    request(payload, &requirements(fixture.authorizer.address()))
}

#[test]
fn claim_without_an_authorizer_signature_is_rejected() {
    let fixture = claim_fixture(500);
    let provider = Arc::new(MockProvider::new(Asserter::new()));
    let response = settle(provider.clone(), claim_body(&fixture, false));
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_authorizer_not_configured"
    );
    assert!(provider.sent().is_empty());
}

#[test]
fn claim_is_simulated_and_broadcast_from_the_same_signer() {
    let fixture = claim_fixture(500);
    let asserter = Asserter::new();
    no_code(&asserter);
    push_claim_totals(&asserter, "0x10", &[(1_000, 100)]);
    push_bytes(&asserter, Vec::new());
    let event = Claimed {
        channelId: channel_id(&fixture.claims[0].voucher.channel),
        sender: Address::repeat_byte(0xfa),
        claimAmount: 400,
        newTotalClaimed: 500,
    };
    let provider =
        MockProvider::new(asserter).with_outcome(Ok(receipt(true, &[event.encode_log_data()])));
    let provider = Arc::new(provider);
    let response = settle(provider.clone(), claim_body(&fixture, true));
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["amount"], "");
    let sent = provider.sent();
    assert_eq!(sent[0].to, BATCH_SETTLEMENT_ADDRESS);
    assert_eq!(sent[0].from, Some(provider.signer()));
    let calls = provider.requests_for("eth_call");
    let simulation = calls.last().unwrap();
    assert_eq!(simulation.to(), Some(BATCH_SETTLEMENT_ADDRESS));
    assert_eq!(simulation.from(), Some(provider.signer()));
    assert_eq!(simulation.input(), sent[0].calldata);
    assert!(
        simulation
            .input()
            .starts_with(&claimWithSignatureCall::SELECTOR)
    );
}

fn settle_body() -> String {
    let payload = json!({ "type": "settle", "receiver": RECEIVER, "token": TOKEN });
    request(payload, &requirements(Address::repeat_byte(0x44)))
}

/// `eth_estimateGas` of a `settle` that transfers Monad USDC on mainnet. A fixed
/// limit of 120,000 is below it.
const MONAD_USDC_SETTLE_GAS: u64 = 125_884;

/// Queues the reads of a `settle` that owes 500: block number, `receivers`,
/// the gas estimate, and the simulation.
fn owed_transfer(estimate: u64) -> Asserter {
    let asserter = Asserter::new();
    asserter.push_success(&"0x2a");
    push_bytes(&asserter, (900u128, 400u128).abi_encode_params());
    asserter.push_success(&format!("{estimate:#x}"));
    push_bytes(&asserter, Vec::new());
    asserter
}

#[test]
fn settle_reports_the_amount_from_the_settled_event() {
    let asserter = owed_transfer(MONAD_USDC_SETTLE_GAS);
    let event = Settled {
        receiver: RECEIVER,
        token: TOKEN,
        sender: Address::repeat_byte(0xfa),
        amount: 500,
    };
    let provider =
        MockProvider::new(asserter).with_outcome(Ok(receipt(true, &[event.encode_log_data()])));
    let provider = Arc::new(provider);
    let response = settle(provider.clone(), settle_body());
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["amount"], "500");
}

/// The owed read and the gas estimate use the block the facilitator pinned,
/// so the estimate always prices the transfer path the read showed.
#[test]
fn settle_reads_and_estimates_at_one_pinned_block() {
    let asserter = owed_transfer(MONAD_USDC_SETTLE_GAS);
    let provider = MockProvider::new(asserter).with_outcome(Ok(receipt(true, &[])));
    let provider = Arc::new(provider);
    settle(provider.clone(), settle_body());
    let owed = &provider.requests_for("eth_call")[0];
    let estimate = &provider.requests_for("eth_estimateGas")[0];
    assert_eq!(owed.block(), Some("0x2a"));
    assert_eq!(estimate.block(), Some("0x2a"));
    assert_eq!(estimate.from(), Some(provider.signer()));
    assert_eq!(estimate.to(), Some(BATCH_SETTLEMENT_ADDRESS));
    assert!(estimate.input().starts_with(&settleCall::SELECTOR));
}

/// The final simulation and the broadcast carry the node's estimate for the
/// transfer path, not a fixed cap. A token whose transfer costs more than any
/// cap must still settle.
#[test]
fn settle_broadcasts_the_estimated_gas_limit() {
    for estimate in [MONAD_USDC_SETTLE_GAS, 400_000] {
        let event = Settled {
            receiver: RECEIVER,
            token: TOKEN,
            sender: Address::repeat_byte(0xfa),
            amount: 500,
        };
        let receipt = receipt(true, &[event.encode_log_data()]);
        let provider = MockProvider::new(owed_transfer(estimate)).with_outcome(Ok(receipt));
        let provider = Arc::new(provider);
        let response = settle(provider.clone(), settle_body());
        assert_eq!(response["success"], true, "{response}");
        let sent = &provider.sent()[0];
        let simulation = provider.requests_for("eth_call").pop().unwrap();
        assert_eq!(simulation.input(), sent.calldata);
        assert_eq!(simulation.gas(), Some(estimate));
        assert_eq!(sent.gas_limit, Some(estimate));
    }
}

/// A failed estimate means the transfer reverts at that block; nothing is sent.
#[test]
fn settle_with_a_failed_gas_estimate_is_not_broadcast() {
    let asserter = Asserter::new();
    asserter.push_success(&"0x10");
    push_bytes(&asserter, (900u128, 400u128).abi_encode_params());
    asserter.push_failure_msg("execution reverted");
    let provider = Arc::new(MockProvider::new(asserter));
    let response = settle(provider.clone(), settle_body());
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_settle_simulation_failed"
    );
    assert!(provider.sent().is_empty());
}

#[test]
fn mined_revert_keeps_the_transaction_hash() {
    let asserter = owed_transfer(MONAD_USDC_SETTLE_GAS);
    let provider = Arc::new(MockProvider::new(asserter).with_outcome(Ok(receipt(false, &[]))));
    let response = settle(provider, settle_body());
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_settle_transaction_failed"
    );
    assert_eq!(
        response["transaction"],
        format!("{:#x}", B256::repeat_byte(1))
    );
}

#[test]
fn unconfirmed_broadcast_is_settlement_pending_with_its_hash() {
    let asserter = owed_transfer(MONAD_USDC_SETTLE_GAS);
    let tx_hash = B256::repeat_byte(0x99);
    let pending = MetaTransactionSendError::Unconfirmed {
        tx_hash,
        message: "timeout".into(),
    };
    let provider = Arc::new(MockProvider::new(asserter).with_outcome(Err(pending)));
    let response = settle(provider.clone(), settle_body());
    assert_eq!(response["errorReason"], "settlement_pending");
    assert_eq!(response["transaction"], format!("{tx_hash:#x}"));
    assert_eq!(
        provider.sent().len(),
        1,
        "an uncertain broadcast is never retried"
    );
}

fn refund_body(authorizer: &PrivateKeySigner, amount: u128, nonce: u64) -> String {
    let payer = PrivateKeySigner::random();
    let config = channel_config(
        Address::repeat_byte(0x11),
        payer.address(),
        authorizer.address(),
    );
    let id = channel_id(&config);
    let digest = compute_refund_digest(id, U256::from(nonce), U128::from(amount), CHAIN_ID);
    let payload = json!({
        "type": "refund",
        "channelConfig": config,
        "voucher": {
            "channelId": id,
            "maxClaimableAmount": "0",
            "signature": sign(&payer, compute_voucher_digest(id, U128::ZERO, CHAIN_ID)),
        },
        "amount": amount.to_string(),
        "refundNonce": nonce.to_string(),
        "refundAuthorizerSignature": sign(authorizer, digest),
    });
    request(payload, &requirements(authorizer.address()))
}

#[test]
fn refund_with_no_available_escrow_is_not_broadcast() {
    let authorizer = PrivateKeySigner::random();
    let asserter = Asserter::new();
    push_channel_state(&asserter, 1_000, 1_000, 0);
    no_code(&asserter);
    let provider = Arc::new(MockProvider::new(asserter));
    let response = settle(provider.clone(), refund_body(&authorizer, 100, 0));
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_refund_no_balance"
    );
    assert!(provider.sent().is_empty());
}

#[test]
fn refund_with_a_stale_nonce_is_rejected() {
    let authorizer = PrivateKeySigner::random();
    let asserter = Asserter::new();
    push_channel_state(&asserter, 1_000, 0, 2);
    let provider = Arc::new(MockProvider::new(asserter));
    let response = settle(provider.clone(), refund_body(&authorizer, 100, 1));
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_refund_payload"
    );
    assert!(provider.sent().is_empty());
}

#[test]
fn refund_reports_the_event_amount_and_end_of_block_state() {
    let authorizer = PrivateKeySigner::random();
    let body = refund_body(&authorizer, 5_000, 0);
    let channel = serde_json::from_str::<Value>(&body).unwrap()["paymentPayload"]["payload"]
        ["voucher"]["channelId"]
        .as_str()
        .unwrap()
        .parse::<B256>()
        .unwrap();
    let asserter = Asserter::new();
    push_channel_state(&asserter, 1_000, 200, 0);
    no_code(&asserter);
    push_bytes(&asserter, Vec::new());
    push_channel_state(&asserter, 200, 200, 1);
    let event = Refunded {
        channelId: channel,
        sender: Address::repeat_byte(0xfa),
        amount: 800,
    };
    let provider =
        MockProvider::new(asserter).with_outcome(Ok(receipt(true, &[event.encode_log_data()])));
    let provider = Arc::new(provider);
    let response = settle(provider.clone(), body);
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["amount"], "800");
    assert_eq!(response["extra"]["channelState"]["balance"], "200");
    assert_eq!(response["extra"]["channelState"]["refundNonce"], "1");
    // Pre-state reads, the simulation, then the snapshot at the receipt block
    // (0x10), not at `latest`.
    let calls = provider.requests_for("eth_call");
    let blocks: Vec<_> = calls.iter().map(|call| call.block().unwrap()).collect();
    let snapshot = ["0x10", "0x10", "0x10"];
    assert_eq!(blocks[..3], ["latest", "latest", "latest"]);
    assert_eq!(blocks[4..], snapshot);
}

#[test]
fn bare_voucher_cannot_be_settled() {
    let payload = json!({
        "type": "voucher",
        "channelConfig": channel_config(Address::ZERO, Address::ZERO, Address::ZERO),
        "voucher": { "channelId": B256::ZERO, "maxClaimableAmount": "1", "signature": "0x" },
    });
    let provider = Arc::new(MockProvider::new(Asserter::new()));
    let response = settle(
        provider,
        request(payload, &requirements(Address::repeat_byte(0x44))),
    );
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_payload_type"
    );
}
