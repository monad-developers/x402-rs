//! Deposit settlement through the public facilitator, against a mock RPC.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;

use std::sync::Arc;

use alloy_primitives::{Address, B256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolEvent;
use alloy_transport::mock::Asserter;
use batch_settlement_common::*;
use serde_json::Value;
use x402_chain_eip155::V2Eip155BatchSettlement;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::Deposited;
use x402_types::proto;
use x402_types::scheme::{X402SchemeFacilitator, X402SchemeFacilitatorBuilder};

const AUTHORIZER: Address = Address::repeat_byte(0x44);

fn facilitator(provider: Arc<MockProvider>) -> Box<dyn X402SchemeFacilitator> {
    V2Eip155BatchSettlement.build(provider, None).unwrap()
}

fn settle(facilitator: &dyn X402SchemeFacilitator, body: &str) -> Value {
    let raw = serde_json::value::RawValue::from_string(body.to_string()).unwrap();
    run(facilitator.settle(&proto::SettleRequest::from(raw)))
        .unwrap()
        .0
}

fn body(payer: &PrivateKeySigner) -> String {
    request(
        erc3009_deposit(payer, AUTHORIZER),
        &requirements(AUTHORIZER),
    )
}

fn deposit_channel(payer: &PrivateKeySigner) -> B256 {
    channel_id(&channel_config(
        payer.address(),
        payer.address(),
        AUTHORIZER,
    ))
}

/// Deposit checks, both simulations, then the broadcast.
fn queue_verified_deposit(asserter: &Asserter) {
    push_deposit_reads(asserter, 5_000);
    push_bytes(asserter, Vec::new());
    push_bytes(asserter, Vec::new());
}

#[test]
fn deposit_reports_the_event_amount_and_end_of_block_state() {
    let payer = PrivateKeySigner::random();
    let asserter = Asserter::new();
    queue_verified_deposit(&asserter);
    push_channel_state(&asserter, 1_000, 0, 0);
    let event = Deposited {
        channelId: deposit_channel(&payer),
        sender: Address::repeat_byte(0xfa),
        amount: 1_000,
        newBalance: 1_000,
    };
    let provider =
        MockProvider::new(asserter).with_outcome(Ok(receipt(true, &[event.encode_log_data()])));
    let response = settle(facilitator(Arc::new(provider)).as_ref(), &body(&payer));
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["amount"], "1000");
    assert_eq!(response["asset"], TOKEN.to_checksum(None));
    assert_eq!(response["payer"], payer.address().to_checksum(None));
    assert_eq!(response["extra"]["channelState"]["balance"], "1000");
}

/// A consumed authorization fails simulation; nothing reports success.
#[test]
fn consumed_authorization_fails_simulation_without_broadcast() {
    let payer = PrivateKeySigner::random();
    let asserter = Asserter::new();
    push_deposit_reads(&asserter, 5_000);
    asserter.push_failure_msg("execution reverted: FiatTokenV2: authorization is used or canceled");
    let provider = Arc::new(MockProvider::new(asserter));
    let response = settle(facilitator(provider.clone()).as_ref(), &body(&payer));
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_deposit_simulation_failed"
    );
    assert!(provider.sent().is_empty());
}

#[test]
fn deposit_without_a_deposited_event_is_not_a_success() {
    let payer = PrivateKeySigner::random();
    let asserter = Asserter::new();
    queue_verified_deposit(&asserter);
    let provider = MockProvider::new(asserter).with_outcome(Ok(receipt(true, &[])));
    let response = settle(facilitator(Arc::new(provider)).as_ref(), &body(&payer));
    assert_eq!(response["success"], false);
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_deposit_transaction_failed"
    );
    assert_eq!(
        response["transaction"],
        format!("{:#x}", B256::repeat_byte(1))
    );
}

/// The snapshot read after the receipt failing keeps the success and says so.
#[test]
fn failed_snapshot_read_keeps_the_success_without_a_state() {
    let payer = PrivateKeySigner::random();
    let asserter = Asserter::new();
    queue_verified_deposit(&asserter);
    let event = Deposited {
        channelId: deposit_channel(&payer),
        sender: Address::repeat_byte(0xfa),
        amount: 1_000,
        newBalance: 1_000,
    };
    let provider =
        MockProvider::new(asserter).with_outcome(Ok(receipt(true, &[event.encode_log_data()])));
    let response = settle(facilitator(Arc::new(provider)).as_ref(), &body(&payer));
    assert_eq!(response["success"], true);
    assert!(response.get("extra").is_none());
    assert!(
        response["errorMessage"]
            .as_str()
            .unwrap()
            .contains("snapshot unavailable")
    );
}
