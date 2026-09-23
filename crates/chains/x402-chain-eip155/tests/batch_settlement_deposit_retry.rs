//! The SDK retry of a deposit after `settlement_pending`, through the public
//! facilitator, against a recording mock RPC.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;

use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256, LogData, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolEvent, SolValue};
use alloy_transport::mock::Asserter;
use batch_settlement_common::rpc::{Request, Route, push_transport_failure, success};
use batch_settlement_common::*;
use serde_json::{Value, json};
use x402_chain_eip155::V2Eip155BatchSettlement;
use x402_chain_eip155::chain::MetaTransactionSendError;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::{
    Deposited, channelsCall, pendingWithdrawalsCall, refundNonceCall,
};
use x402_chain_eip155::v2_eip155_batch_settlement::{PaymentRequirements, U256String};
use x402_types::proto;
use x402_types::scheme::{X402SchemeFacilitator, X402SchemeFacilitatorBuilder};

const AUTHORIZER: Address = Address::repeat_byte(0x44);
/// The hash of the `receipt` fixture, so the broadcast and its receipt agree.
const TX: B256 = B256::repeat_byte(1);
const SIGNER: Address = Address::repeat_byte(0xfa);
const DEPOSIT_PAYLOAD: &str = "invalid_batch_settlement_evm_deposit_payload";
const TRANSACTION_FAILED: &str = "invalid_batch_settlement_evm_deposit_transaction_failed";
const SIMULATION_FAILED: &str = "invalid_batch_settlement_evm_deposit_simulation_failed";

/// A facilitator whose first deposit broadcast ended as `settlement_pending`.
struct AfterPending {
    asserter: Asserter,
    provider: Arc<MockProvider>,
    facilitator: Arc<dyn X402SchemeFacilitator>,
    payer: PrivateKeySigner,
    payload: Value,
}

impl AfterPending {
    fn new(route: Option<Route>) -> Self {
        let asserter = Asserter::new();
        push_deposit_reads(&asserter, 5_000);
        push_bytes(&asserter, Vec::new());
        push_bytes(&asserter, Vec::new());
        let pending = MetaTransactionSendError::Unconfirmed {
            tx_hash: TX,
            message: "timeout".into(),
        };
        let provider = MockProvider::routed(asserter.clone(), route).with_outcome(Err(pending));
        let provider = Arc::new(provider);
        let facilitator = V2Eip155BatchSettlement
            .build(provider.clone(), None)
            .unwrap();
        let payer = PrivateKeySigner::random();
        // One payload for every call: the fixture signs a fresh expiry each time.
        let payload = erc3009_deposit(&payer, AUTHORIZER);
        let this = Self {
            asserter,
            provider,
            facilitator: Arc::from(facilitator),
            payer,
            payload,
        };
        let first = this.settle(&this.body());
        assert_eq!(first["errorReason"], "settlement_pending", "{first}");
        assert_eq!(first["transaction"], format!("{TX:#x}"));
        this
    }

    fn body(&self) -> String {
        request(self.payload.clone(), &requirements(AUTHORIZER))
    }

    fn settle(&self, body: &str) -> Value {
        run(self.facilitator.settle(&settle_request(body)))
            .unwrap()
            .0
    }

    fn channel(&self) -> B256 {
        channel_id(&channel_config(
            self.payer.address(),
            self.payer.address(),
            AUTHORIZER,
        ))
    }

    fn deposited(&self) -> Deposited {
        Deposited {
            channelId: self.channel(),
            sender: SIGNER,
            amount: 1_000,
            newBalance: 1_000,
        }
    }

    /// Queues the mined receipt and the channel state at its block.
    fn queue_mined_deposit(&self) {
        let receipt = mined(true, &[self.deposited().encode_log_data()]);
        self.asserter.push_success(&receipt);
        push_channel_state(&self.asserter, 1_000, 0, 0);
    }

    fn receipt_reads(&self) -> usize {
        self.provider
            .requests_for("eth_getTransactionReceipt")
            .len()
    }
}

fn settle_request(body: &str) -> proto::SettleRequest {
    let raw = serde_json::value::RawValue::from_string(body.to_string()).unwrap();
    proto::SettleRequest::from(raw)
}

fn mined(status: bool, logs: &[LogData]) -> Value {
    serde_json::to_value(receipt(status, logs)).unwrap()
}

fn assert_pending(response: &Value) {
    assert_eq!(response["success"], false, "{response}");
    assert_eq!(response["errorReason"], "settlement_pending", "{response}");
    assert_eq!(response["transaction"], format!("{TX:#x}"));
}

#[test]
fn retry_reports_the_first_transaction_once_it_is_mined() {
    let retry = AfterPending::new(None);
    let calls_before = retry.provider.requests_for("eth_call").len();
    retry.queue_mined_deposit();

    let response = retry.settle(&retry.body());
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["transaction"], format!("{TX:#x}"));
    assert_eq!(response["amount"], "1000");
    assert_eq!(response["payer"], retry.payer.address().to_checksum(None));
    assert_eq!(response["extra"]["channelState"]["balance"], "1000");
    assert_eq!(retry.provider.sent().len(), 1, "no second broadcast");

    let reads = retry.provider.requests_for("eth_getTransactionReceipt");
    assert_eq!(reads.len(), 1);
    assert_eq!(reads[0].params[0], json!(TX));
    let calls = retry.provider.requests_for("eth_call");
    assert_eq!(
        calls.len(),
        calls_before + 3,
        "no simulation, only the state read"
    );
    let state_blocks: Vec<_> = calls[calls_before..].iter().map(Request::block).collect();
    assert_eq!(
        state_blocks,
        [Some("0x10"); 3],
        "state comes from the receipt block"
    );
}

#[test]
fn retry_before_the_receipt_stays_pending_with_the_first_hash() {
    let retry = AfterPending::new(None);
    retry.asserter.push_success(&Value::Null);
    assert_pending(&retry.settle(&retry.body()));

    retry.queue_mined_deposit();
    let later = retry.settle(&retry.body());
    assert_eq!(later["success"], true, "{later}");
    assert_eq!(retry.provider.sent().len(), 1);
}

#[test]
fn receipt_read_fault_stays_pending_with_the_first_hash() {
    let retry = AfterPending::new(None);
    retry.asserter.push_failure_msg("header not found");
    assert_pending(&retry.settle(&retry.body()));
    push_transport_failure(&retry.asserter, "https://rpc.example/secret-key");
    let response = retry.settle(&retry.body());
    assert_pending(&response);
    assert!(!response.to_string().contains("secret-key"));
    assert_eq!(retry.receipt_reads(), 2);
    assert_eq!(retry.provider.sent().len(), 1);
}

/// Only a revert leaves the authorization unspent. The next attempt runs
/// every deposit check again.
#[test]
fn mined_revert_stays_a_failure_with_its_hash() {
    let retry = AfterPending::new(None);
    retry.asserter.push_success(&mined(false, &[]));
    let response = retry.settle(&retry.body());
    assert_eq!(response["success"], false);
    assert_eq!(response["errorReason"], TRANSACTION_FAILED);
    assert_eq!(response["transaction"], format!("{TX:#x}"));
    assert!(response.get("extra").is_none());

    push_deposit_reads(&retry.asserter, 5_000);
    rpc::push_revert(&retry.asserter, &[]);
    let next = retry.settle(&retry.body());
    assert_eq!(next["errorReason"], SIMULATION_FAILED);
    assert_eq!(retry.receipt_reads(), 1);
    assert_eq!(retry.provider.sent().len(), 1);
}

type Change = fn(&mut Value, &mut PaymentRequirements);
type EventChange = fn(&mut Deposited);

/// Each change keeps the deposit authorization of the pending request.
fn changes() -> Vec<(&'static str, Change, &'static str)> {
    vec![
        (
            "voucher signature",
            |payload, _| payload["voucher"]["signature"] = json!(format!("0x{}", "1b".repeat(65))),
            DEPOSIT_PAYLOAD,
        ),
        (
            "voucher amount",
            |payload, _| payload["voucher"]["maxClaimableAmount"] = json!("200"),
            DEPOSIT_PAYLOAD,
        ),
        (
            "requirement amount",
            |_, requirements| requirements.amount = U256String(U256::from(5u64)),
            DEPOSIT_PAYLOAD,
        ),
        (
            "channel",
            |payload, _| payload["voucher"]["channelId"] = json!(B256::repeat_byte(0xcd)),
            "invalid_batch_settlement_evm_channel_id_mismatch",
        ),
        (
            "chain",
            |_, requirements| requirements.network = "eip155:10143".parse().unwrap(),
            "invalid_batch_settlement_evm_network_mismatch",
        ),
        (
            "requirement receiver",
            |_, requirements| requirements.pay_to = Address::repeat_byte(0x99).into(),
            "invalid_batch_settlement_evm_receiver_mismatch",
        ),
    ]
}

#[test]
fn changed_request_cannot_reuse_the_pending_deposit() {
    let retry = AfterPending::new(None);
    for (name, change, reason) in changes() {
        let mut payload = retry.payload.clone();
        let mut requirements = requirements(AUTHORIZER);
        change(&mut payload, &mut requirements);
        let response = retry.settle(&request(payload, &requirements));
        assert_eq!(response["success"], false, "{name}: {response}");
        assert_eq!(response["errorReason"], reason, "{name}: {response}");
        assert_eq!(response["transaction"], "", "{name}");
    }
    assert_eq!(retry.receipt_reads(), 0, "no receipt read");
    assert_eq!(retry.provider.sent().len(), 1, "no broadcast");

    retry.queue_mined_deposit();
    let original = retry.settle(&retry.body());
    assert_eq!(original["success"], true, "the record survives: {original}");
}

/// Answers the reconcile reads by method, so concurrent retries do not
/// depend on the order of a FIFO queue. With no receipt set, the queue
/// answers.
fn reconcile_route(receipt: Arc<Mutex<Option<Value>>>) -> Route {
    Arc::new(move |request: &Request| {
        let receipt = receipt.lock().unwrap().clone()?;
        if request.method == "eth_getTransactionReceipt" {
            return Some(success(&receipt));
        }
        let input = request.input();
        let selector = input.get(..4)?;
        let encoded = if selector == channelsCall::SELECTOR {
            (1_000u128, 0u128).abi_encode_params()
        } else if selector == pendingWithdrawalsCall::SELECTOR {
            (0u128, U256::ZERO).abi_encode_params()
        } else if selector == refundNonceCall::SELECTOR {
            U256::ZERO.abi_encode()
        } else {
            return None;
        };
        Some(success(alloy_primitives::Bytes::from(encoded)))
    })
}

#[test]
fn concurrent_retries_share_the_first_transaction() {
    let receipt = Arc::new(Mutex::new(None));
    let retry = AfterPending::new(Some(reconcile_route(receipt.clone())));
    *receipt.lock().unwrap() = Some(mined(true, &[retry.deposited().encode_log_data()]));
    let body = retry.body();
    let responses = run(async {
        let tasks: Vec<_> = (0..2)
            .map(|_| {
                let facilitator = retry.facilitator.clone();
                let body = body.clone();
                tokio::spawn(
                    async move { facilitator.settle(&settle_request(&body)).await.unwrap().0 },
                )
            })
            .collect();
        let mut responses = Vec::new();
        for task in tasks {
            responses.push(task.await.unwrap());
        }
        responses
    });
    for response in &responses {
        assert_eq!(response["success"], true, "{response}");
        assert_eq!(response["transaction"], format!("{TX:#x}"));
    }
    assert_eq!(retry.receipt_reads(), 2);
    assert_eq!(retry.provider.sent().len(), 1, "no retry broadcasts again");
}

fn assert_rejected_receipt(name: &str, retry: &AfterPending, receipt: &Value, reason: &str) {
    retry.asserter.push_success(receipt);
    let response = retry.settle(&retry.body());
    assert_eq!(response["success"], false, "{name}: {response}");
    assert_eq!(response["errorReason"], reason, "{name}: {response}");
    assert!(response.get("extra").is_none(), "{name}: {response}");
    assert_eq!(retry.provider.sent().len(), 1, "{name}");
}

/// A mined receipt without the recorded deposit's event is a mined failure.
#[test]
fn retry_binds_the_event_to_the_recorded_deposit() {
    let changes: [(&str, EventChange); 3] = [
        ("amount", |event| event.amount = 999),
        ("channel", |event| event.channelId = B256::ZERO),
        ("sender", |event| event.sender = Address::ZERO),
    ];
    for (name, change) in changes {
        let retry = AfterPending::new(None);
        let mut event = retry.deposited();
        change(&mut event);
        let receipt = mined(true, &[event.encode_log_data()]);
        assert_rejected_receipt(name, &retry, &receipt, TRANSACTION_FAILED);
    }
    let retry = AfterPending::new(None);
    let mut receipt = mined(true, &[retry.deposited().encode_log_data()]);
    receipt["logs"][0]["address"] = json!(Address::repeat_byte(9));
    assert_rejected_receipt("contract", &retry, &receipt, TRANSACTION_FAILED);
}

/// A receipt that is not the recorded transaction proves nothing.
#[test]
fn retry_rejects_a_receipt_of_another_transaction() {
    let other = json!(Address::repeat_byte(3));
    let changes = [
        ("/transactionHash", json!(B256::repeat_byte(2))),
        ("/from", other.clone()),
        ("/to", other),
    ];
    for (pointer, value) in changes {
        let retry = AfterPending::new(None);
        let mut receipt = mined(true, &[retry.deposited().encode_log_data()]);
        *receipt.pointer_mut(pointer).unwrap() = value;
        assert_rejected_receipt(pointer, &retry, &receipt, "settlement_pending");
    }
}

/// A send that fails before broadcast has no hash, so nothing is recorded and
/// the next attempt runs every check again.
#[test]
fn unsent_deposit_leaves_no_pending_state() {
    let asserter = Asserter::new();
    push_deposit_reads(&asserter, 5_000);
    push_bytes(&asserter, Vec::new());
    push_bytes(&asserter, Vec::new());
    let unsent = MetaTransactionSendError::Custom("nonce too low".into());
    let provider = Arc::new(MockProvider::new(asserter.clone()).with_outcome(Err(unsent)));
    let facilitator = V2Eip155BatchSettlement
        .build(provider.clone(), None)
        .unwrap();
    let payer = PrivateKeySigner::random();
    let body = request(
        erc3009_deposit(&payer, AUTHORIZER),
        &requirements(AUTHORIZER),
    );

    let first = run(facilitator.settle(&settle_request(&body))).unwrap().0;
    assert_eq!(first["errorReason"], TRANSACTION_FAILED, "{first}");
    assert_eq!(first["transaction"], "");

    push_deposit_reads(&asserter, 5_000);
    rpc::push_revert(&asserter, &[]);
    let second = run(facilitator.settle(&settle_request(&body))).unwrap().0;
    assert_eq!(second["errorReason"], SIMULATION_FAILED, "{second}");
    assert!(
        provider
            .requests_for("eth_getTransactionReceipt")
            .is_empty()
    );
    assert_eq!(provider.sent().len(), 1);
}
