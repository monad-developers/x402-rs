//! Idempotent claim and settle, and the bounded claim read.
//!
//! The SDK channel managers record claimed totals and clear their pending
//! settle only on `success: true`. A retry after a lost update must therefore
//! succeed when the chain already holds the goal state.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes, U128};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolError, SolEvent, SolValue};
use alloy_transport::mock::Asserter;
use batch_settlement_common::*;
use serde_json::{Value, json};
use x402_chain_eip155::V2Eip155BatchSettlement;
use x402_chain_eip155::v2_eip155_batch_settlement::constants::BATCH_SETTLEMENT_ADDRESS;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::{
    InvalidSignature, Settled, channelsCall, claimWithSignatureCall, multicallCall,
};
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::{
    compute_claim_batch_digest, compute_voucher_digest,
};
use x402_chain_eip155::v2_eip155_batch_settlement::{
    ChannelConfig, U128String, VoucherClaim, VoucherClaimVoucher,
};
use x402_types::proto;
use x402_types::scheme::X402SchemeFacilitatorBuilder;

fn settle(provider: Arc<MockProvider>, body: String) -> Value {
    let facilitator = V2Eip155BatchSettlement.build(provider, None).unwrap();
    let raw = serde_json::value::RawValue::from_string(body).unwrap();
    run(facilitator.settle(&proto::SettleRequest::from(raw)))
        .unwrap()
        .0
}

fn config(payer: &PrivateKeySigner, authorizer: Address, salt: u8) -> ChannelConfig {
    ChannelConfig {
        salt: B256::with_last_byte(salt),
        ..channel_config(Address::repeat_byte(0x11), payer.address(), authorizer)
    }
}

fn row(payer: &PrivateKeySigner, config: ChannelConfig, total: u128) -> VoucherClaim {
    let digest = compute_voucher_digest(channel_id(&config), U128::from(total), CHAIN_ID);
    VoucherClaim {
        voucher: VoucherClaimVoucher {
            channel: config,
            max_claimable_amount: U128String(U128::from(total)),
        },
        signature: sign(payer, digest),
        total_claimed: U128String(U128::from(total)),
    }
}

fn claim_body(signer: &PrivateKeySigner, authorizer: Address, claims: &[VoucherClaim]) -> String {
    let digest = compute_claim_batch_digest(claims, CHAIN_ID);
    let payload = json!({
        "type": "claim",
        "claims": claims,
        "claimAuthorizerSignature": sign(signer, digest),
    });
    request(payload, &requirements(authorizer))
}

struct Batch {
    authorizer: PrivateKeySigner,
    claims: Vec<VoucherClaim>,
}

/// One row that claims 500 on a fresh channel.
fn single_row() -> Batch {
    let authorizer = PrivateKeySigner::random();
    let payer = PrivateKeySigner::random();
    let claims = vec![row(&payer, config(&payer, authorizer.address(), 1), 500)];
    Batch { authorizer, claims }
}

fn body(batch: &Batch) -> String {
    claim_body(&batch.authorizer, batch.authorizer.address(), &batch.claims)
}

/// After a lost update, the SDK sends rows that the chain already holds. The
/// canonical call at the read block checks the authorizer signature, and
/// nothing is broadcast.
#[test]
fn an_already_claimed_batch_succeeds_without_a_broadcast() {
    let batch = single_row();
    let asserter = Asserter::new();
    no_code(&asserter);
    push_claim_totals(&asserter, "0x2a", &[(1_000, 500)]);
    push_bytes(&asserter, Vec::new());
    let provider = Arc::new(MockProvider::new(asserter));
    let response = settle(provider.clone(), body(&batch));
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["transaction"], "");
    assert_eq!(response["amount"], "");
    assert!(provider.sent().is_empty());

    let check = provider.requests_for("eth_call").pop().unwrap();
    assert_eq!(check.to(), Some(BATCH_SETTLEMENT_ADDRESS));
    assert_eq!(check.from(), Some(provider.signer()));
    assert_eq!(check.block(), Some("0x2a"));
    let call = claimWithSignatureCall::abi_decode(&check.input()).unwrap();
    assert_eq!(call.voucherClaims.len(), 1);
    let digest = compute_claim_batch_digest(&batch.claims, CHAIN_ID);
    assert_eq!(call.authorizerSignature, sign(&batch.authorizer, digest));
}

/// The contract rejects the signature at the read block: no success.
#[test]
fn an_already_claimed_batch_that_the_contract_rejects_is_a_failure() {
    let batch = single_row();
    let asserter = Asserter::new();
    no_code(&asserter);
    push_claim_totals(&asserter, "0x2a", &[(1_000, 500)]);
    rpc::push_revert(&asserter, &InvalidSignature::SELECTOR);
    let provider = Arc::new(MockProvider::new(asserter));
    let response = settle(provider.clone(), body(&batch));
    assert_eq!(response["success"], false);
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_claim_simulation_failed"
    );
    assert!(provider.sent().is_empty());
}

/// A replayed body signed by another key is not merchant consent.
#[test]
fn an_already_claimed_batch_with_a_forged_signature_is_rejected() {
    let batch = single_row();
    let forger = PrivateKeySigner::random();
    let asserter = Asserter::new();
    no_code(&asserter);
    let provider = Arc::new(MockProvider::new(asserter));
    let forged = claim_body(&forger, batch.authorizer.address(), &batch.claims);
    let response = settle(provider.clone(), forged);
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_authorizer_address_mismatch"
    );
    assert_eq!(provider.requests().len(), 1, "only the code read");
    assert!(provider.sent().is_empty());
}

#[test]
fn an_empty_claim_batch_is_rejected() {
    let batch = Batch {
        claims: Vec::new(),
        ..single_row()
    };
    let provider = Arc::new(MockProvider::new(Asserter::new()));
    let response = settle(provider.clone(), body(&batch));
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_claim_payload"
    );
    assert!(provider.requests().is_empty());
}

fn fresh_claim(outcome: bool) -> (Value, Arc<MockProvider>) {
    let batch = single_row();
    let asserter = Asserter::new();
    no_code(&asserter);
    push_claim_totals(&asserter, "0x10", &[(1_000, 100)]);
    push_bytes(&asserter, Vec::new());
    let provider = MockProvider::new(asserter).with_outcome(Ok(receipt(outcome, &[])));
    let provider = Arc::new(provider);
    (settle(provider.clone(), body(&batch)), provider)
}

/// Another claim reached the totals first, so this one mined with no event.
#[test]
fn a_claim_that_mines_without_a_claimed_event_is_a_success() {
    let (response, provider) = fresh_claim(true);
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(
        response["transaction"],
        format!("{:#x}", B256::repeat_byte(1))
    );
    assert_eq!(provider.sent().len(), 1);
}

#[test]
fn a_claim_that_mines_and_reverts_is_a_failure() {
    let (response, _) = fresh_claim(false);
    assert_eq!(response["success"], false);
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_claim_transaction_failed"
    );
}

/// A multicall result with the wrong number of entries is not a state read.
#[test]
fn a_short_channel_read_is_a_failure() {
    let authorizer = PrivateKeySigner::random();
    let payer = PrivateKeySigner::random();
    let claims = [1, 2].map(|salt| row(&payer, config(&payer, authorizer.address(), salt), 500));
    let asserter = Asserter::new();
    no_code(&asserter);
    push_claim_totals(&asserter, "0x10", &[(1_000, 0)]);
    let provider = Arc::new(MockProvider::new(asserter));
    let response = settle(
        provider.clone(),
        claim_body(&authorizer, authorizer.address(), &claims),
    );
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_channel_state_read_failed"
    );
    assert!(provider.sent().is_empty());
}

/// 100 channels plus one repeated row. Only row 57 is new: every other channel
/// holds `(500, 500)`, so a result mapped to the wrong channel puts 800 above a
/// balance of 500 and fails. The read cost does not depend on the row count.
#[test]
fn a_claim_of_100_channels_reads_every_total_in_one_call() {
    let authorizer = PrivateKeySigner::random();
    let payer = PrivateKeySigner::random();
    let mut claims: Vec<_> = (0..100u8)
        .map(|salt| {
            let total = if salt == 57 { 800 } else { 500 };
            row(&payer, config(&payer, authorizer.address(), salt), total)
        })
        .collect();
    claims.push(claims[3].clone());
    let totals: Vec<_> = (0..100)
        .map(|salt| if salt == 57 { (1_000, 0) } else { (500, 500) })
        .collect();
    let asserter = Asserter::new();
    no_code(&asserter);
    push_claim_totals(&asserter, "0x10", &totals);
    push_bytes(&asserter, Vec::new());
    let provider = MockProvider::new(asserter).with_outcome(Ok(receipt(true, &[])));
    let provider = Arc::new(provider);
    let body = claim_body(&authorizer, authorizer.address(), &claims);
    let response = settle(provider.clone(), body);
    assert_eq!(response["success"], true, "{response}");

    let methods: Vec<_> = provider.requests().into_iter().map(|r| r.method).collect();
    let expected = ["eth_getCode", "eth_blockNumber", "eth_call", "eth_call"];
    assert_eq!(methods, expected);
    let read = &provider.requests_for("eth_call")[0];
    assert_eq!(read.to(), Some(BATCH_SETTLEMENT_ADDRESS));
    assert_eq!(read.block(), Some("0x10"));
    let reads = multicallCall::abi_decode(&read.input()).unwrap().data;
    let ids: Vec<Bytes> = claims[..100]
        .iter()
        .map(|claim| {
            let channel_id = channel_id(&claim.voucher.channel);
            channelsCall {
                channelId: channel_id,
            }
            .abi_encode()
            .into()
        })
        .collect();
    assert_eq!(reads, ids);
    let sent = claimWithSignatureCall::abi_decode(&provider.sent()[0].calldata).unwrap();
    assert_eq!(sent.voucherClaims.len(), 101);
}

fn settle_body() -> String {
    let payload = json!({ "type": "settle", "receiver": RECEIVER, "token": TOKEN });
    request(payload, &requirements(Address::repeat_byte(0x44)))
}

/// An earlier settle already swept the funds. The SDK clears its pending
/// settle on this success.
#[test]
fn a_settle_with_nothing_owed_succeeds_without_a_broadcast() {
    let asserter = Asserter::new();
    asserter.push_success(&"0x10");
    push_bytes(&asserter, (500u128, 500u128).abi_encode_params());
    let provider = Arc::new(MockProvider::new(asserter));
    let response = settle(provider.clone(), settle_body());
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["transaction"], "");
    assert_eq!(response["amount"], "0");
    assert!(provider.requests_for("eth_estimateGas").is_empty());
    assert!(provider.sent().is_empty());
}

fn owed_settle(logs: &[alloy_primitives::LogData]) -> Value {
    let asserter = Asserter::new();
    asserter.push_success(&"0x10");
    push_bytes(&asserter, (900u128, 400u128).abi_encode_params());
    asserter.push_success(&"0x1ebbc");
    push_bytes(&asserter, Vec::new());
    let provider = MockProvider::new(asserter).with_outcome(Ok(receipt(true, logs)));
    settle(Arc::new(provider), settle_body())
}

/// A permissionless settle by another party landed first.
#[test]
fn a_settle_that_mines_without_a_settled_event_is_a_success_of_zero() {
    let response = owed_settle(&[]);
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["amount"], "0");
    assert_eq!(
        response["transaction"],
        format!("{:#x}", B256::repeat_byte(1))
    );
}

/// An event for another receiver is not this settle's transfer.
#[test]
fn a_settled_event_for_another_receiver_counts_as_zero() {
    let event = Settled {
        receiver: Address::repeat_byte(0x99),
        token: TOKEN,
        sender: Address::repeat_byte(0xfa),
        amount: 500,
    };
    let response = owed_settle(&[event.encode_log_data()]);
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["amount"], "0");
}
