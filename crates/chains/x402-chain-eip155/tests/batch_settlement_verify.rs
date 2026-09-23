//! `/verify` and `/supported` through the public facilitator, against a mock RPC.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;

use std::sync::Arc;

use alloy_primitives::{Address, B256, U128};
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::mock::Asserter;
use batch_settlement_common::*;
use serde_json::{Value, json};
use x402_chain_eip155::V2Eip155BatchSettlement;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::compute_voucher_digest;
use x402_types::proto;
use x402_types::scheme::{X402SchemeFacilitator, X402SchemeFacilitatorBuilder};

/// Stands in for transport text; a real one can hold an RPC URL and its key.
const TRANSPORT_MARKER: &str = "transport-detail-marker";

fn facilitator(asserter: Asserter) -> Box<dyn X402SchemeFacilitator> {
    V2Eip155BatchSettlement
        .build(MockProvider::new(asserter), None)
        .unwrap()
}

fn verify(asserter: Asserter, body: String) -> Value {
    verify_with(Arc::new(MockProvider::new(asserter)), body)
}

fn verify_with(provider: Arc<MockProvider>, body: String) -> Value {
    let request =
        proto::VerifyRequest::from(serde_json::value::RawValue::from_string(body).unwrap());
    let facilitator = V2Eip155BatchSettlement.build(provider, None).unwrap();
    run(facilitator.verify(&request)).unwrap().0
}

fn voucher_payload(kind: &str, payer_key: &PrivateKeySigner, max_claimable: u128) -> Value {
    let authorizer = Address::repeat_byte(0x44);
    let config = channel_config(Address::repeat_byte(0x11), payer_key.address(), authorizer);
    let id = channel_id(&config);
    let digest = compute_voucher_digest(id, U128::from(max_claimable), CHAIN_ID);
    json!({
        "type": kind,
        "channelConfig": config,
        "voucher": {
            "channelId": id,
            "maxClaimableAmount": max_claimable.to_string(),
            "signature": sign(payer_key, digest),
        },
    })
}

/// A nonzero `payerAuthorizer` is strict ECDSA even when that address has
/// code, so the facilitator never reads its code or calls it.
#[test]
fn valid_voucher_returns_the_onchain_snapshot() {
    let key = PrivateKeySigner::random();
    let asserter = Asserter::new();
    push_channel_state(&asserter, 1_000, 200, 3);
    let body = request(
        voucher_payload("voucher", &key, 300),
        &requirements(Address::repeat_byte(0x44)),
    );
    let provider = Arc::new(MockProvider::new(asserter));
    let response = verify_with(provider.clone(), body);
    let methods: Vec<_> = provider.requests().into_iter().map(|r| r.method).collect();
    assert_eq!(methods, ["eth_call", "eth_call", "eth_call"]);
    assert_eq!(response["isValid"], true, "{response}");
    assert_eq!(response["extra"]["balance"], "1000");
    assert_eq!(response["extra"]["totalClaimed"], "200");
    assert_eq!(response["extra"]["refundNonce"], "3");
    assert_eq!(response["extra"]["withdrawRequestedAt"], 0);
}

/// A strict-ECDSA voucher never reaches the RPC when its signature is wrong.
#[test]
fn voucher_signed_by_another_key_is_rejected_before_any_read() {
    let key = PrivateKeySigner::random();
    let mut payload = voucher_payload("voucher", &key, 300);
    let other = PrivateKeySigner::random();
    payload["voucher"]["signature"] = json!(sign(&other, B256::repeat_byte(1)));
    let response = verify(
        Asserter::new(),
        request(payload, &requirements(Address::repeat_byte(0x44))),
    );
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_voucher_signature"
    );
}

#[test]
fn voucher_on_an_unfunded_channel_is_not_found() {
    let key = PrivateKeySigner::random();
    let asserter = Asserter::new();
    push_channel_state(&asserter, 0, 0, 0);
    let body = request(
        voucher_payload("voucher", &key, 1),
        &requirements(Address::repeat_byte(0x44)),
    );
    let response = verify(asserter, body);
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_channel_not_found"
    );
}

#[test]
fn refund_voucher_may_equal_the_claimed_total() {
    let key = PrivateKeySigner::random();
    let asserter = Asserter::new();
    push_channel_state(&asserter, 1_000, 300, 0);
    let body = request(
        voucher_payload("refund", &key, 300),
        &requirements(Address::repeat_byte(0x44)),
    );
    assert_eq!(verify(asserter, body)["isValid"], true);
}

#[test]
fn requirements_for_another_chain_are_rejected() {
    let key = PrivateKeySigner::random();
    let mut requirements = requirements(Address::repeat_byte(0x44));
    requirements.network = "eip155:10143".parse().unwrap();
    let response = verify(
        Asserter::new(),
        request(voucher_payload("voucher", &key, 1), &requirements),
    );
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_network_mismatch"
    );
}

#[test]
fn settle_only_payload_is_not_verifiable() {
    let payload = json!({ "type": "settle", "receiver": RECEIVER, "token": TOKEN });
    let response = verify(
        Asserter::new(),
        request(payload, &requirements(Address::repeat_byte(0x44))),
    );
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_payload_type"
    );
}

#[test]
fn erc3009_deposit_is_simulated_and_reports_pre_deposit_state() {
    let payer = PrivateKeySigner::random();
    let authorizer = Address::repeat_byte(0x44);
    let asserter = Asserter::new();
    push_deposit_reads(&asserter, 5_000);
    push_bytes(&asserter, Vec::new());
    let body = request(
        erc3009_deposit(&payer, authorizer),
        &requirements(authorizer),
    );
    let provider = Arc::new(MockProvider::new(asserter));
    let response = verify_with(provider.clone(), body);
    assert_eq!(response["isValid"], true, "{response}");
    assert_eq!(response["extra"]["balance"], "0");
    // The deposit simulation sets no gas, so the node uses its call gas cap.
    assert_eq!(provider.requests_for("eth_call").pop().unwrap().gas(), None);
}

/// The deposit simulation reaches the client. Transport text can carry the
/// RPC URL, so it never does; an EVM revert keeps its detail.
#[test]
fn deposit_simulation_errors_never_carry_transport_text() {
    let payer = PrivateKeySigner::random();
    let authorizer = Address::repeat_byte(0x44);
    let body = request(
        erc3009_deposit(&payer, authorizer),
        &requirements(authorizer),
    );
    let asserter = Asserter::new();
    push_deposit_reads(&asserter, 5_000);
    rpc::push_transport_failure(&asserter, TRANSPORT_MARKER);
    let response = verify(asserter, body.clone());
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_deposit_simulation_failed"
    );
    assert_eq!(response["invalidMessage"], "RPC request failed");

    let asserter = Asserter::new();
    push_deposit_reads(&asserter, 5_000);
    rpc::push_revert(&asserter, &[0xde, 0xad]);
    let response = verify(asserter, body);
    assert_eq!(response["invalidMessage"], "execution reverted: 0xdead");
}

#[test]
fn deposit_larger_than_the_payer_balance_is_rejected() {
    let payer = PrivateKeySigner::random();
    let authorizer = Address::repeat_byte(0x44);
    let asserter = Asserter::new();
    push_deposit_reads(&asserter, 999);
    let body = request(
        erc3009_deposit(&payer, authorizer),
        &requirements(authorizer),
    );
    let response = verify(asserter, body);
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_insufficient_balance"
    );
}

#[test]
fn supported_advertises_no_receiver_authorizer() {
    let supported = run(facilitator(Asserter::new()).supported()).unwrap();
    let kind = &supported.kinds[0];
    assert_eq!(kind.scheme, "batch-settlement");
    assert_eq!(kind.network, NETWORK);
    assert!(kind.extra.is_none());
    assert!(supported.extensions.is_empty());
    assert_eq!(supported.signers.len(), 1);
}

/// No key or reserved flag is accepted, so a stale authorizer key fails loudly.
#[test]
fn builder_rejects_any_configuration_key() {
    for config in [
        json!({ "receiverAuthorizerPrivateKey": "0x01" }),
        json!({ "eip2612GasSponsoring": false }),
    ] {
        let result =
            V2Eip155BatchSettlement.build(MockProvider::new(Asserter::new()), Some(config));
        assert!(result.is_err());
    }
    for config in [None, Some(json!({})), Some(Value::Null)] {
        assert!(
            V2Eip155BatchSettlement
                .build(MockProvider::new(Asserter::new()), config)
                .is_ok()
        );
    }
}

fn zero_authorizer_voucher(payer: Address, signer: &PrivateKeySigner) -> Value {
    let config = channel_config(payer, Address::ZERO, Address::repeat_byte(0x44));
    let id = channel_id(&config);
    let signature = sign(
        signer,
        compute_voucher_digest(id, U128::from(300u128), CHAIN_ID),
    );
    json!({
        "type": "voucher",
        "channelConfig": config,
        "voucher": { "channelId": id, "maxClaimableAmount": "300", "signature": signature },
    })
}

/// Zero `payerAuthorizer` and an EOA payer: `SignatureChecker` takes its ECDSA
/// branch against the payer, not against any authorizer.
#[test]
fn zero_payer_authorizer_with_an_eoa_payer_uses_ecdsa_against_the_payer() {
    let payer = PrivateKeySigner::random();
    let asserter = Asserter::new();
    no_code(&asserter);
    push_channel_state(&asserter, 1_000, 0, 0);
    let body = request(
        zero_authorizer_voucher(payer.address(), &payer),
        &requirements(Address::repeat_byte(0x44)),
    );
    assert_eq!(verify(asserter, body)["isValid"], true);

    let asserter = Asserter::new();
    no_code(&asserter);
    let other = PrivateKeySigner::random();
    let body = request(
        zero_authorizer_voucher(payer.address(), &other),
        &requirements(Address::repeat_byte(0x44)),
    );
    let response = verify(asserter, body);
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_voucher_signature"
    );
}
