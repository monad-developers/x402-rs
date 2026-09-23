//! Request bodies in the shape the official SDK servers send.
//!
//! `BatchSettlementChannelManager` (`@x402/evm` 2.22.0 and 2.27.0
//! `buildPaymentRequirements`, Go `requirementsMap`) sends the same
//! placeholder requirements as `accepted` and `paymentRequirements` for claim,
//! settle, and refund: `amount: "0"`, `maxTimeoutSeconds: 0`, `extra: {}`.
//! `HTTPFacilitatorClient.settle` wraps them with `x402Version: 2`. The signed
//! payload carries the merchant consent, so these bodies must reach the scheme
//! checks. `/verify` and deposits still need the published authorizer.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;

use std::sync::Arc;

use alloy_primitives::{Address, B256, U128, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolEvent, SolValue};
use alloy_transport::mock::Asserter;
use batch_settlement_common::*;
use serde_json::{Value, json};
use x402_chain_eip155::V2Eip155BatchSettlement;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::{
    Claimed, Refunded, Settled,
};
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::{
    compute_claim_batch_digest, compute_refund_digest, compute_voucher_digest,
};
use x402_chain_eip155::v2_eip155_batch_settlement::{
    BatchSettlementPaymentRequirementsExtra, ChannelConfig, U128String, VoucherClaim,
    VoucherClaimVoucher,
};
use x402_types::proto;
use x402_types::scheme::{X402SchemeFacilitator, X402SchemeFacilitatorBuilder};

fn facilitator(provider: Arc<MockProvider>) -> Box<dyn X402SchemeFacilitator> {
    V2Eip155BatchSettlement.build(provider, None).unwrap()
}

fn settle(provider: Arc<MockProvider>, body: String) -> Value {
    let raw = serde_json::value::RawValue::from_string(body).unwrap();
    run(facilitator(provider).settle(&proto::SettleRequest::from(raw)))
        .unwrap()
        .0
}

fn verify(provider: Arc<MockProvider>, body: String) -> Value {
    let raw = serde_json::value::RawValue::from_string(body).unwrap();
    run(facilitator(provider).verify(&proto::VerifyRequest::from(raw)))
        .unwrap()
        .0
}

/// The body `HTTPFacilitatorClient.settle` posts for a channel-manager call.
fn manager_body(payload: Value) -> String {
    let requirements = json!({
        "scheme": "batch-settlement",
        "network": NETWORK,
        "asset": TOKEN,
        "amount": "0",
        "payTo": RECEIVER,
        "maxTimeoutSeconds": 0,
        "extra": {},
    });
    json!({
        "x402Version": 2,
        "paymentPayload": { "x402Version": 2, "accepted": requirements, "payload": payload },
        "paymentRequirements": requirements,
    })
    .to_string()
}

struct Channel {
    payer: PrivateKeySigner,
    authorizer: PrivateKeySigner,
    config: ChannelConfig,
}

/// A channel as the SDK client builds it: `payerAuthorizer` is the payer.
fn channel() -> Channel {
    let payer = PrivateKeySigner::random();
    let authorizer = PrivateKeySigner::random();
    let config = channel_config(payer.address(), payer.address(), authorizer.address());
    Channel {
        payer,
        authorizer,
        config,
    }
}

impl Channel {
    fn id(&self) -> B256 {
        channel_id(&self.config)
    }

    fn voucher(&self, max_claimable: u128) -> Value {
        let digest = compute_voucher_digest(self.id(), U128::from(max_claimable), CHAIN_ID);
        json!({
            "channelId": self.id(),
            "maxClaimableAmount": max_claimable.to_string(),
            "signature": sign(&self.payer, digest),
        })
    }

    /// `submitClaim`: one row per claimable channel and the batch signature.
    fn claim_payload(&self) -> Value {
        let digest = compute_voucher_digest(self.id(), U128::from(500u128), CHAIN_ID);
        let claims = vec![VoucherClaim {
            voucher: VoucherClaimVoucher {
                channel: self.config.clone(),
                max_claimable_amount: U128String(U128::from(500u128)),
            },
            signature: sign(&self.payer, digest),
            total_claimed: U128String(U128::from(500u128)),
        }];
        let batch = compute_claim_batch_digest(&claims, CHAIN_ID);
        json!({
            "type": "claim",
            "claims": claims,
            "claimAuthorizerSignature": sign(&self.authorizer, batch),
        })
    }

    /// `refundChannel` with nothing left to claim: `claims: []`.
    fn refund_payload(&self, signer: &PrivateKeySigner) -> Value {
        let digest = compute_refund_digest(self.id(), U256::ZERO, U128::from(500u128), CHAIN_ID);
        json!({
            "type": "refund",
            "channelConfig": self.config,
            "voucher": self.voucher(500),
            "amount": "500",
            "refundNonce": "0",
            "claims": [],
            "refundAuthorizerSignature": sign(signer, digest),
        })
    }
}

#[test]
fn a_manager_claim_with_empty_extra_is_claimed() {
    let channel = channel();
    let asserter = Asserter::new();
    no_code(&asserter);
    push_claim_totals(&asserter, "0x10", &[(1_000, 100)]);
    push_bytes(&asserter, Vec::new());
    let event = Claimed {
        channelId: channel.id(),
        sender: Address::repeat_byte(0xfa),
        claimAmount: 400,
        newTotalClaimed: 500,
    };
    let receipt = receipt(true, &[event.encode_log_data()]);
    let provider = Arc::new(MockProvider::new(asserter).with_outcome(Ok(receipt)));
    let response = settle(provider.clone(), manager_body(channel.claim_payload()));
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(provider.sent().len(), 1);
}

#[test]
fn a_manager_settle_with_empty_extra_is_settled() {
    let asserter = Asserter::new();
    asserter.push_success(&"0x10");
    push_bytes(&asserter, (900u128, 400u128).abi_encode_params());
    asserter.push_success(&"0x1ebbc");
    push_bytes(&asserter, Vec::new());
    let event = Settled {
        receiver: RECEIVER,
        token: TOKEN,
        sender: Address::repeat_byte(0xfa),
        amount: 500,
    };
    let receipt = receipt(true, &[event.encode_log_data()]);
    let provider = Arc::new(MockProvider::new(asserter).with_outcome(Ok(receipt)));
    let payload = json!({ "type": "settle", "receiver": RECEIVER, "token": TOKEN });
    let response = settle(provider.clone(), manager_body(payload));
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["amount"], "500");
}

#[test]
fn a_manager_refund_with_empty_extra_is_refunded() {
    let channel = channel();
    let asserter = Asserter::new();
    push_channel_state(&asserter, 1_000, 500, 0);
    no_code(&asserter);
    push_bytes(&asserter, Vec::new());
    push_channel_state(&asserter, 500, 500, 1);
    let event = Refunded {
        channelId: channel.id(),
        sender: Address::repeat_byte(0xfa),
        amount: 500,
    };
    let receipt = receipt(true, &[event.encode_log_data()]);
    let provider = Arc::new(MockProvider::new(asserter).with_outcome(Ok(receipt)));
    let payload = channel.refund_payload(&channel.authorizer);
    let response = settle(provider.clone(), manager_body(payload));
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["amount"], "500");
    assert_eq!(response["extra"]["channelState"]["refundNonce"], "1");
}

/// The refund voucher must name the channel of `channelConfig`.
#[test]
fn a_refund_bound_to_another_channel_id_is_rejected() {
    let channel = channel();
    let mut payload = channel.refund_payload(&channel.authorizer);
    payload["voucher"]["channelId"] = json!(B256::repeat_byte(0x77));
    let provider = Arc::new(MockProvider::new(Asserter::new()));
    let response = settle(provider.clone(), manager_body(payload));
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_channel_id_mismatch"
    );
    assert!(provider.requests().is_empty());
}

/// Placeholder requirements do not relax the refund signature check.
#[test]
fn a_refund_signed_by_another_key_is_rejected() {
    let channel = channel();
    let payload = channel.refund_payload(&PrivateKeySigner::random());
    let asserter = Asserter::new();
    push_channel_state(&asserter, 1_000, 500, 0);
    no_code(&asserter);
    let provider = Arc::new(MockProvider::new(asserter));
    let response = settle(provider.clone(), manager_body(payload));
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_authorizer_address_mismatch"
    );
    assert!(provider.sent().is_empty());
}

fn with_extra(payload: Value, extra: BatchSettlementPaymentRequirementsExtra) -> String {
    let mut requirements = requirements(Address::ZERO);
    requirements.extra = extra;
    request(payload, &requirements)
}

fn published(channel: &Channel) -> BatchSettlementPaymentRequirementsExtra {
    BatchSettlementPaymentRequirementsExtra {
        receiver_authorizer: Some(channel.authorizer.address().into()),
        ..Default::default()
    }
}

/// With no published authorizer, nothing shows merchant consent to the
/// channel. The request fails before any RPC call.
#[test]
fn a_voucher_or_deposit_without_a_published_authorizer_fails_closed() {
    let channel = channel();
    let voucher = json!({
        "type": "voucher",
        "channelConfig": channel.config,
        "voucher": channel.voucher(100),
    });
    let deposit = erc3009_deposit(&channel.payer, channel.authorizer.address());
    for payload in [voucher, deposit.clone()] {
        let provider = Arc::new(MockProvider::new(Asserter::new()));
        let response = verify(provider.clone(), with_extra(payload, Default::default()));
        assert_eq!(response["isValid"], false);
        assert_eq!(
            response["invalidReason"],
            "invalid_batch_settlement_evm_receiver_authorizer_mismatch"
        );
        assert!(provider.requests().is_empty());
    }
    let provider = Arc::new(MockProvider::new(Asserter::new()));
    let response = settle(provider.clone(), with_extra(deposit, Default::default()));
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_receiver_authorizer_mismatch"
    );
    assert!(provider.requests().is_empty());
    assert!(provider.sent().is_empty());
}

/// `withdrawDelay` is compared only when the server publishes it.
#[test]
fn a_voucher_verify_compares_withdraw_delay_only_when_present() {
    let channel = channel();
    let payload = json!({
        "type": "voucher",
        "channelConfig": channel.config,
        "voucher": channel.voucher(100),
    });
    let asserter = Asserter::new();
    push_channel_state(&asserter, 1_000, 0, 0);
    let provider = Arc::new(MockProvider::new(asserter));
    let response = verify(provider, with_extra(payload.clone(), published(&channel)));
    assert_eq!(response["isValid"], true, "{response}");

    let extra = BatchSettlementPaymentRequirementsExtra {
        withdraw_delay: Some(1_800),
        ..published(&channel)
    };
    let provider = Arc::new(MockProvider::new(Asserter::new()));
    let response = verify(provider, with_extra(payload, extra));
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_withdraw_delay_mismatch"
    );
}
