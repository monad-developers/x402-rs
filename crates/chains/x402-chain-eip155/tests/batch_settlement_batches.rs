//! Claim-batch semantics: rows across receivers and tokens, stale rows, and
//! refund multicalls that carry claims for other channels.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;

use std::sync::Arc;

use alloy_primitives::{Address, Bytes, U128, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolEvent};
use alloy_transport::mock::Asserter;
use batch_settlement_common::*;
use serde_json::{Value, json};
use x402_chain_eip155::V2Eip155BatchSettlement;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::{
    Claimed, Refunded, claimWithSignatureCall, multicallCall, refundWithSignatureCall,
};
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::{
    compute_claim_batch_digest, compute_refund_digest, compute_voucher_digest,
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

fn config(authorizer: Address, receiver: u8, token: u8) -> ChannelConfig {
    ChannelConfig {
        receiver: Address::repeat_byte(receiver).into(),
        token: Address::repeat_byte(token).into(),
        ..channel_config(
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x12),
            authorizer,
        )
    }
}

fn row(payer: &PrivateKeySigner, config: ChannelConfig, total: u128) -> VoucherClaim {
    let config = ChannelConfig {
        payer_authorizer: payer.address().into(),
        ..config
    };
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

fn claim_body(authorizer: &PrivateKeySigner, claims: &[VoucherClaim]) -> String {
    let digest = compute_claim_batch_digest(claims, CHAIN_ID);
    let payload = json!({
        "type": "claim",
        "claims": claims,
        "claimAuthorizerSignature": sign(authorizer, digest),
    });
    request(payload, &requirements(authorizer.address()))
}

fn claimed(config: &ChannelConfig, total: u128) -> alloy_primitives::LogData {
    Claimed {
        channelId: channel_id(config),
        sender: Address::repeat_byte(0xfa),
        claimAmount: total,
        newTotalClaimed: total,
    }
    .encode_log_data()
}

/// Rows for different receivers and tokens share one authorizer, which is all
/// the contract requires. Nothing binds them to the request's `payTo`.
#[test]
fn batch_across_receivers_and_tokens_is_submitted_whole() {
    let authorizer = PrivateKeySigner::random();
    let payer = PrivateKeySigner::random();
    let first = row(&payer, config(authorizer.address(), 0x31, 0x51), 300);
    let second = row(&payer, config(authorizer.address(), 0x32, 0x52), 400);
    let asserter = Asserter::new();
    no_code(&asserter);
    push_claim_totals(&asserter, "0x10", &[(1_000, 0), (1_000, 0)]);
    push_bytes(&asserter, Vec::new());
    let logs = [
        claimed(&first.voucher.channel, 300),
        claimed(&second.voucher.channel, 400),
    ];
    let provider = Arc::new(MockProvider::new(asserter).with_outcome(Ok(receipt(true, &logs))));
    let response = settle(provider.clone(), claim_body(&authorizer, &[first, second]));
    assert_eq!(response["success"], true, "{response}");
    let sent = claimWithSignatureCall::abi_decode(&provider.sent()[0].calldata).unwrap();
    assert_eq!(sent.voucherClaims.len(), 2);
}

/// A stale row next to a new one stays in the batch; the contract skips it.
#[test]
fn stale_row_does_not_block_a_new_row() {
    let authorizer = PrivateKeySigner::random();
    let payer = PrivateKeySigner::random();
    let stale = row(&payer, config(authorizer.address(), 0x31, 0x51), 300);
    let fresh = row(&payer, config(authorizer.address(), 0x32, 0x52), 400);
    let asserter = Asserter::new();
    no_code(&asserter);
    push_claim_totals(&asserter, "0x10", &[(1_000, 300), (1_000, 0)]);
    push_bytes(&asserter, Vec::new());
    let logs = [claimed(&fresh.voucher.channel, 400)];
    let provider = Arc::new(MockProvider::new(asserter).with_outcome(Ok(receipt(true, &logs))));
    let response = settle(provider.clone(), claim_body(&authorizer, &[stale, fresh]));
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(provider.sent().len(), 1);
}

/// `claimWithSignature` reverts with `NotReceiverAuthorizer` on a mixed batch.
#[test]
fn batch_with_mixed_authorizers_is_rejected_before_any_read() {
    let authorizer = PrivateKeySigner::random();
    let payer = PrivateKeySigner::random();
    let own = row(&payer, config(authorizer.address(), 0x31, 0x51), 300);
    let foreign = row(&payer, config(Address::repeat_byte(0x99), 0x31, 0x51), 300);
    let provider = Arc::new(MockProvider::new(Asserter::new()));
    let response = settle(provider.clone(), claim_body(&authorizer, &[own, foreign]));
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_claim_payload"
    );
    assert!(provider.sent().is_empty());
}

/// A server-completed refund of 500 on `target`, bundling `claims`.
fn refund_payload(
    authorizer: &PrivateKeySigner,
    target: &ChannelConfig,
    claims: &[VoucherClaim],
) -> Value {
    let target_id = channel_id(target);
    let refund = compute_refund_digest(target_id, U256::ZERO, U128::from(500u128), CHAIN_ID);
    let claim = compute_claim_batch_digest(claims, CHAIN_ID);
    json!({
        "type": "refund",
        "channelConfig": target,
        "voucher": { "channelId": target_id, "maxClaimableAmount": "0", "signature": Bytes::new() },
        "amount": "500",
        "refundNonce": "0",
        "claims": claims,
        "refundAuthorizerSignature": sign(authorizer, refund),
        "claimAuthorizerSignature": sign(authorizer, claim),
    })
}

/// A refund multicall may carry claims for other channels. Only the refunded
/// channel's own state limits the refund, and both calls go out atomically.
#[test]
fn refund_multicall_with_another_channels_claim() {
    let authorizer = PrivateKeySigner::random();
    let payer = PrivateKeySigner::random();
    let target = ChannelConfig {
        payer_authorizer: payer.address().into(),
        ..channel_config(
            Address::repeat_byte(0x11),
            Address::ZERO,
            authorizer.address(),
        )
    };
    let claims = [row(&payer, config(authorizer.address(), 0x32, 0x52), 400)];
    let asserter = Asserter::new();
    push_channel_state(&asserter, 1_000, 0, 0);
    no_code(&asserter);
    no_code(&asserter);
    push_claim_totals(&asserter, "0x10", &[(1_000, 0)]);
    push_bytes(&asserter, Vec::new());
    push_channel_state(&asserter, 500, 0, 1);
    let refunded = Refunded {
        channelId: channel_id(&target),
        sender: Address::repeat_byte(0xfa),
        amount: 500,
    };
    let logs = [
        claimed(&claims[0].voucher.channel, 400),
        refunded.encode_log_data(),
    ];
    let provider = Arc::new(MockProvider::new(asserter).with_outcome(Ok(receipt(true, &logs))));
    let body = request(
        refund_payload(&authorizer, &target, &claims),
        &requirements(authorizer.address()),
    );
    let response = settle(provider.clone(), body);
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["amount"], "500");
    assert_eq!(
        response["extra"]["channelState"]["channelId"],
        json!(channel_id(&target))
    );
    let multicall = multicallCall::abi_decode(&provider.sent()[0].calldata).unwrap();
    assert!(claimWithSignatureCall::abi_decode(&multicall.data[0]).is_ok());
    let refund = refundWithSignatureCall::abi_decode(&multicall.data[1]).unwrap();
    assert_eq!(refund.amount, 500);
}
