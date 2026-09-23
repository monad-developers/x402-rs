//! Payer code reads in a claim batch.
//!
//! A batch can name one payer in many rows. The facilitator reads the code of
//! each payer with a zero `payerAuthorizer` one time for each batch. It still
//! checks each EOA voucher with strict ECDSA. A payer with code gets no local
//! verdict, and a nonzero `payerAuthorizer` never uses the payer code. The
//! route answers each `eth_getCode` from the address, so a test can count the
//! reads for each payer. The queue answers the other requests in order.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes, Signature, U128, U256, uint};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolError, SolEvent};
use alloy_transport::mock::Asserter;
use batch_settlement_common::rpc::{Request, Route, push_revert, success};
use batch_settlement_common::*;
use serde_json::{Value, json};
use x402_chain_eip155::V2Eip155BatchSettlement;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::{
    InvalidSignature, Refunded, claimWithSignatureCall,
};
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::{
    compute_claim_batch_digest, compute_refund_digest, compute_voucher_digest,
};
use x402_chain_eip155::v2_eip155_batch_settlement::{
    ChannelConfig, U128String, VoucherClaim, VoucherClaimVoucher,
};
use x402_types::proto;
use x402_types::scheme::X402SchemeFacilitatorBuilder;

const CONTRACT: &[u8] = &[0x60, 0x00];
const SECP256K1_ORDER: U256 =
    uint!(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_U256);
const BAD_VOUCHER: &str = "invalid_batch_settlement_evm_voucher_signature";

/// `contracts` have code. Every other address has none.
fn code_route(contracts: Vec<Address>) -> Route {
    Arc::new(move |request: &Request| {
        if request.method != "eth_getCode" {
            return None;
        }
        let target: Address = serde_json::from_value(request.params[0].clone()).ok()?;
        let code = if contracts.contains(&target) {
            CONTRACT
        } else {
            &[]
        };
        Some(success(Bytes::from(code.to_vec())))
    })
}

fn mock(asserter: Asserter, contracts: &[Address]) -> Arc<MockProvider> {
    let route = code_route(contracts.to_vec());
    let provider = MockProvider::routed(asserter, Some(route));
    Arc::new(provider.with_outcome(Ok(receipt(true, &[]))))
}

fn settle(provider: &Arc<MockProvider>, body: String) -> Value {
    let facilitator = V2Eip155BatchSettlement
        .build(provider.clone(), None)
        .unwrap();
    let raw = serde_json::value::RawValue::from_string(body).unwrap();
    run(facilitator.settle(&proto::SettleRequest::from(raw)))
        .unwrap()
        .0
}

/// A channel of `payer`. `salt` makes it different from the other channels.
fn channel(
    payer: Address,
    payer_authorizer: Address,
    authorizer: &PrivateKeySigner,
    salt: u8,
) -> ChannelConfig {
    ChannelConfig {
        salt: B256::repeat_byte(salt),
        ..channel_config(payer, payer_authorizer, authorizer.address())
    }
}

/// A row that claims `total`, with a voucher for `total` that `signer` signs.
fn row(config: &ChannelConfig, signer: &PrivateKeySigner, total: u128) -> VoucherClaim {
    let digest = compute_voucher_digest(channel_id(config), U128::from(total), CHAIN_ID);
    VoucherClaim {
        voucher: VoucherClaimVoucher {
            channel: config.clone(),
            max_claimable_amount: U128String(U128::from(total)),
        },
        signature: sign(signer, digest),
        total_claimed: U128String(U128::from(total)),
    }
}

/// The same signer, with `n - s` and the other parity. Strict ECDSA rejects
/// it. A recovery that normalizes `s`, as Permit2 does, accepts it.
fn high_s(signature: &Bytes) -> Bytes {
    let low = Signature::try_from(signature.as_ref()).unwrap();
    let high = Signature::new(low.r(), SECP256K1_ORDER - low.s(), !low.v());
    Bytes::from(high.as_bytes().to_vec())
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

/// Queues the channel read of `channels` fresh channels with a balance of
/// 1,000, and one claim simulation that passes.
fn claim_queue(channels: usize) -> Asserter {
    let asserter = Asserter::new();
    push_claim_totals(&asserter, "0x10", &vec![(1_000, 0); channels]);
    push_bytes(&asserter, Vec::new());
    asserter
}

fn code_reads(provider: &MockProvider, address: Address) -> usize {
    let target = json!(address);
    let reads = provider.requests_for("eth_getCode");
    reads.iter().filter(|read| read.params[0] == target).count()
}

/// The canonical claim simulations from the broadcast sender.
fn simulations(provider: &MockProvider) -> usize {
    let calls = provider.requests_for("eth_call");
    let from_sender = calls
        .iter()
        .filter(|call| call.from() == Some(provider.signer()));
    from_sender
        .filter(|call| call.input().starts_with(&claimWithSignatureCall::SELECTOR))
        .count()
}

/// Rows 1..=count on one channel of an EOA payer, and one stale row with a
/// bad signature. The contract skips the stale row, so no check reads it.
fn one_payer_rows(
    payer: &PrivateKeySigner,
    config: &ChannelConfig,
    count: u128,
) -> Vec<VoucherClaim> {
    let mut rows: Vec<_> = (1..=count).map(|total| row(config, payer, total)).collect();
    let mut stale = row(config, payer, 1);
    stale.signature = Bytes::from(vec![0xab; 65]);
    rows.insert(10, stale);
    rows
}

#[test]
fn many_rows_of_one_eoa_payer_read_its_code_once() {
    let authorizer = PrivateKeySigner::random();
    let payer = PrivateKeySigner::random();
    let config = channel(payer.address(), Address::ZERO, &authorizer, 1);
    let rows = one_payer_rows(&payer, &config, 40);
    let provider = mock(claim_queue(1), &[]);
    let response = settle(&provider, claim_body(&authorizer, &rows));
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(code_reads(&provider, payer.address()), 1);
    assert_eq!(
        provider.requests_for("eth_getCode").len(),
        2,
        "authorizer and payer"
    );
    let sent = claimWithSignatureCall::abi_decode(&provider.sent()[0].calldata).unwrap();
    assert_eq!(
        sent.voucherClaims.len(),
        41,
        "the facilitator never splits a batch"
    );
}

/// The facilitator keeps the code read of the payer, not a signature verdict.
/// A bad last row fails, also when only strict ECDSA rejects it.
#[test]
fn a_bad_last_row_of_a_known_eoa_payer_is_rejected_without_send() {
    let authorizer = PrivateKeySigner::random();
    let payer = PrivateKeySigner::random();
    let config = channel(payer.address(), Address::ZERO, &authorizer, 1);
    let good = row(&config, &payer, 40);
    let other_key = row(&config, &PrivateKeySigner::random(), 40).signature;
    for bad in [other_key, high_s(&good.signature)] {
        let mut rows = one_payer_rows(&payer, &config, 39);
        rows.push(VoucherClaim {
            signature: bad,
            ..good.clone()
        });
        let provider = mock(claim_queue(1), &[]);
        let response = settle(&provider, claim_body(&authorizer, &rows));
        assert_eq!(response["errorReason"], BAD_VOUCHER, "{response}");
        assert_eq!(code_reads(&provider, payer.address()), 1);
        assert_eq!(simulations(&provider), 0);
        assert!(provider.sent().is_empty());
    }
}

/// The first row of a payer, and each row with a nonzero `payerAuthorizer`,
/// also gets strict ECDSA. A high-`s` signature fails at each position.
#[test]
fn a_high_s_row_fails_at_each_position_and_signer() {
    let authorizer = PrivateKeySigner::random();
    let payer = PrivateKeySigner::random();
    let delegate = PrivateKeySigner::random();
    let direct = channel(payer.address(), Address::ZERO, &authorizer, 1);
    let delegated = channel(payer.address(), delegate.address(), &authorizer, 2);
    for (config, signer) in [(&direct, &payer), (&delegated, &delegate)] {
        for bad in 0..2 {
            let mut rows = vec![row(config, signer, 1), row(config, signer, 2)];
            rows[bad].signature = high_s(&rows[bad].signature);
            let provider = mock(claim_queue(1), &[]);
            let response = settle(&provider, claim_body(&authorizer, &rows));
            assert_eq!(response["errorReason"], BAD_VOUCHER, "{bad}: {response}");
            assert_eq!(simulations(&provider), 0);
            assert!(provider.sent().is_empty());
        }
    }
}

/// Each payer is a key of its own. One payer with two channels reads its code
/// one time, and a contract payer after an EOA payer keeps its own kind.
#[test]
fn distinct_payers_each_read_their_code_once() {
    let authorizer = PrivateKeySigner::random();
    let first = PrivateKeySigner::random();
    let second = PrivateKeySigner::random();
    let wallet = Address::repeat_byte(0x77);
    let first_a = channel(first.address(), Address::ZERO, &authorizer, 1);
    let first_b = channel(first.address(), Address::ZERO, &authorizer, 2);
    let second_a = channel(second.address(), Address::ZERO, &authorizer, 3);
    let wallet_a = channel(wallet, Address::ZERO, &authorizer, 4);
    let rows = [
        row(&first_a, &first, 100),
        row(&second_a, &second, 100),
        row(&wallet_a, &first, 100),
        row(&first_b, &first, 100),
        row(&first_a, &first, 200),
        row(&second_a, &second, 200),
        row(&wallet_a, &first, 200),
    ];
    let provider = mock(claim_queue(4), &[wallet]);
    let response = settle(&provider, claim_body(&authorizer, &rows));
    assert_eq!(response["success"], true, "{response}");
    for payer in [first.address(), second.address(), wallet] {
        assert_eq!(code_reads(&provider, payer), 1, "{payer}");
    }
    assert_eq!(simulations(&provider), 1);
}

/// A payer with code gets no local verdict, however often it repeats. The
/// canonical simulation from the broadcast sender decides the batch.
#[test]
fn a_repeated_contract_payer_is_decided_by_the_simulation() {
    let authorizer = PrivateKeySigner::random();
    let wallet = Address::repeat_byte(0x77);
    let config = channel(wallet, Address::ZERO, &authorizer, 1);
    let key = PrivateKeySigner::random();
    let rows: Vec<_> = (1..=5).map(|total| row(&config, &key, total)).collect();

    let provider = mock(claim_queue(1), &[wallet]);
    let response = settle(&provider, claim_body(&authorizer, &rows));
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(code_reads(&provider, wallet), 1);
    assert_eq!(simulations(&provider), 1);
    assert!(
        provider
            .requests_for("eth_call")
            .iter()
            .all(|call| call.to() != Some(wallet))
    );

    let asserter = Asserter::new();
    push_claim_totals(&asserter, "0x10", &[(1_000, 0)]);
    push_revert(&asserter, &InvalidSignature::SELECTOR);
    let provider = mock(asserter, &[wallet]);
    let response = settle(&provider, claim_body(&authorizer, &rows));
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_claim_simulation_failed"
    );
    assert_eq!(simulations(&provider), 1);
    assert!(provider.sent().is_empty());
}

/// A nonzero `payerAuthorizer` gets strict ECDSA against that authorizer. It
/// neither reads nor writes the kind of its payer, in either row order.
#[test]
fn a_nonzero_payer_authorizer_ignores_the_payer_code() {
    let authorizer = PrivateKeySigner::random();
    let wallet = Address::repeat_byte(0x77);
    let delegate = PrivateKeySigner::random();
    let direct = channel(wallet, Address::ZERO, &authorizer, 1);
    let delegated = channel(wallet, delegate.address(), &authorizer, 2);

    let forged = row(&delegated, &PrivateKeySigner::random(), 100);
    let rows = [row(&direct, &delegate, 100), forged];
    let provider = mock(claim_queue(2), &[wallet]);
    let response = settle(&provider, claim_body(&authorizer, &rows));
    assert_eq!(response["errorReason"], BAD_VOUCHER, "{response}");
    assert_eq!(simulations(&provider), 0);
    assert!(provider.sent().is_empty());

    let rows = [
        row(&delegated, &delegate, 100),
        row(&direct, &delegate, 100),
    ];
    let provider = mock(claim_queue(2), &[wallet]);
    let response = settle(&provider, claim_body(&authorizer, &rows));
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(
        code_reads(&provider, wallet),
        1,
        "the direct row reads the code"
    );
    assert_eq!(code_reads(&provider, delegate.address()), 0);
    assert_eq!(simulations(&provider), 1);
}

/// A refund shares the claim checks, so its bundled claims read each payer
/// one time too.
#[test]
fn bundled_refund_claims_read_the_payer_code_once() {
    let authorizer = PrivateKeySigner::random();
    let payer = PrivateKeySigner::random();
    let target = channel(payer.address(), Address::ZERO, &authorizer, 9);
    let config = channel(payer.address(), Address::ZERO, &authorizer, 1);
    let claims: Vec<_> = (1..=20).map(|total| row(&config, &payer, total)).collect();
    let target_id = channel_id(&target);
    let refund = compute_refund_digest(target_id, U256::ZERO, U128::from(500u128), CHAIN_ID);
    let batch = compute_claim_batch_digest(&claims, CHAIN_ID);
    let payload = json!({
        "type": "refund",
        "channelConfig": target,
        "voucher": { "channelId": target_id, "maxClaimableAmount": "0", "signature": Bytes::new() },
        "amount": "500",
        "refundNonce": "0",
        "claims": claims,
        "refundAuthorizerSignature": sign(&authorizer, refund),
        "claimAuthorizerSignature": sign(&authorizer, batch),
    });
    let asserter = Asserter::new();
    push_channel_state(&asserter, 1_000, 0, 0);
    push_claim_totals(&asserter, "0x10", &[(1_000, 0)]);
    push_bytes(&asserter, Vec::new());
    push_channel_state(&asserter, 500, 0, 1);
    let refunded = Refunded {
        channelId: target_id,
        sender: Address::repeat_byte(0xfa),
        amount: 500,
    };
    let receipt = receipt(true, &[refunded.encode_log_data()]);
    let provider = MockProvider::routed(asserter, Some(code_route(Vec::new())));
    let provider = Arc::new(provider.with_outcome(Ok(receipt)));
    let response = settle(
        &provider,
        request(payload, &requirements(authorizer.address())),
    );
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(code_reads(&provider, payer.address()), 1);
    assert_eq!(provider.sent().len(), 1);
}
