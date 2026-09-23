//! Contract wallets (zero `payerAuthorizer`, payer with code) and contract
//! authorizers. The route models two wallets with different caller rules by how
//! they are called, so a direct `isValidSignature` call and the canonical
//! contract call get different answers:
//!
//! - `DirectOnly` returns the magic value to a top-level call but fails the
//!   settlement contract's static call (a caller-0 or `SSTORE` wallet).
//! - `SettlementOnly` returns the magic value only to the settlement contract.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes, U128, U256};
use alloy_sol_types::{SolCall, SolError, SolEvent, SolValue};
use alloy_transport::mock::Asserter;
use batch_settlement_common::rpc::{Request, Route, revert, success};
use batch_settlement_common::*;
use serde_json::{Value, json};
use x402_chain_eip155::V2Eip155BatchSettlement;
use x402_chain_eip155::v2_eip155_batch_settlement::constants::BATCH_SETTLEMENT_ADDRESS;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::EIP1271_MAGIC_VALUE;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::{
    Claimed, InvalidSignature, channelsCall, claimCall, claimWithSignatureCall, multicallCall,
};
use x402_chain_eip155::v2_eip155_batch_settlement::{
    U128String, VoucherClaim, VoucherClaimVoucher,
};
use x402_types::proto;
use x402_types::scheme::{X402SchemeFacilitator, X402SchemeFacilitatorBuilder};

const WALLET: Address = Address::repeat_byte(0x11);
const AUTHORIZER: Address = Address::repeat_byte(0x44);

#[derive(Clone, Copy, PartialEq)]
enum Wallet {
    DirectOnly,
    SettlementOnly,
}

fn signature() -> Bytes {
    Bytes::from(vec![0xab; 65])
}

/// A call the settlement contract makes to the wallet: every write entry
/// point, and the read-only `claim` and `multicall` checks. A `multicall` of
/// `channels` views is a state read, which the queue answers.
fn is_contract_call(request: &Request) -> bool {
    let selectors = [
        claimCall::SELECTOR,
        multicallCall::SELECTOR,
        claimWithSignatureCall::SELECTOR,
    ];
    let input = request.input();
    let channel_read = multicallCall::abi_decode(&input).is_ok_and(|call| {
        call.data
            .iter()
            .all(|d| d.starts_with(&channelsCall::SELECTOR))
    });
    request.to() == Some(BATCH_SETTLEMENT_ADDRESS)
        && selectors.iter().any(|s| input.starts_with(s))
        && !channel_read
}

fn route(wallet: Wallet) -> Route {
    Arc::new(move |request: &Request| {
        if request.method == "eth_blockNumber" {
            return Some(success("0x10"));
        }
        if request.method != "eth_call" {
            return None;
        }
        let mut magic = [0u8; 32];
        magic[..4].copy_from_slice(&EIP1271_MAGIC_VALUE);
        let invalid = revert(&InvalidSignature::SELECTOR);
        if request.to() == Some(WALLET) || request.to() == Some(AUTHORIZER) {
            return Some(match wallet {
                Wallet::DirectOnly => success(Bytes::from(magic.to_vec())),
                Wallet::SettlementOnly => revert(&[]),
            });
        }
        is_contract_call(request).then(|| match wallet {
            Wallet::DirectOnly => invalid,
            Wallet::SettlementOnly => success(Bytes::new()),
        })
    })
}

fn wallet_provider(asserter: Asserter, wallet: Wallet) -> Arc<MockProvider> {
    Arc::new(MockProvider::routed(asserter, Some(route(wallet))))
}

fn facilitator(provider: Arc<MockProvider>) -> Box<dyn X402SchemeFacilitator> {
    V2Eip155BatchSettlement.build(provider, None).unwrap()
}

fn verify(provider: Arc<MockProvider>, payload: Value) -> Value {
    let body = request(payload, &requirements(AUTHORIZER));
    let raw = serde_json::value::RawValue::from_string(body).unwrap();
    let request = proto::VerifyRequest::from(raw);
    run(facilitator(provider).verify(&request)).unwrap().0
}

fn voucher(kind: &str, max_claimable: u128) -> Value {
    let config = channel_config(WALLET, Address::ZERO, AUTHORIZER);
    json!({
        "type": kind,
        "channelConfig": config,
        "voucher": {
            "channelId": channel_id(&config),
            "maxClaimableAmount": max_claimable.to_string(),
            "signature": signature(),
        },
    })
}

fn code(asserter: &Asserter) {
    push_bytes(asserter, vec![0x60, 0x00]);
}

/// The one canonical check: `claim` from the authorizer at the pinned block,
/// with no state override and no call to the wallet itself.
fn canonical_claim(provider: &MockProvider) -> Request {
    let calls = provider.requests_for("eth_call");
    assert!(calls.iter().all(|call| !call.has_state_override()));
    assert!(calls.iter().all(|call| call.to() != Some(WALLET)));
    let claims: Vec<_> = calls.into_iter().filter(is_contract_call).collect();
    assert_eq!(claims.len(), 1);
    let claim = claims[0].clone();
    assert_eq!(claim.from(), Some(AUTHORIZER));
    assert_eq!(claim.block(), Some("0x10"));
    claim
}

fn assert_claims_max(input: &[u8], max_claimable: u128) {
    let call = claimCall::abi_decode(input).unwrap();
    let row = &call.voucherClaims[0];
    assert_eq!(row.totalClaimed, max_claimable);
    assert_eq!(row.voucher.maxClaimableAmount, max_claimable);
    assert_eq!(
        row.signature,
        signature(),
        "the signature bytes pass through unchanged"
    );
}

fn verify_paid_voucher(wallet: Wallet) -> (Value, Arc<MockProvider>) {
    let asserter = Asserter::new();
    code(&asserter);
    push_channel_state(&asserter, 1_000, 0, 0);
    no_code(&asserter);
    let provider = wallet_provider(asserter, wallet);
    (verify(provider.clone(), voucher("voucher", 300)), provider)
}

#[test]
fn paid_voucher_that_only_passes_a_direct_call_is_rejected() {
    let (response, provider) = verify_paid_voucher(Wallet::DirectOnly);
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_voucher_signature"
    );
    assert_claims_max(&canonical_claim(&provider).input(), 300);
    let reads = provider.requests_for("eth_call");
    assert!(reads.iter().all(|read| read.block() == Some("0x10")));
}

#[test]
fn paid_voucher_from_a_settlement_only_wallet_is_valid() {
    let (response, provider) = verify_paid_voucher(Wallet::SettlementOnly);
    assert_eq!(response["isValid"], true, "{response}");
    assert_claims_max(&canonical_claim(&provider).input(), 300);
}

fn wallet_deposit() -> Value {
    let config = channel_config(WALLET, Address::ZERO, AUTHORIZER);
    let valid_before = x402_types::timestamp::UnixTimestamp::now().as_secs() + 600;
    json!({
        "type": "deposit",
        "channelConfig": config,
        "voucher": {
            "channelId": channel_id(&config),
            "maxClaimableAmount": "300",
            "signature": signature(),
        },
        "deposit": {
            "amount": "1000",
            "authorization": { "erc3009Authorization": {
                "validAfter": "0",
                "validBefore": valid_before.to_string(),
                "salt": B256::repeat_byte(0x77),
                "signature": signature(),
            }},
        },
    })
}

/// Authorization code read, voucher code read, pre-deposit reads, the
/// deposit simulation from the broadcast sender, and the authorizer code read.
fn verify_wallet_deposit(wallet: Wallet) -> (Value, Arc<MockProvider>) {
    let asserter = Asserter::new();
    code(&asserter);
    code(&asserter);
    push_channel_state(&asserter, 0, 0, 0);
    push_bytes(&asserter, U256::from(5_000u64).abi_encode());
    push_bytes(&asserter, Vec::new());
    no_code(&asserter);
    let provider = wallet_provider(asserter, wallet);
    (verify(provider.clone(), wallet_deposit()), provider)
}

/// The claim must see the deposit, so it runs after it in one `multicall`.
fn assert_deposit_then_claim(provider: &MockProvider) {
    let call = multicallCall::abi_decode(&canonical_claim(provider).input()).unwrap();
    let simulated = provider.requests_for("eth_call");
    let deposit = simulated
        .iter()
        .find(|call| call.from() == Some(provider.signer()));
    assert_eq!(call.data[0], deposit.unwrap().input());
    assert_claims_max(&call.data[1], 300);
}

#[test]
fn deposit_voucher_that_only_passes_a_direct_call_is_rejected() {
    let (response, provider) = verify_wallet_deposit(Wallet::DirectOnly);
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_voucher_signature"
    );
    assert_deposit_then_claim(&provider);
}

/// The ERC-3009 authorization of a contract payer is not pre-rejected by a
/// direct call; the token checks it inside the deposit simulation.
#[test]
fn deposit_from_a_settlement_only_wallet_is_valid() {
    let (response, provider) = verify_wallet_deposit(Wallet::SettlementOnly);
    assert_eq!(response["isValid"], true, "{response}");
    assert_deposit_then_claim(&provider);
}

/// A refund voucher at the claimed total pays nothing, and `claim` skips it,
/// so only the direct wallet call checks it. A refund voucher above the
/// claimed total is claimable, so it gets the canonical check.
#[test]
fn refund_voucher_is_checked_canonically_only_when_it_is_claimable() {
    let asserter = Asserter::new();
    code(&asserter);
    push_channel_state(&asserter, 1_000, 300, 0);
    let provider = wallet_provider(asserter, Wallet::SettlementOnly);
    let response = verify(provider.clone(), voucher("refund", 300));
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_voucher_signature"
    );
    let direct = provider.requests_for("eth_call");
    assert!(direct.iter().any(|call| call.to() == Some(WALLET)));
    assert!(!direct.iter().any(is_contract_call));

    let asserter = Asserter::new();
    code(&asserter);
    push_channel_state(&asserter, 1_000, 200, 0);
    no_code(&asserter);
    let provider = wallet_provider(asserter, Wallet::DirectOnly);
    let response = verify(provider.clone(), voucher("refund", 300));
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_voucher_signature"
    );
    assert_claims_max(&canonical_claim(&provider).input(), 300);
}

fn wallet_claim_body() -> String {
    let row = VoucherClaim {
        voucher: VoucherClaimVoucher {
            channel: channel_config(WALLET, Address::ZERO, AUTHORIZER),
            max_claimable_amount: U128String(U128::from(500u128)),
        },
        signature: signature(),
        total_claimed: U128String(U128::from(500u128)),
    };
    let payload = json!({
        "type": "claim",
        "claims": [row],
        "claimAuthorizerSignature": signature(),
    });
    request(payload, &requirements(AUTHORIZER))
}

/// The row claims 500 on a channel that has `claimed` onchain. The payer code
/// read runs only when the row moves the total.
fn settle_wallet_claim(wallet: Wallet, claimed: u128) -> (Value, Arc<MockProvider>) {
    let asserter = Asserter::new();
    code(&asserter);
    push_channel_totals(&asserter, &[(1_000, claimed)]);
    code(&asserter);
    let config = channel_config(WALLET, Address::ZERO, AUTHORIZER);
    let event = Claimed {
        channelId: channel_id(&config),
        sender: Address::repeat_byte(0xfa),
        claimAmount: 400,
        newTotalClaimed: 500,
    };
    let receipt = receipt(true, &[event.encode_log_data()]);
    let provider = MockProvider::routed(asserter, Some(route(wallet))).with_outcome(Ok(receipt));
    let provider = Arc::new(provider);
    let raw = serde_json::value::RawValue::from_string(wallet_claim_body()).unwrap();
    let request = proto::SettleRequest::from(raw);
    let response = run(facilitator(provider.clone()).settle(&request))
        .unwrap()
        .0;
    (response, provider)
}

/// A contract authorizer and a contract payer get no direct pre-check. The
/// write simulation from the broadcast sender decides.
#[test]
fn relayed_claim_is_decided_by_the_write_simulation() {
    let (response, provider) = settle_wallet_claim(Wallet::SettlementOnly, 100);
    assert_eq!(response["success"], true, "{response}");
    let calls = provider.requests_for("eth_call");
    let simulation = calls.iter().find(|call| is_contract_call(call)).unwrap();
    assert_eq!(simulation.from(), Some(provider.signer()));
    assert_eq!(simulation.input(), provider.sent()[0].calldata);
    assert!(calls.iter().all(|call| call.to() != Some(WALLET)));

    let (response, provider) = settle_wallet_claim(Wallet::DirectOnly, 100);
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_claim_simulation_failed"
    );
    assert!(provider.sent().is_empty());
}

/// An already-claimed batch from a contract authorizer gets no local verdict.
/// The no-broadcast success needs the canonical call at the read block, so a
/// signature that only passes a direct wallet call is not consent.
#[test]
fn already_claimed_batch_from_a_contract_authorizer_is_decided_by_the_contract() {
    let (response, provider) = settle_wallet_claim(Wallet::SettlementOnly, 500);
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["transaction"], "");
    assert!(provider.sent().is_empty());
    let calls = provider.requests_for("eth_call");
    let check = calls.iter().find(|call| is_contract_call(call)).unwrap();
    assert!(claimWithSignatureCall::abi_decode(&check.input()).is_ok());
    assert_eq!(check.from(), Some(provider.signer()));
    assert_eq!(check.block(), Some("0x10"));
    assert!(calls.iter().all(|call| call.to() != Some(AUTHORIZER)));

    let (response, provider) = settle_wallet_claim(Wallet::DirectOnly, 500);
    assert_eq!(response["success"], false);
    assert_eq!(
        response["errorReason"],
        "invalid_batch_settlement_evm_claim_simulation_failed"
    );
    assert!(provider.sent().is_empty());
}
