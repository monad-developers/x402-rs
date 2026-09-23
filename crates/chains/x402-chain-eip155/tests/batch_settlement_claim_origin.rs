//! The transaction origin of the paid-voucher claim simulation.
//!
//! An `eth_call` sets `tx.origin` to its `from`, and an ERC-1271 wallet can
//! read it. A contract address has no key, so it is never the origin of a real
//! claim. The route models a wallet that accepts the canonical claim only
//! from one origin. The receiver authorizer and the receiver get their code
//! from the route, so each test picks which of them can send a transaction.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes};
use alloy_sol_types::{SolCall, SolError, SolValue};
use alloy_transport::mock::Asserter;
use batch_settlement_common::rpc::{Request, Route, push_transport_failure, revert, success};
use batch_settlement_common::*;
use serde_json::{Value, json};
use x402_chain_eip155::V2Eip155BatchSettlement;
use x402_chain_eip155::v2_eip155_batch_settlement::constants::BATCH_SETTLEMENT_ADDRESS;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::EIP1271_MAGIC_VALUE;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::{
    InvalidSignature, channelsCall, claimCall, multicallCall,
};
use x402_types::proto;
use x402_types::scheme::X402SchemeFacilitatorBuilder;

const WALLET: Address = Address::repeat_byte(0x11);
const AUTHORIZER: Address = Address::repeat_byte(0x44);
const CONTRACT: &[u8] = &[0x60, 0x00];
const SECRET: &str = "https://rpc.example/secret-key";

/// EIP-7702 delegation code to an arbitrary target.
fn delegation() -> Vec<u8> {
    [&[0xef, 0x01, 0x00][..], &[0x42; 20]].concat()
}

/// Which `tx.origin` the payer wallet accepts in the canonical claim.
#[derive(Clone, Copy)]
enum Accepts {
    Any,
    Origin(Address),
}

/// The code of the two receiver-side accounts. `None` leaves the read to the
/// queue, so a test can make it fail.
#[derive(Clone)]
struct Accounts {
    authorizer: Option<Vec<u8>>,
    receiver: Option<Vec<u8>>,
    wallet: Accepts,
}

/// A `claim`, or a `multicall` that is not a batch of `channels` views.
fn is_claim(request: &Request) -> bool {
    let input = request.input();
    let is_multicall_claim = multicallCall::abi_decode(&input).is_ok_and(|call| {
        !call
            .data
            .iter()
            .all(|d| d.starts_with(&channelsCall::SELECTOR))
    });
    request.method == "eth_call"
        && request.to() == Some(BATCH_SETTLEMENT_ADDRESS)
        && (input.starts_with(&claimCall::SELECTOR) || is_multicall_claim)
}

fn code_target(request: &Request) -> Option<Address> {
    serde_json::from_value(request.params.get(0)?.clone()).ok()
}

fn code_of(accounts: &Accounts, address: Address) -> Option<Vec<u8>> {
    match address {
        WALLET => Some(CONTRACT.to_vec()),
        AUTHORIZER => accounts.authorizer.clone(),
        RECEIVER => accounts.receiver.clone(),
        _ => None,
    }
}

fn route(accounts: Accounts) -> Route {
    Arc::new(move |request: &Request| match request.method.as_str() {
        "eth_blockNumber" => Some(success("0x10")),
        "eth_getCode" => {
            let code = code_of(&accounts, code_target(request)?)?;
            Some(success(Bytes::from(code)))
        }
        "eth_call" if request.to() == Some(WALLET) => {
            let mut magic = [0u8; 32];
            magic[..4].copy_from_slice(&EIP1271_MAGIC_VALUE);
            Some(success(Bytes::from(magic.to_vec())))
        }
        _ if is_claim(request) => Some(match accounts.wallet {
            Accepts::Origin(origin) if request.from() != Some(origin) => {
                revert(&InvalidSignature::SELECTOR)
            }
            _ => success(Bytes::new()),
        }),
        _ => None,
    })
}

fn verify(asserter: Asserter, accounts: Accounts, payload: Value) -> (Value, Arc<MockProvider>) {
    let provider = Arc::new(MockProvider::routed(asserter, Some(route(accounts))));
    let body = request(payload, &requirements(AUTHORIZER));
    let raw = serde_json::value::RawValue::from_string(body).unwrap();
    let facilitator = V2Eip155BatchSettlement
        .build(provider.clone(), None)
        .unwrap();
    let response = run(facilitator.verify(&proto::VerifyRequest::from(raw)));
    (response.unwrap().0, provider)
}

fn voucher(kind: &str, max_claimable: u128) -> Value {
    let config = channel_config(WALLET, Address::ZERO, AUTHORIZER);
    json!({
        "type": kind,
        "channelConfig": config,
        "voucher": {
            "channelId": channel_id(&config),
            "maxClaimableAmount": max_claimable.to_string(),
            "signature": Bytes::from(vec![0xab; 65]),
        },
    })
}

fn deposit() -> Value {
    let mut payload = voucher("deposit", 300);
    let valid_before = x402_types::timestamp::UnixTimestamp::now().as_secs() + 600;
    payload["deposit"] = json!({
        "amount": "1000",
        "authorization": { "erc3009Authorization": {
            "validAfter": "0",
            "validBefore": valid_before.to_string(),
            "salt": B256::repeat_byte(0x77),
            "signature": Bytes::from(vec![0xab; 65]),
        }},
    });
    payload
}

fn verify_voucher(accounts: Accounts) -> (Value, Arc<MockProvider>) {
    let asserter = Asserter::new();
    push_channel_state(&asserter, 1_000, 0, 0);
    verify(asserter, accounts, voucher("voucher", 300))
}

/// Pre-deposit reads and the deposit simulation from the broadcast sender.
fn verify_deposit(accounts: Accounts) -> (Value, Arc<MockProvider>) {
    let asserter = Asserter::new();
    push_channel_state(&asserter, 0, 0, 0);
    push_bytes(
        &asserter,
        alloy_primitives::U256::from(5_000u64).abi_encode(),
    );
    push_bytes(&asserter, Vec::new());
    verify(asserter, accounts, deposit())
}

/// The receiver-side code reads, in order. Each one is at the pinned block.
fn receiver_side_reads(provider: &MockProvider) -> Vec<Address> {
    let reads: Vec<_> = provider
        .requests_for("eth_getCode")
        .into_iter()
        .filter(|read| code_target(read) != Some(WALLET))
        .collect();
    assert!(reads.iter().all(|read| read.block() == Some("0x10")));
    reads.iter().filter_map(code_target).collect()
}

/// The claim simulations: at the pinned block, with no state override.
fn claims(provider: &MockProvider) -> Vec<Request> {
    let calls = provider.requests_for("eth_call");
    assert!(calls.iter().all(|call| !call.has_state_override()));
    let claims: Vec<_> = calls.into_iter().filter(is_claim).collect();
    assert!(claims.iter().all(|claim| claim.block() == Some("0x10")));
    claims
}

fn claim_origin(provider: &MockProvider) -> Option<Address> {
    let claims = claims(provider);
    assert_eq!(claims.len(), 1);
    claims[0].from()
}

fn accounts(authorizer: &[u8], receiver: &[u8], wallet: Accepts) -> Accounts {
    Accounts {
        authorizer: Some(authorizer.to_vec()),
        receiver: Some(receiver.to_vec()),
        wallet,
    }
}

#[test]
fn an_eoa_authorizer_is_the_claim_origin() {
    let (response, provider) = verify_voucher(accounts(&[], &[], Accepts::Origin(AUTHORIZER)));
    assert_eq!(response["isValid"], true, "{response}");
    assert_eq!(claim_origin(&provider), Some(AUTHORIZER));
    assert_eq!(receiver_side_reads(&provider), [AUTHORIZER]);
}

#[test]
fn a_delegated_authorizer_is_the_claim_origin() {
    let wallet = Accepts::Origin(AUTHORIZER);
    let (response, provider) = verify_voucher(accounts(&delegation(), CONTRACT, wallet));
    assert_eq!(response["isValid"], true, "{response}");
    assert_eq!(claim_origin(&provider), Some(AUTHORIZER));
    assert_eq!(receiver_side_reads(&provider), [AUTHORIZER]);
}

/// This wallet accepts only the contract authorizer as its transaction origin.
/// No real claim has that origin, so the voucher is rejected.
#[test]
fn a_contract_authorizer_falls_back_to_an_eoa_receiver() {
    let wallet = Accepts::Origin(AUTHORIZER);
    let (response, provider) = verify_voucher(accounts(CONTRACT, &[], wallet));
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_voucher_signature"
    );
    assert_eq!(claim_origin(&provider), Some(RECEIVER));
    assert_eq!(receiver_side_reads(&provider), [AUTHORIZER, RECEIVER]);

    let (response, provider) = verify_voucher(accounts(CONTRACT, &[], Accepts::Any));
    assert_eq!(response["isValid"], true, "{response}");
    assert_eq!(claim_origin(&provider), Some(RECEIVER));
}

#[test]
fn a_deposit_voucher_uses_the_same_origin() {
    let wallet = Accepts::Origin(AUTHORIZER);
    let (response, provider) = verify_deposit(accounts(CONTRACT, &[], wallet));
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_voucher_signature"
    );
    assert_eq!(claim_origin(&provider), Some(RECEIVER));
    assert_eq!(receiver_side_reads(&provider), [AUTHORIZER, RECEIVER]);

    let (response, provider) = verify_deposit(accounts(CONTRACT, &[], Accepts::Any));
    assert_eq!(response["isValid"], true, "{response}");
    assert_eq!(claim_origin(&provider), Some(RECEIVER));
    let deposit = provider.requests_for("eth_call");
    let deposit = deposit
        .iter()
        .find(|call| call.from() == Some(provider.signer()));
    assert!(
        deposit.is_some(),
        "the deposit simulation keeps the broadcast sender"
    );
}

/// Two ordinary contracts: no simulation runs, and no verdict is invented.
#[test]
fn no_receiver_side_origin_fails_closed() {
    let (response, provider) = verify_voucher(accounts(CONTRACT, CONTRACT, Accepts::Any));
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_claim_simulation_failed"
    );
    let message = "no receiver-side account can send a claim transaction";
    assert_eq!(response["invalidMessage"], message);
    assert!(claims(&provider).is_empty());
    assert_eq!(receiver_side_reads(&provider), [AUTHORIZER, RECEIVER]);

    let (response, provider) = verify_deposit(accounts(CONTRACT, CONTRACT, Accepts::Any));
    assert_eq!(
        response["invalidReason"],
        "invalid_batch_settlement_evm_deposit_simulation_failed"
    );
    assert_eq!(response["invalidMessage"], message);
    assert!(claims(&provider).is_empty());
}

#[test]
fn a_code_read_failure_is_rpc_read_failed() {
    for accounts in [
        Accounts {
            authorizer: None,
            receiver: Some(Vec::new()),
            wallet: Accepts::Any,
        },
        Accounts {
            authorizer: Some(CONTRACT.to_vec()),
            receiver: None,
            wallet: Accepts::Any,
        },
    ] {
        let asserter = Asserter::new();
        push_channel_state(&asserter, 1_000, 0, 0);
        push_transport_failure(&asserter, SECRET);
        let (response, provider) = verify(asserter, accounts, voucher("voucher", 300));
        assert_eq!(
            response["invalidReason"],
            "invalid_batch_settlement_evm_rpc_read_failed"
        );
        assert!(response.get("invalidMessage").is_none(), "{response}");
        assert!(!response.to_string().contains("secret"));
        assert!(claims(&provider).is_empty());
    }
}

/// A refund voucher at the claimed total pays nothing. It needs no claim
/// origin, so two contract accounts do not reject it.
#[test]
fn a_zero_charge_refund_reads_no_receiver_side_code() {
    let asserter = Asserter::new();
    push_channel_state(&asserter, 1_000, 300, 0);
    let accounts = accounts(CONTRACT, CONTRACT, Accepts::Any);
    let (response, provider) = verify(asserter, accounts, voucher("refund", 300));
    assert_eq!(response["isValid"], true, "{response}");
    assert!(receiver_side_reads(&provider).is_empty());
    assert!(claims(&provider).is_empty());
}
