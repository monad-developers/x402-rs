use alloy_network::Ethereum;
use alloy_primitives::{Bytes, U256, uint};
use alloy_provider::RootProvider;
use alloy_rpc_client::RpcClient;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::mock::Asserter;

use super::*;

const ORDER: U256 = uint!(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_U256);
const DIGEST: B256 = B256::repeat_byte(0x42);

fn signed_bytes(signer: &PrivateKeySigner) -> [u8; 65] {
    signer.sign_hash_sync(&DIGEST).unwrap().as_bytes()
}

fn check(bytes: &[u8], signer: Address, rules: EcdsaRules) -> Result<(), SignatureCheckError> {
    let signature = Bytes::copy_from_slice(bytes);
    let signed = SignedDigest {
        signature: &signature,
        digest: DIGEST,
        signer,
    };
    verify_ecdsa(&signed, rules)
}

/// Same key and digest, with `s` moved to the upper half and `v` flipped.
fn high_s(canonical: [u8; 65]) -> [u8; 65] {
    let s = U256::from_be_slice(&canonical[32..64]);
    let mut out = canonical;
    out[32..64].copy_from_slice(&(ORDER - s).to_be_bytes::<32>());
    out[64] = if canonical[64] == 27 { 28 } else { 27 };
    out
}

fn compact(canonical: [u8; 65]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&canonical[..64]);
    if canonical[64] == 28 {
        out[32] |= 0x80;
    }
    out
}

#[test]
fn strict_accepts_a_canonical_signature() {
    let signer = PrivateKeySigner::random();
    let bytes = signed_bytes(&signer);
    assert_eq!(check(&bytes, signer.address(), EcdsaRules::Strict), Ok(()));
}

#[test]
fn strict_rejects_another_signer() {
    let signer = PrivateKeySigner::random();
    let bytes = signed_bytes(&signer);
    let other = PrivateKeySigner::random().address();
    assert_eq!(
        check(&bytes, other, EcdsaRules::Strict),
        Err(SignatureCheckError::InvalidSignature)
    );
}

/// OZ `recoverCalldata` only accepts 65 bytes.
#[test]
fn strict_rejects_the_erc2098_compact_form() {
    let signer = PrivateKeySigner::random();
    let bytes = compact(signed_bytes(&signer));
    assert_eq!(
        check(&bytes, signer.address(), EcdsaRules::Strict),
        Err(SignatureCheckError::InvalidFormat)
    );
}

/// OZ rejects `s` above half the order; recovering it anyway would accept an
/// unclaimable voucher.
#[test]
fn strict_rejects_high_s() {
    let signer = PrivateKeySigner::random();
    let bytes = high_s(signed_bytes(&signer));
    assert_eq!(
        check(&bytes, signer.address(), EcdsaRules::Strict),
        Err(SignatureCheckError::InvalidFormat)
    );
}

#[test]
fn strict_and_permit2_reject_v_zero_or_one() {
    let signer = PrivateKeySigner::random();
    let canonical = signed_bytes(&signer);
    for v in [canonical[64] - 27, 0, 1] {
        let mut bytes = canonical;
        bytes[64] = v;
        for rules in [EcdsaRules::Strict, EcdsaRules::Permit2] {
            assert_eq!(
                check(&bytes, signer.address(), rules),
                Err(SignatureCheckError::InvalidFormat)
            );
        }
    }
}

#[test]
fn strict_rejects_other_lengths() {
    for length in [0, 32, 64, 66] {
        assert_eq!(
            check(&vec![0x11; length], Address::ZERO, EcdsaRules::Strict),
            Err(SignatureCheckError::InvalidFormat)
        );
    }
}

/// Permit2 `SignatureVerification` accepts both forms and any `s`.
#[test]
fn permit2_accepts_compact_and_high_s() {
    let signer = PrivateKeySigner::random();
    let canonical = signed_bytes(&signer);
    let address = signer.address();
    assert_eq!(check(&canonical, address, EcdsaRules::Permit2), Ok(()));
    assert_eq!(
        check(&compact(canonical), address, EcdsaRules::Permit2),
        Ok(())
    );
    assert_eq!(
        check(&high_s(canonical), address, EcdsaRules::Permit2),
        Ok(())
    );
}

fn mocked(asserter: Asserter) -> RootProvider<Ethereum> {
    RootProvider::new(RpcClient::mocked(asserter))
}

fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Runtime::new().unwrap().block_on(future)
}

fn run_checker(
    asserter: Asserter,
    signer: &PrivateKeySigner,
) -> Result<SignerCheck, SignatureCheckError> {
    let signature = Bytes::from(signed_bytes(signer).to_vec());
    let signed = SignedDigest {
        signature: &signature,
        digest: DIGEST,
        signer: signer.address(),
    };
    run(check_signature_checker(
        &mocked(asserter),
        &signed,
        EcdsaRules::Strict,
    ))
}

/// An account with code never falls back to ECDSA, even for a valid EOA
/// signature (the EIP-7702 case). The code read is the only RPC call.
#[test]
fn account_with_code_gets_no_local_verdict() {
    let asserter = Asserter::new();
    asserter.push_success(&Bytes::from_static(&[0x60, 0x00]));
    let signer = PrivateKeySigner::random();
    assert_eq!(run_checker(asserter, &signer), Ok(SignerCheck::Contract));
}

#[test]
fn account_without_code_uses_ecdsa() {
    let asserter = Asserter::new();
    asserter.push_success(&Bytes::new());
    let signer = PrivateKeySigner::random();
    assert_eq!(run_checker(asserter, &signer), Ok(SignerCheck::Ecdsa));
}

#[test]
fn code_read_failure_is_an_rpc_error() {
    let asserter = Asserter::new();
    asserter.push_failure_msg("node down");
    let signer = PrivateKeySigner::random();
    assert_eq!(
        run_checker(asserter, &signer),
        Err(SignatureCheckError::RpcReadFailed)
    );
}

fn wallet_reply(push: impl FnOnce(&Asserter)) -> Result<(), SignatureCheckError> {
    let asserter = Asserter::new();
    push(&asserter);
    let signature = Bytes::from(vec![0x11; 65]);
    let signed = SignedDigest {
        signature: &signature,
        digest: DIGEST,
        signer: Address::repeat_byte(0x77),
    };
    run(call_is_valid_signature(&mocked(asserter), &signed))
}

fn magic_word() -> [u8; 32] {
    let mut word = [0u8; 32];
    word[..4].copy_from_slice(&EIP1271_MAGIC_VALUE);
    word
}

#[test]
fn direct_call_accepts_the_padded_magic_word() {
    let result = wallet_reply(|a| a.push_success(&Bytes::from(magic_word().to_vec())));
    assert_eq!(result, Ok(()));
}

/// OZ requires `returndatasize() >= 32` and compares the whole first word.
#[test]
fn direct_call_rejects_a_short_reply_and_dirty_padding() {
    let short = wallet_reply(|a| a.push_success(&Bytes::from_static(&EIP1271_MAGIC_VALUE)));
    assert_eq!(short, Err(SignatureCheckError::InvalidSignature));
    let mut dirty = magic_word();
    dirty[31] = 1;
    let dirty = wallet_reply(|a| a.push_success(&Bytes::from(dirty.to_vec())));
    assert_eq!(dirty, Err(SignatureCheckError::InvalidSignature));
}

#[test]
fn direct_call_treats_an_execution_revert_as_invalid() {
    let revert = serde_json::json!({ "code": 3, "message": "execution reverted", "data": "0x" });
    let result = wallet_reply(|a| a.push_failure(serde_json::from_value(revert).unwrap()));
    assert_eq!(result, Err(SignatureCheckError::InvalidSignature));
}

/// A rate limit or node fault says nothing about the signature.
#[test]
fn direct_call_treats_other_node_errors_as_retryable() {
    for (code, message) in [(429, "too many requests"), (-32603, "internal error")] {
        let payload = serde_json::json!({ "code": code, "message": message });
        let result = wallet_reply(|a| a.push_failure(serde_json::from_value(payload).unwrap()));
        assert_eq!(result, Err(SignatureCheckError::RpcReadFailed));
    }
}
