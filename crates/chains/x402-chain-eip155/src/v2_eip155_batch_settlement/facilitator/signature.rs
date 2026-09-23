//! Signature checks with onchain parity.
//!
//! - [`EcdsaRules::Strict`]: OpenZeppelin `ECDSA` (pinned at
//!   `fcbae539`) and Circle FiatToken `ECRecover`. 65 bytes only, `v` in
//!   {27, 28}, low `s`. Noncanonical signatures are rejected, never normalized,
//!   because the contract rejects them.
//! - [`EcdsaRules::Permit2`]: Permit2 `SignatureVerification`. 65 or 64
//!   (ERC-2098) bytes, any `s`, `v` in {27, 28}.
//! - A signer with code: no local verdict. The contract calls ERC-1271 from
//!   its own address in a static context, so a canonical simulation decides
//!   (see [`SignerCheck::Contract`]). No ERC-6492 unwrap.

use alloy_primitives::{Address, B256, Bytes, Signature, U256, uint};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::SolCall;

use super::abi::{EIP1271_MAGIC_VALUE, isValidSignatureCall};
use super::rpc_error::{as_revert, log_rpc_error};

/// secp256k1 order / 2. OZ rejects any `s` above it.
const HALF_ORDER: U256 =
    uint!(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0_U256);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureCheckError {
    InvalidFormat,
    InvalidSignature,
    RpcReadFailed,
}

/// Which ECDSA verifier the target contract uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaRules {
    Strict,
    Permit2,
}

/// A digest, its signature, and the address that must have signed it.
#[derive(Debug, Clone, Copy)]
pub struct SignedDigest<'a> {
    pub signature: &'a Bytes,
    pub digest: B256,
    pub signer: Address,
}

/// ECDSA recovery under the given rules. No code check, no ERC-1271 route.
pub fn verify_ecdsa(
    signed: &SignedDigest<'_>,
    rules: EcdsaRules,
) -> Result<(), SignatureCheckError> {
    let signature = match rules {
        EcdsaRules::Strict => parse_strict(signed.signature)?,
        EcdsaRules::Permit2 => parse_permit2(signed.signature)?,
    };
    let recovered = signature
        .recover_address_from_prehash(&signed.digest)
        .map_err(|_| SignatureCheckError::InvalidSignature)?;
    if recovered == signed.signer {
        Ok(())
    } else {
        Err(SignatureCheckError::InvalidSignature)
    }
}

fn parse_strict(bytes: &[u8]) -> Result<Signature, SignatureCheckError> {
    if bytes.len() != 65 {
        return Err(SignatureCheckError::InvalidFormat);
    }
    let parity = v_parity(bytes[64])?;
    let s = U256::from_be_slice(&bytes[32..64]);
    if s > HALF_ORDER {
        return Err(SignatureCheckError::InvalidFormat);
    }
    Ok(Signature::new(U256::from_be_slice(&bytes[..32]), s, parity))
}

fn parse_permit2(bytes: &[u8]) -> Result<Signature, SignatureCheckError> {
    let signature = match bytes.len() {
        65 => Signature::new(
            U256::from_be_slice(&bytes[..32]),
            U256::from_be_slice(&bytes[32..64]),
            v_parity(bytes[64])?,
        ),
        64 => Signature::from_erc2098(bytes),
        _ => return Err(SignatureCheckError::InvalidFormat),
    };
    // Permit2 accepts high `s`; the local recovery library does not.
    Ok(signature.normalized_s())
}

/// `ecrecover` returns zero for any `v` outside {27, 28}.
fn v_parity(v: u8) -> Result<bool, SignatureCheckError> {
    match v {
        27 => Ok(false),
        28 => Ok(true),
        _ => Err(SignatureCheckError::InvalidFormat),
    }
}

/// What a local check proves about a `SignatureChecker`-style signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerCheck {
    /// The signer has no code, and the ECDSA signature is valid.
    Ecdsa,
    /// The signer has code (a contract or an EIP-7702 account). Onchain, the
    /// verifier contract `STATICCALL`s its ERC-1271 function, so only a
    /// canonical simulation of the contract call can decide.
    Contract,
}

/// `isValidSignatureNow` up to its ERC-1271 branch: ECDSA when `signer` has
/// no code. A signer with code never falls back to ECDSA.
pub async fn check_signature_checker<P: Provider>(
    provider: &P,
    signed: &SignedDigest<'_>,
    rules: EcdsaRules,
) -> Result<SignerCheck, SignatureCheckError> {
    let code = provider.get_code_at(signed.signer).await.map_err(|error| {
        log_rpc_error(&error);
        SignatureCheckError::RpcReadFailed
    })?;
    if code.is_empty() {
        return verify_ecdsa(signed, rules).map(|()| SignerCheck::Ecdsa);
    }
    Ok(SignerCheck::Contract)
}

/// A top-level `isValidSignature` call to the wallet. It has no contract
/// caller and no static context, so it is not the onchain check. Use it only
/// for a signature that no contract call ever checks.
pub async fn call_is_valid_signature<P: Provider>(
    provider: &P,
    signed: &SignedDigest<'_>,
) -> Result<(), SignatureCheckError> {
    let calldata = isValidSignatureCall {
        hash: signed.digest,
        signature: signed.signature.clone(),
    }
    .abi_encode();
    let request = TransactionRequest::default()
        .input(calldata.into())
        .to(signed.signer);
    match provider.call(request).await {
        Ok(returned) if is_eip1271_magic_word(&returned) => Ok(()),
        Ok(_) => Err(SignatureCheckError::InvalidSignature),
        Err(error) if as_revert(&error).is_some() => Err(SignatureCheckError::InvalidSignature),
        Err(error) => {
            log_rpc_error(&error);
            Err(SignatureCheckError::RpcReadFailed)
        }
    }
}

/// At least 32 return bytes, and the first word equal to the right-padded
/// magic value, as the OZ assembly and the Permit2 `bytes4` decode require.
fn is_eip1271_magic_word(returned: &[u8]) -> bool {
    let mut expected = [0u8; 32];
    expected[..4].copy_from_slice(&EIP1271_MAGIC_VALUE);
    returned.len() >= 32 && returned[..32] == expected
}

#[cfg(test)]
#[path = "signature_tests.rs"]
mod tests;
