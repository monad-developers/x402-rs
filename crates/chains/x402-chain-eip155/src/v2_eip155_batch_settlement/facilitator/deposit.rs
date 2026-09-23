//! Deposit authorization checks and deposit calldata.
//!
//! Supported: ERC-3009 through `ERC3009DepositCollector`, and Permit2 through
//! `Permit2DepositCollector` with a standing Permit2 allowance. Sponsored
//! approvals (EIP-2612, relayed ERC-20 approve) are not supported; such a
//! payload fails the allowance check or the deposit simulation.

use alloy_primitives::{Address, B256, Bytes, U128, U256};
use alloy_provider::Provider;
use alloy_sol_types::{SolCall, SolStruct, eip712_domain};

use super::abi::{
    DepositWitness, IERC20View, PermitWitnessTransferFrom, ReceiveWithAuthorization,
    TokenPermissions, X402BatchSettlement::depositCall,
};
use super::digest::to_abi_channel_config;
use super::signature::{
    EcdsaRules, SignatureCheckError, SignedDigest, SignerCheck, check_signature_checker,
};
use crate::chain::permit2::PERMIT2_ADDRESS;
use crate::v2_eip155_batch_settlement::constants::{
    ERC3009_DEPOSIT_COLLECTOR_ADDRESS, EXPIRY_GRACE_SECONDS, PERMIT2_DEPOSIT_COLLECTOR_ADDRESS,
};
use crate::v2_eip155_batch_settlement::encoding::{
    build_erc3009_collector_data, build_erc3009_deposit_nonce, build_permit2_collector_data,
};
use crate::v2_eip155_batch_settlement::errors as err;
use crate::v2_eip155_batch_settlement::types::{
    AssetTransferMethod, DepositAuthorization, DepositPayload, Erc3009Authorization,
    PaymentRequirements, Permit2Authorization,
};

/// Inputs shared by the deposit authorization checks.
#[derive(Clone, Copy)]
pub struct DepositCheck<'a> {
    pub payload: &'a DepositPayload,
    pub requirements: &'a PaymentRequirements,
    pub chain_id: u64,
}

impl DepositCheck<'_> {
    fn payer(&self) -> Address {
        self.payload.channel_config.payer.into()
    }

    fn token(&self) -> Address {
        self.requirements.asset.into()
    }
}

/// Checks the deposit authorization against the transfer-method hint.
pub async fn verify_deposit_authorization<P: Provider>(
    provider: &P,
    check: DepositCheck<'_>,
) -> Result<(), &'static str> {
    let hint = check.requirements.extra.asset_transfer_method;
    match &check.payload.deposit.authorization {
        DepositAuthorization::Erc3009(_) if hint == Some(AssetTransferMethod::Permit2) => {
            Err(err::ERR_PERMIT2_AUTHORIZATION_REQUIRED)
        }
        DepositAuthorization::Permit2(_) if hint == Some(AssetTransferMethod::Eip3009) => {
            Err(err::ERR_ERC3009_AUTHORIZATION_REQUIRED)
        }
        DepositAuthorization::Erc3009(auth) => verify_erc3009(provider, check, auth).await,
        DepositAuthorization::Permit2(auth) => verify_permit2(provider, check, auth).await,
    }
}

async fn verify_erc3009<P: Provider>(
    provider: &P,
    check: DepositCheck<'_>,
    auth: &Erc3009Authorization,
) -> Result<(), &'static str> {
    let extra = &check.requirements.extra;
    let (Some(name), Some(version)) = (&extra.name, &extra.version) else {
        return Err(err::ERR_MISSING_EIP712_DOMAIN);
    };
    assert_authorization_window(auth.valid_after.0, auth.valid_before.0)?;

    let authorization = ReceiveWithAuthorization {
        from: check.payer(),
        to: ERC3009_DEPOSIT_COLLECTOR_ADDRESS,
        value: check.payload.deposit.amount.0,
        validAfter: auth.valid_after.0,
        validBefore: auth.valid_before.0,
        nonce: build_erc3009_deposit_nonce(check.payload.voucher.channel_id, auth.salt),
    };
    let domain = eip712_domain! {
        name: name.clone(),
        version: version.clone(),
        chain_id: check.chain_id,
        verifying_contract: check.token(),
    };
    let signed = SignedDigest {
        signature: &auth.signature,
        digest: authorization.eip712_signing_hash(&domain),
        signer: check.payer(),
    };
    // FiatToken `ECRecover` has the same rules as OZ `ECDSA`.
    let invalid = err::ERR_INVALID_RECEIVE_AUTHORIZATION_SIGNATURE;
    check_payer_signature(provider, &signed, EcdsaRules::Strict, invalid).await
}

/// A payer with code gets no local verdict. The token or Permit2 checks its
/// ERC-1271 signature inside the deposit simulation, which runs before any
/// broadcast.
async fn check_payer_signature<P: Provider>(
    provider: &P,
    signed: &SignedDigest<'_>,
    rules: EcdsaRules,
    invalid: &'static str,
) -> Result<(), &'static str> {
    match check_signature_checker(provider, signed, rules).await {
        Ok(SignerCheck::Ecdsa | SignerCheck::Contract) => Ok(()),
        Err(SignatureCheckError::RpcReadFailed) => Err(err::ERR_RPC_READ_FAILED),
        Err(SignatureCheckError::InvalidFormat | SignatureCheckError::InvalidSignature) => {
            Err(invalid)
        }
    }
}

async fn verify_permit2<P: Provider>(
    provider: &P,
    check: DepositCheck<'_>,
    auth: &Permit2Authorization,
) -> Result<(), &'static str> {
    assert_permit2_fields(check, auth)?;
    assert_not_expired(auth.deadline.0, err::ERR_PERMIT2_DEADLINE_EXPIRED)?;
    let signed = SignedDigest {
        signature: &auth.signature,
        digest: permit2_digest(check, auth),
        signer: check.payer(),
    };
    let invalid = err::ERR_PERMIT2_INVALID_SIGNATURE;
    check_payer_signature(provider, &signed, EcdsaRules::Permit2, invalid).await?;

    let allowance = IERC20View::new(check.token(), provider)
        .allowance(check.payer(), PERMIT2_ADDRESS)
        .call()
        .await
        .map_err(|_| err::ERR_RPC_READ_FAILED)?;
    if allowance < check.payload.deposit.amount.0 {
        return Err(err::ERR_PERMIT2_ALLOWANCE_REQUIRED);
    }
    Ok(())
}

fn permit2_digest(check: DepositCheck<'_>, auth: &Permit2Authorization) -> B256 {
    let permit = PermitWitnessTransferFrom {
        permitted: TokenPermissions {
            token: check.token(),
            amount: check.payload.deposit.amount.0,
        },
        spender: PERMIT2_DEPOSIT_COLLECTOR_ADDRESS,
        nonce: auth.nonce.0,
        deadline: auth.deadline.0,
        witness: DepositWitness {
            channelId: check.payload.voucher.channel_id,
        },
    };
    let domain = eip712_domain! {
        name: "Permit2",
        chain_id: check.chain_id,
        verifying_contract: PERMIT2_ADDRESS,
    };
    permit.eip712_signing_hash(&domain)
}

fn assert_permit2_fields(
    check: DepositCheck<'_>,
    auth: &Permit2Authorization,
) -> Result<(), &'static str> {
    if Address::from(auth.from) != check.payer() {
        return Err(err::ERR_DEPOSIT_PAYLOAD);
    }
    if Address::from(auth.spender) != PERMIT2_DEPOSIT_COLLECTOR_ADDRESS {
        return Err(err::ERR_PERMIT2_INVALID_SPENDER);
    }
    if Address::from(auth.permitted.token) != check.token() {
        return Err(err::ERR_TOKEN_MISMATCH);
    }
    // The collector pulls exactly the deposit amount.
    if auth.permitted.amount.0 != check.payload.deposit.amount.0 {
        return Err(err::ERR_PERMIT2_AMOUNT_MISMATCH);
    }
    if auth.witness.channel_id != check.payload.voucher.channel_id {
        return Err(err::ERR_CHANNEL_ID_MISMATCH);
    }
    Ok(())
}

fn assert_authorization_window(valid_after: U256, valid_before: U256) -> Result<(), &'static str> {
    assert_not_expired(valid_before, err::ERR_VALID_BEFORE_EXPIRED)?;
    if valid_after > U256::from(now_seconds()) {
        return Err(err::ERR_VALID_AFTER_IN_FUTURE);
    }
    Ok(())
}

fn assert_not_expired(deadline: U256, reason: &'static str) -> Result<(), &'static str> {
    if deadline < U256::from(now_seconds() + EXPIRY_GRACE_SECONDS) {
        return Err(reason);
    }
    Ok(())
}

fn now_seconds() -> u64 {
    x402_types::timestamp::UnixTimestamp::now().as_secs()
}

pub fn deposit_collector(authorization: &DepositAuthorization) -> Address {
    match authorization {
        DepositAuthorization::Erc3009(_) => ERC3009_DEPOSIT_COLLECTOR_ADDRESS,
        DepositAuthorization::Permit2(_) => PERMIT2_DEPOSIT_COLLECTOR_ADDRESS,
    }
}

/// Collector payload. Signatures pass through unchanged: what was verified
/// is exactly what the collector receives.
pub fn deposit_collector_data(authorization: &DepositAuthorization) -> Bytes {
    match authorization {
        DepositAuthorization::Erc3009(auth) => build_erc3009_collector_data(
            auth.valid_after.0,
            auth.valid_before.0,
            auth.salt,
            &auth.signature,
        ),
        DepositAuthorization::Permit2(auth) => {
            build_permit2_collector_data(auth.nonce.0, auth.deadline.0, &auth.signature)
        }
    }
}

/// Encodes `deposit(config, amount, collector, collectorData)`.
pub fn build_deposit_calldata(payload: &DepositPayload, amount: U128) -> Bytes {
    depositCall {
        config: to_abi_channel_config(&payload.channel_config),
        amount: amount.to::<u128>(),
        collector: deposit_collector(&payload.deposit.authorization),
        collectorData: deposit_collector_data(&payload.deposit.authorization),
    }
    .abi_encode()
    .into()
}

#[cfg(test)]
#[path = "deposit_tests.rs"]
mod tests;
