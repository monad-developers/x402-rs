//! Facilitator for the V2 EIP-155 `batch-settlement` scheme.
//!
//! The facilitator relays signed operations and pays gas. It holds no
//! receiver-authorizer key: claim and refund payloads must carry the
//! resource server's authorizer signatures, and `/supported` advertises no
//! `receiverAuthorizer`.

pub mod abi;
pub mod channel;
pub mod deposit;
pub mod digest;
mod pending;
pub mod response;
pub mod rpc_error;
pub mod settle;
pub mod signature;
pub mod submit;
pub mod verify;
pub mod voucher;
mod zero_authorizer_log;

pub use digest::{
    batch_settlement_domain, compute_channel_id, compute_claim_batch_digest, compute_refund_digest,
    compute_voucher_digest,
};
pub use response::{
    BatchSettlementSettleExtra, BatchSettlementSettleResponse, BatchSettlementVerifyExtra,
    BatchSettlementVerifyResponse,
};

use std::collections::HashMap;

use alloy_primitives::Address;
use alloy_provider::Provider;
use rand::seq::IndexedRandom;
use serde::Deserialize;
use x402_types::chain::ChainProviderOps;
use x402_types::proto::{self, PaymentVerificationError, v2};
use x402_types::scheme::{
    X402SchemeFacilitator, X402SchemeFacilitatorBuilder, X402SchemeFacilitatorError,
};

use crate::V2Eip155BatchSettlement;
use crate::chain::{
    Eip155MetaTransactionProvider, Eip155SignerAddresses, MetaTransactionSendError,
};
use crate::v2_eip155_batch_settlement::types::{
    BatchSettlementScheme, SettleRequest, VerifyRequest,
};
use pending::PendingDeposits;
use submit::SettleContext;
use verify::VerifyContext;

/// Scheme configuration. It has no fields. Any key fails `build`, so the
/// registry registers no handler rather than ignore a stale authorizer key
/// or feature flag.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct V2Eip155BatchSettlementConfig {}

impl<P> X402SchemeFacilitatorBuilder<P> for V2Eip155BatchSettlement
where
    P: Eip155MetaTransactionProvider
        + ChainProviderOps
        + Eip155SignerAddresses
        + Send
        + Sync
        + 'static,
    P::Inner: Provider,
    P::Error: Into<MetaTransactionSendError>,
{
    fn build(
        &self,
        provider: P,
        config: Option<serde_json::Value>,
    ) -> Result<Box<dyn X402SchemeFacilitator>, Box<dyn std::error::Error>> {
        if let Some(config) = config.filter(|value| !value.is_null()) {
            V2Eip155BatchSettlementConfig::deserialize(config)
                .map_err(|e| format!("invalid v2-eip155-batch-settlement config: {e}"))?;
        }
        Ok(Box::new(V2Eip155BatchSettlementFacilitator::new(provider)))
    }
}

pub struct V2Eip155BatchSettlementFacilitator<P> {
    provider: P,
    pending: PendingDeposits,
}

impl<P> V2Eip155BatchSettlementFacilitator<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            pending: PendingDeposits::default(),
        }
    }
}

impl<P> V2Eip155BatchSettlementFacilitator<P>
where
    P: Eip155MetaTransactionProvider + Eip155SignerAddresses,
{
    fn chain_id(&self) -> u64 {
        self.provider.chain().inner()
    }

    /// Simulation and broadcast use the same randomly chosen signer.
    fn sender(&self) -> Result<Address, X402SchemeFacilitatorError> {
        self.provider
            .signer_addresses()
            .choose(&mut rand::rng())
            .copied()
            .ok_or_else(|| X402SchemeFacilitatorError::OnchainFailure("no signer".into()))
    }
}

#[async_trait::async_trait]
impl<P> X402SchemeFacilitator for V2Eip155BatchSettlementFacilitator<P>
where
    P: Eip155MetaTransactionProvider + ChainProviderOps + Eip155SignerAddresses + Send + Sync,
    P::Inner: Provider,
    P::Error: Into<MetaTransactionSendError>,
{
    async fn verify(
        &self,
        request: &proto::VerifyRequest,
    ) -> Result<proto::VerifyResponse, X402SchemeFacilitatorError> {
        let request = parse::<VerifyRequest>(request.as_str())?;
        let context = VerifyContext {
            chain_id: self.chain_id(),
            sender: self.sender()?,
        };
        let payload = &request.payment_payload;
        let requirements = &request.payment_requirements;
        let response = verify::verify(self.provider.inner(), context, payload, requirements).await;
        zero_authorizer_log::log_verify(context.chain_id, &payload.payload, &response);
        Ok(response.into())
    }

    async fn settle(
        &self,
        request: &proto::SettleRequest,
    ) -> Result<proto::SettleResponse, X402SchemeFacilitatorError> {
        let request = parse::<SettleRequest>(request.as_str())?;
        let network = request.payment_requirements.network.to_string();
        let context = SettleContext {
            provider: &self.provider,
            chain_id: self.chain_id(),
            network: &network,
            sender: self.sender()?,
        };
        let payload = &request.payment_payload;
        let requirements = &request.payment_requirements;
        let response = settle::settle(&context, &self.pending, payload, requirements).await;
        zero_authorizer_log::log_settle(context.chain_id, &payload.payload, &response);
        Ok(response.into())
    }

    async fn supported(&self) -> Result<proto::SupportedResponse, X402SchemeFacilitatorError> {
        let chain_id = self.provider.chain_id();
        let kinds = vec![proto::SupportedPaymentKind {
            x402_version: v2::X402Version2.into(),
            scheme: BatchSettlementScheme.to_string(),
            network: chain_id.clone().into(),
            extra: None,
        }];
        let signers =
            HashMap::from([(chain_id, ChainProviderOps::signer_addresses(&self.provider))]);
        Ok(proto::SupportedResponse {
            kinds,
            extensions: Vec::new(),
            signers,
        })
    }
}

/// Parses a request body. Unknown payload shapes are a verification error,
/// not a facilitator fault.
fn parse<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T, X402SchemeFacilitatorError> {
    serde_json::from_str(raw)
        .map_err(|e| PaymentVerificationError::InvalidFormat(e.to_string()).into())
}
