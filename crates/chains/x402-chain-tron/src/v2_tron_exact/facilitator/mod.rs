//! Facilitator implementation for V2 TRON "exact" payment scheme.

pub mod eip3009;
pub mod permit2;

use std::collections::HashMap;

use x402_types::chain::ChainProviderOps;
use x402_types::proto;
use x402_types::proto::v2;
use x402_types::scheme::{
    X402SchemeFacilitator, X402SchemeFacilitatorBuilder, X402SchemeFacilitatorError,
};
#[cfg(feature = "telemetry")]
use x402_types::util::telemetry::record_payment_context;

use crate::V2TronExact;
use crate::chain::TronAddress;
use crate::chain::provider::TronChainProviderLike;
use crate::chain::tron_grid::WaitForTxLike;
use crate::v2_tron_exact::ExactScheme;
use crate::v2_tron_exact::types::{FacilitatorSettleRequest, FacilitatorVerifyRequest};

#[cfg(feature = "telemetry")]
fn tron_payer(address: alloy_primitives::Address) -> String {
    let tron_address = TronAddress::from(address);
    tron_address.to_string()
}

impl<P> X402SchemeFacilitatorBuilder<P> for V2TronExact
where
    P: TronChainProviderLike + WaitForTxLike + ChainProviderOps + Send + Sync + 'static,
{
    fn build(
        &self,
        provider: P,
        _config: Option<serde_json::Value>,
    ) -> Result<Box<dyn X402SchemeFacilitator>, Box<dyn std::error::Error>> {
        Ok(Box::new(V2TronExactFacilitator { provider }))
    }
}

/// Facilitator for the V2 TRON "exact" payment scheme.
pub struct V2TronExactFacilitator<P> {
    /// The chain provider used for on-chain reads and settlement.
    pub provider: P,
}

#[async_trait::async_trait]
impl<P> X402SchemeFacilitator for V2TronExactFacilitator<P>
where
    P: TronChainProviderLike + WaitForTxLike + ChainProviderOps + Send + Sync,
{
    #[cfg_attr(feature = "telemetry", tracing::instrument(skip_all, err, fields(
        otel.kind = "internal",
        chain_id = tracing::field::Empty,
        payer = tracing::field::Empty,
        pay_to = tracing::field::Empty
    )))]
    async fn verify(
        &self,
        request: &proto::VerifyRequest,
    ) -> Result<proto::VerifyResponse, X402SchemeFacilitatorError> {
        let verify_request = FacilitatorVerifyRequest::try_from(request.clone())?;
        let verify_response = match verify_request {
            FacilitatorVerifyRequest::Eip3009 {
                payment_payload,
                payment_requirements,
                x402_version: _,
            } => {
                #[cfg(feature = "telemetry")]
                record_payment_context(
                    &payment_payload.accepted.network,
                    tron_payer(payment_payload.payload.authorization.from),
                    payment_requirements.pay_to,
                );
                eip3009::verify_eip3009_payment(
                    &self.provider,
                    &payment_payload,
                    &payment_requirements,
                )
                .await?
            }
            FacilitatorVerifyRequest::Permit2 {
                payment_payload,
                payment_requirements,
                x402_version: _,
            } => {
                #[cfg(feature = "telemetry")]
                {
                    let authorization = &payment_payload.payload.permit2_authorization;
                    record_payment_context(
                        &payment_payload.accepted.network,
                        tron_payer(authorization.from),
                        payment_requirements.pay_to,
                    );
                }
                permit2::verify_permit2_payment(
                    &self.provider,
                    &payment_payload,
                    &payment_requirements,
                )
                .await?
            }
        };
        Ok(verify_response.into())
    }

    #[cfg_attr(feature = "telemetry", tracing::instrument(skip_all, err, fields(
        otel.kind = "internal",
        chain_id = tracing::field::Empty,
        payer = tracing::field::Empty,
        pay_to = tracing::field::Empty
    )))]
    async fn settle(
        &self,
        request: &proto::SettleRequest,
    ) -> Result<proto::SettleResponse, X402SchemeFacilitatorError> {
        let settle_request = FacilitatorSettleRequest::try_from(request.clone())?;
        let settle_response = match settle_request {
            FacilitatorSettleRequest::Eip3009 {
                payment_payload,
                payment_requirements,
                x402_version: _,
            } => {
                #[cfg(feature = "telemetry")]
                record_payment_context(
                    &payment_payload.accepted.network,
                    tron_payer(payment_payload.payload.authorization.from),
                    payment_requirements.pay_to,
                );
                eip3009::settle_eip3009_payment(
                    &self.provider,
                    &payment_payload,
                    &payment_requirements,
                )
                .await?
            }
            FacilitatorSettleRequest::Permit2 {
                payment_payload,
                payment_requirements,
                x402_version: _,
            } => {
                #[cfg(feature = "telemetry")]
                {
                    let authorization = &payment_payload.payload.permit2_authorization;
                    record_payment_context(
                        &payment_payload.accepted.network,
                        tron_payer(authorization.from),
                        payment_requirements.pay_to,
                    );
                }
                permit2::settle_permit2_payment(
                    &self.provider,
                    &payment_payload,
                    &payment_requirements,
                )
                .await?
            }
        };
        Ok(settle_response.into())
    }

    async fn supported(&self) -> Result<proto::SupportedResponse, X402SchemeFacilitatorError> {
        let chain_id = self.provider.chain().chain_id();
        let kinds = vec![proto::SupportedPaymentKind {
            x402_version: v2::X402Version2.into(),
            scheme: ExactScheme.to_string(),
            network: chain_id.clone().into(),
            extra: None,
        }];
        let mut signers = HashMap::new();
        signers.insert(chain_id, self.provider.signer_addresses());
        Ok(proto::SupportedResponse {
            kinds,
            extensions: vec![],
            signers,
        })
    }
}
