//! Wire-format payload types for the `batch-settlement` EVM scheme.
//!
//! Every type here round-trips against the canonical JSON the TypeScript and
//! Go reference implementations produce. See
//! `docs/specs/schemes/batch-settlement/scheme_batch_settlement_evm.md`.

use alloy_primitives::{B256, Bytes};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::fmt::{self, Formatter};
use x402_types::lit_str;
use x402_types::proto::v2;

use super::numbers::{U128String, U256String, WithdrawDelay};
use crate::chain::ChecksummedAddress;

lit_str!(BatchSettlementScheme, "batch-settlement");

/// V2 `PaymentRequirements` for batch-settlement payments.
pub type PaymentRequirements = v2::PaymentRequirements<
    BatchSettlementScheme,
    U256String,
    ChecksummedAddress,
    BatchSettlementPaymentRequirementsExtra,
>;

/// V2 `PaymentPayload` that carries any batch-settlement payload variant.
pub type PaymentPayload = v2::PaymentPayload<PaymentRequirements, BatchSettlementPayload>;

/// V2 `VerifyRequest` for batch-settlement payments.
pub type VerifyRequest = v2::VerifyRequest<PaymentPayload, PaymentRequirements>;

/// V2 `SettleRequest`. It has the same shape as the verify request.
pub type SettleRequest = VerifyRequest;

/// Onchain channel snapshot returned in `extra` / `extra.channelState`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelStateExtra {
    pub channel_id: B256,
    pub balance: U128String,
    pub total_claimed: U128String,
    pub withdraw_requested_at: u64,
    pub refund_nonce: U256String,
    /// Server-owned field. The facilitator never sets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charged_cumulative_amount: Option<U128String>,
}

/// Corrective voucher snapshot a server adds to a 402 response. The
/// facilitator only needs to parse it, never to produce it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoucherStateExtra {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_max_claimable: Option<U128String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Bytes>,
}

/// Asset transfer method hint in `PaymentRequirements.extra`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetTransferMethod {
    Eip3009,
    Permit2,
}

impl fmt::Display for AssetTransferMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AssetTransferMethod::Eip3009 => f.write_str("eip3009"),
            AssetTransferMethod::Permit2 => f.write_str("permit2"),
        }
    }
}

/// `PaymentRequirements.extra` for batch-settlement payments.
///
/// Every field is optional on the wire. The SDK channel managers send
/// `extra: {}` for claim, settle, and refund, because the signed payload
/// carries the merchant consent. `/verify` and deposits require a nonzero
/// `receiverAuthorizer` (`receiver_authorizer_mismatch` when it is absent).
/// `withdrawDelay` is compared only when present. `name` and `version` are
/// the token's EIP-712 domain fields; an ERC-3009 deposit without them fails
/// with `missing_eip712_domain`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSettlementPaymentRequirementsExtra {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_authorizer: Option<ChecksummedAddress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdraw_delay: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_transfer_method: Option<AssetTransferMethod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_state: Option<ChannelStateExtra>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voucher_state: Option<VoucherStateExtra>,
}

/// Immutable channel configuration. Its EIP-712 hash is the `channelId`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelConfig {
    pub payer: ChecksummedAddress,
    pub payer_authorizer: ChecksummedAddress,
    pub receiver: ChecksummedAddress,
    pub receiver_authorizer: ChecksummedAddress,
    pub token: ChecksummedAddress,
    pub withdraw_delay: WithdrawDelay,
    pub salt: B256,
}

/// Voucher fields shared by the deposit, voucher, and refund payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoucherFields {
    pub channel_id: B256,
    pub max_claimable_amount: U128String,
    pub signature: Bytes,
}

/// ERC-3009 `ReceiveWithAuthorization` segment of a deposit payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Erc3009Authorization {
    pub valid_after: U256String,
    pub valid_before: U256String,
    pub salt: B256,
    pub signature: Bytes,
}

/// Permit2 authorization segment of a deposit payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Permit2Authorization {
    pub from: ChecksummedAddress,
    pub permitted: Permit2Permitted,
    pub spender: ChecksummedAddress,
    pub nonce: U256String,
    pub deadline: U256String,
    pub witness: Permit2Witness,
    pub signature: Bytes,
}

/// Token permission segment of a Permit2 authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Permit2Permitted {
    pub token: ChecksummedAddress,
    pub amount: U256String,
}

/// Permit2 witness. It binds the authorization to one channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Permit2Witness {
    pub channel_id: B256,
}

/// Deposit authorization. Exactly one variant must be present on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositAuthorization {
    Erc3009(Erc3009Authorization),
    Permit2(Permit2Authorization),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DepositAuthorizationWire<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    erc3009_authorization: Option<&'a Erc3009Authorization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permit2_authorization: Option<&'a Permit2Authorization>,
}

impl Serialize for DepositAuthorization {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = match self {
            DepositAuthorization::Erc3009(auth) => DepositAuthorizationWire {
                erc3009_authorization: Some(auth),
                permit2_authorization: None,
            },
            DepositAuthorization::Permit2(auth) => DepositAuthorizationWire {
                erc3009_authorization: None,
                permit2_authorization: Some(auth),
            },
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DepositAuthorization {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            #[serde(default)]
            erc3009_authorization: Option<Erc3009Authorization>,
            #[serde(default)]
            permit2_authorization: Option<Permit2Authorization>,
        }
        let wire = Wire::deserialize(deserializer)?;
        match (wire.erc3009_authorization, wire.permit2_authorization) {
            (Some(auth), None) => Ok(DepositAuthorization::Erc3009(auth)),
            (None, Some(auth)) => Ok(DepositAuthorization::Permit2(auth)),
            (Some(_), Some(_)) | (None, None) => Err(D::Error::custom(
                "deposit.authorization must hold exactly one of erc3009Authorization \
                 or permit2Authorization",
            )),
        }
    }
}

/// Deposit segment: the amount and how the collector pulls it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositSegment {
    pub amount: U256String,
    pub authorization: DepositAuthorization,
}

/// `type: "deposit"` payload. It funds the channel and carries a voucher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositPayload {
    pub channel_config: ChannelConfig,
    pub voucher: VoucherFields,
    pub deposit: DepositSegment,
}

/// `type: "voucher"` payload. Steady-state cumulative voucher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoucherPayload {
    pub channel_config: ChannelConfig,
    pub voucher: VoucherFields,
}

/// `type: "refund"` payload in its client form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundPayload {
    pub channel_config: ChannelConfig,
    pub voucher: VoucherFields,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<U256String>,
}

/// One claim row for `claim` / `claimWithSignature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoucherClaim {
    pub voucher: VoucherClaimVoucher,
    pub signature: Bytes,
    pub total_claimed: U128String,
}

/// Voucher segment of a claim row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoucherClaimVoucher {
    pub channel: ChannelConfig,
    pub max_claimable_amount: U128String,
}

/// `type: "claim"` settle payload, authored by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimPayload {
    pub claims: Vec<VoucherClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_authorizer_signature: Option<Bytes>,
}

/// `type: "settle"` settle payload, authored by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlePayload {
    pub receiver: ChecksummedAddress,
    pub token: ChecksummedAddress,
}

/// `type: "refund"` settle payload after the server completes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrichedRefundPayload {
    pub channel_config: ChannelConfig,
    pub voucher: VoucherFields,
    pub amount: U256String,
    pub refund_nonce: U256String,
    #[serde(default)]
    pub claims: Vec<VoucherClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund_authorizer_signature: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_authorizer_signature: Option<Bytes>,
}

/// Refund payload variant. The presence of `refundNonce` selects the form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchSettlementRefundPayload {
    Client(RefundPayload),
    Enriched(EnrichedRefundPayload),
}

impl Serialize for BatchSettlementRefundPayload {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            BatchSettlementRefundPayload::Client(payload) => payload.serialize(serializer),
            BatchSettlementRefundPayload::Enriched(payload) => payload.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for BatchSettlementRefundPayload {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Materialize the object once, then dispatch on `refundNonce`. Only the
        // server-completed form carries it.
        let value = serde_json::Value::deserialize(deserializer)?;
        let is_enriched = value
            .as_object()
            .is_some_and(|object| object.contains_key("refundNonce"));
        if is_enriched {
            serde_json::from_value::<EnrichedRefundPayload>(value)
                .map(BatchSettlementRefundPayload::Enriched)
                .map_err(D::Error::custom)
        } else {
            serde_json::from_value::<RefundPayload>(value)
                .map(BatchSettlementRefundPayload::Client)
                .map_err(D::Error::custom)
        }
    }
}

impl BatchSettlementRefundPayload {
    /// The channel config that both refund forms carry.
    pub fn channel_config(&self) -> &ChannelConfig {
        match self {
            BatchSettlementRefundPayload::Client(payload) => &payload.channel_config,
            BatchSettlementRefundPayload::Enriched(payload) => &payload.channel_config,
        }
    }

    /// The voucher that both refund forms carry.
    pub fn voucher(&self) -> &VoucherFields {
        match self {
            BatchSettlementRefundPayload::Client(payload) => &payload.voucher,
            BatchSettlementRefundPayload::Enriched(payload) => &payload.voucher,
        }
    }
}

/// Every payload variant the facilitator accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BatchSettlementPayload {
    Deposit(DepositPayload),
    Voucher(VoucherPayload),
    Refund(BatchSettlementRefundPayload),
    Claim(ClaimPayload),
    Settle(SettlePayload),
}
