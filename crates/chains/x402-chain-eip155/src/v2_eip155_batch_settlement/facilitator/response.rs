//! Verify and settle response bodies for the batch-settlement scheme.
//!
//! The shared `proto` response types carry no `extra` slot, so the scheme
//! serializes its own shapes and wraps them the same way the `upto` scheme
//! does. The field names match the spec examples exactly.

use alloy_primitives::{Address, B256, TxHash};
use serde::{Deserialize, Serialize};
use x402_types::proto;

use super::channel::OnchainChannelState;
use crate::v2_eip155_batch_settlement::errors as err;
use crate::v2_eip155_batch_settlement::types::{ChannelStateExtra, U128String, U256String};

/// Channel snapshot returned in a verify response `extra`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSettlementVerifyExtra {
    pub channel_id: B256,
    pub balance: U128String,
    pub total_claimed: U128String,
    pub withdraw_requested_at: u64,
    pub refund_nonce: U256String,
}

impl BatchSettlementVerifyExtra {
    pub fn from_state(channel_id: B256, state: &OnchainChannelState) -> Self {
        Self {
            channel_id,
            balance: state.balance.into(),
            total_claimed: state.total_claimed.into(),
            withdraw_requested_at: state.withdraw_requested_at,
            refund_nonce: state.refund_nonce.into(),
        }
    }
}

/// Channel snapshot returned in a settle response `extra`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSettlementSettleExtra {
    pub channel_state: ChannelStateExtra,
}

impl BatchSettlementSettleExtra {
    pub fn from_state(channel_id: B256, state: &OnchainChannelState) -> Self {
        Self {
            channel_state: ChannelStateExtra {
                channel_id,
                balance: state.balance.into(),
                total_claimed: state.total_claimed.into(),
                withdraw_requested_at: state.withdraw_requested_at,
                refund_nonce: state.refund_nonce.into(),
                // The server owns the cumulative charge. The facilitator holds
                // no per-channel state and must not invent one.
                charged_cumulative_amount: None,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSettlementVerifyResponse {
    pub is_valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalid_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BatchSettlementVerifyExtra>,
}

impl BatchSettlementVerifyResponse {
    /// A valid payload, with the channel snapshot the server mirrors.
    pub fn valid(payer: Address, extra: BatchSettlementVerifyExtra) -> Self {
        Self {
            is_valid: true,
            payer: Some(payer.to_checksum(None)),
            invalid_reason: None,
            invalid_message: None,
            extra: Some(extra),
        }
    }

    pub fn invalid(payer: Option<Address>, reason: &str) -> Self {
        Self {
            is_valid: false,
            payer: payer.map(|address| address.to_checksum(None)),
            invalid_reason: Some(reason.to_string()),
            invalid_message: None,
            extra: None,
        }
    }

    /// A rejected payload with a free-form diagnostic message.
    pub fn invalid_with_message(payer: Option<Address>, reason: &str, message: String) -> Self {
        Self {
            invalid_message: Some(message),
            ..Self::invalid(payer, reason)
        }
    }
}

impl From<BatchSettlementVerifyResponse> for proto::VerifyResponse {
    fn from(value: BatchSettlementVerifyResponse) -> Self {
        proto::VerifyResponse(
            serde_json::to_value(value).expect("verify response serialization cannot fail"),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSettlementSettleResponse {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub transaction: String,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    pub amount: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BatchSettlementSettleExtra>,
}

impl BatchSettlementSettleResponse {
    /// A settlement that did not happen. The transaction field stays empty.
    pub fn failure(network: &str, reason: &str) -> Self {
        Self {
            success: false,
            error_reason: Some(reason.to_string()),
            error_message: None,
            transaction: String::new(),
            network: network.to_string(),
            payer: None,
            amount: String::new(),
            asset: None,
            extra: None,
        }
    }

    /// A settlement that did not happen, with a diagnostic message.
    pub fn failure_with_message(network: &str, reason: &str, message: String) -> Self {
        Self {
            error_message: Some(message),
            ..Self::failure(network, reason)
        }
    }

    /// A transaction that was mined and reverted, or that produced no success
    /// event. The hash is kept so the caller can inspect the mined
    /// transaction instead of re-submitting a payload that already landed.
    pub fn mined_failure(
        network: &str,
        reason: &str,
        transaction: TxHash,
        message: String,
    ) -> Self {
        Self {
            transaction: format!("{transaction:#x}"),
            ..Self::failure_with_message(network, reason, message)
        }
    }

    /// A transaction that was broadcast but whose receipt never arrived.
    ///
    /// The hash lets the caller reconcile. Deposits use the in-process retry
    /// record. Other operations need a receipt check before another submission.
    pub fn settlement_pending(network: &str, transaction: TxHash, message: String) -> Self {
        Self::mined_failure(network, err::ERR_SETTLEMENT_PENDING, transaction, message)
    }

    pub fn success(network: &str, transaction: TxHash, amount: String) -> Self {
        Self {
            success: true,
            error_reason: None,
            error_message: None,
            transaction: format!("{transaction:#x}"),
            network: network.to_string(),
            payer: None,
            amount,
            asset: None,
            extra: None,
        }
    }

    /// The chain is already in the goal state, so nothing was broadcast. The
    /// transaction field stays empty.
    pub fn success_without_transaction(network: &str, amount: String) -> Self {
        Self {
            transaction: String::new(),
            ..Self::success(network, TxHash::ZERO, amount)
        }
    }

    pub fn with_payer(mut self, payer: Address) -> Self {
        self.payer = Some(payer.to_checksum(None));
        self
    }

    pub fn with_asset(mut self, asset: Address) -> Self {
        self.asset = Some(asset.to_checksum(None));
        self
    }

    pub fn with_channel_state(mut self, extra: BatchSettlementSettleExtra) -> Self {
        self.extra = Some(extra);
        self
    }

    /// Records that the post-transaction snapshot could not be read. The
    /// settlement still succeeded, so the caller must re-read channel state
    /// rather than treat the missing snapshot as a failure.
    pub fn without_channel_state(mut self, reason: &str) -> Self {
        self.error_message = Some(format!("channel state snapshot unavailable: {reason}"));
        self
    }
}

impl From<BatchSettlementSettleResponse> for proto::SettleResponse {
    fn from(value: BatchSettlementSettleResponse) -> Self {
        proto::SettleResponse(
            serde_json::to_value(value).expect("settle response serialization cannot fail"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{U128, U256};

    fn state() -> OnchainChannelState {
        OnchainChannelState {
            balance: U128::from(100_000u128),
            total_claimed: U128::from(3_200u128),
            withdraw_requested_at: 0,
            refund_nonce: U256::from(1u64),
        }
    }

    #[test]
    fn verify_success_carries_the_channel_snapshot_as_decimal_strings() {
        let extra = BatchSettlementVerifyExtra::from_state(B256::repeat_byte(0xaa), &state());
        let response = BatchSettlementVerifyResponse::valid(Address::repeat_byte(0x11), extra);
        let encoded = serde_json::to_value(response).unwrap();
        assert_eq!(encoded["isValid"], true);
        assert_eq!(encoded["extra"]["balance"], "100000");
        assert_eq!(encoded["extra"]["totalClaimed"], "3200");
        assert_eq!(encoded["extra"]["refundNonce"], "1");
        assert_eq!(encoded["extra"]["withdrawRequestedAt"], 0);
    }

    #[test]
    fn verify_failure_omits_the_channel_snapshot() {
        let response = BatchSettlementVerifyResponse::invalid(
            Some(Address::repeat_byte(0x11)),
            err::ERR_INVALID_VOUCHER_SIGNATURE,
        );
        let encoded = serde_json::to_value(response).unwrap();
        assert_eq!(encoded["isValid"], false);
        assert_eq!(
            encoded["invalidReason"],
            "invalid_batch_settlement_evm_voucher_signature"
        );
        assert!(encoded.get("extra").is_none());
    }

    #[test]
    fn settle_failure_has_no_transaction_hash() {
        let response =
            BatchSettlementSettleResponse::failure("eip155:143", err::ERR_NOTHING_TO_SETTLE);
        let encoded = serde_json::to_value(response).unwrap();
        assert_eq!(encoded["success"], false);
        assert_eq!(encoded["transaction"], "");
        assert_eq!(encoded["amount"], "");
        assert_eq!(encoded["network"], "eip155:143");
    }

    /// A mined revert keeps its hash. Without it the caller cannot tell a
    /// transaction that never left from one that landed and failed.
    #[test]
    fn mined_failure_keeps_the_transaction_hash() {
        let hash = TxHash::repeat_byte(0xab);
        let response = BatchSettlementSettleResponse::mined_failure(
            "eip155:143",
            err::ERR_REFUND_TRANSACTION_FAILED,
            hash,
            "reverted".into(),
        );
        let encoded = serde_json::to_value(response).unwrap();
        assert_eq!(encoded["success"], false);
        assert_eq!(encoded["transaction"], format!("{hash:#x}"));
    }

    #[test]
    fn settlement_pending_reports_the_broadcast_hash() {
        let hash = TxHash::repeat_byte(0xcd);
        let response = BatchSettlementSettleResponse::settlement_pending(
            "eip155:143",
            hash,
            "receipt timed out".into(),
        );
        let encoded = serde_json::to_value(response).unwrap();
        assert_eq!(encoded["errorReason"], "settlement_pending");
        assert_eq!(encoded["transaction"], format!("{hash:#x}"));
    }

    #[test]
    fn settle_success_carries_the_snapshot_and_the_payer() {
        let response = BatchSettlementSettleResponse::success(
            "eip155:143",
            TxHash::repeat_byte(0x01),
            "1500".into(),
        )
        .with_payer(Address::repeat_byte(0x22))
        .with_channel_state(BatchSettlementSettleExtra::from_state(
            B256::repeat_byte(0xab),
            &state(),
        ));
        let encoded = serde_json::to_value(response).unwrap();
        assert_eq!(encoded["success"], true);
        assert_eq!(encoded["amount"], "1500");
        assert_eq!(encoded["extra"]["channelState"]["balance"], "100000");
        assert!(encoded["extra"]["channelState"]["chargedCumulativeAmount"].is_null());
        assert!(encoded["payer"].is_string());
    }
}
