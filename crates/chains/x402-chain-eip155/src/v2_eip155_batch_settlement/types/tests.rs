//! Wire-format round-trip tests for the batch-settlement payload types.

use alloy_primitives::{Address, B256, Bytes, U128, U256, b256};
use serde_json::json;

use super::*;

fn sample_channel_config() -> ChannelConfig {
    ChannelConfig {
        payer: "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap(),
        payer_authorizer: "0x0000000000000000000000000000000000000002"
            .parse()
            .unwrap(),
        receiver: "0x0000000000000000000000000000000000000003"
            .parse()
            .unwrap(),
        receiver_authorizer: "0x0000000000000000000000000000000000000004"
            .parse()
            .unwrap(),
        token: "0x0000000000000000000000000000000000000005"
            .parse()
            .unwrap(),
        withdraw_delay: 900u64.try_into().unwrap(),
        salt: B256::ZERO,
    }
}

fn sample_voucher() -> VoucherFields {
    VoucherFields {
        channel_id: b256!("0xabc123abc123abc123abc123abc123abc123abc123abc123abc123abc1230000"),
        max_claimable_amount: U128::from(1_000u128).into(),
        signature: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
    }
}

#[test]
fn deposit_payload_round_trips_with_erc3009() {
    let payload = BatchSettlementPayload::Deposit(DepositPayload {
        channel_config: sample_channel_config(),
        voucher: sample_voucher(),
        deposit: DepositSegment {
            amount: U256::from(1_000u64).into(),
            authorization: DepositAuthorization::Erc3009(Erc3009Authorization {
                valid_after: U256::ZERO.into(),
                valid_before: U256::from(1_770_000_000u64).into(),
                salt: B256::repeat_byte(0x11),
                signature: Bytes::from_static(&[0x01, 0x02]),
            }),
        },
    });
    let encoded = serde_json::to_value(&payload).unwrap();
    assert_eq!(encoded["type"], "deposit");
    assert_eq!(encoded["deposit"]["amount"], "1000");
    assert_eq!(
        encoded["deposit"]["authorization"]["erc3009Authorization"]["validBefore"],
        "1770000000"
    );
    assert!(encoded["deposit"]["authorization"]["permit2Authorization"].is_null());
    assert_eq!(
        serde_json::from_value::<BatchSettlementPayload>(encoded).unwrap(),
        payload
    );
}

#[test]
fn deposit_payload_round_trips_with_permit2() {
    let payload = BatchSettlementPayload::Deposit(DepositPayload {
        channel_config: sample_channel_config(),
        voucher: sample_voucher(),
        deposit: DepositSegment {
            amount: U256::from(2_000u64).into(),
            authorization: DepositAuthorization::Permit2(Permit2Authorization {
                from: "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
                permitted: Permit2Permitted {
                    token: "0x0000000000000000000000000000000000000005"
                        .parse()
                        .unwrap(),
                    amount: U256::from(2_000u64).into(),
                },
                spender: "0x4020425FAf3B746C082C2f942b4E5159887B0005"
                    .parse()
                    .unwrap(),
                nonce: U256::from(42u64).into(),
                deadline: U256::from(1_770_000_000u64).into(),
                witness: Permit2Witness {
                    channel_id: sample_voucher().channel_id,
                },
                signature: Bytes::from_static(&[0x03, 0x04]),
            }),
        },
    });
    let encoded = serde_json::to_value(&payload).unwrap();
    assert_eq!(
        encoded["deposit"]["authorization"]["permit2Authorization"]["nonce"],
        "42"
    );
    assert!(encoded["deposit"]["authorization"]["erc3009Authorization"].is_null());
    assert_eq!(
        serde_json::from_value::<BatchSettlementPayload>(encoded).unwrap(),
        payload
    );
}

/// Two authorizations in one payload is ambiguous: the facilitator would pick
/// one collector and leave the other signature unspent but exposed.
#[test]
fn deposit_authorization_rejects_both_variants() {
    let encoded = json!({
        "erc3009Authorization": {
            "validAfter": "0",
            "validBefore": "1",
            "salt": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "signature": "0x"
        },
        "permit2Authorization": {
            "from": "0x0000000000000000000000000000000000000001",
            "permitted": {
                "token": "0x0000000000000000000000000000000000000005",
                "amount": "1"
            },
            "spender": "0x4020425FAf3B746C082C2f942b4E5159887B0005",
            "nonce": "0",
            "deadline": "0",
            "witness": {
                "channelId": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "signature": "0x"
        }
    });
    let error = serde_json::from_value::<DepositAuthorization>(encoded).unwrap_err();
    assert!(error.to_string().contains("exactly one"), "{error}");
}

#[test]
fn deposit_authorization_rejects_no_variant() {
    let error = serde_json::from_value::<DepositAuthorization>(json!({})).unwrap_err();
    assert!(error.to_string().contains("exactly one"), "{error}");
}

/// An unknown key inside `authorization` means the client used a transfer
/// method this facilitator does not support. Accepting it would drop the
/// authorization and then fail onchain.
#[test]
fn deposit_authorization_rejects_unknown_keys() {
    let encoded = json!({ "eip2612Authorization": {} });
    assert!(serde_json::from_value::<DepositAuthorization>(encoded).is_err());
}

#[test]
fn voucher_payload_round_trips() {
    let payload = BatchSettlementPayload::Voucher(VoucherPayload {
        channel_config: sample_channel_config(),
        voucher: sample_voucher(),
    });
    let encoded = serde_json::to_value(&payload).unwrap();
    assert_eq!(encoded["type"], "voucher");
    assert_eq!(encoded["voucher"]["maxClaimableAmount"], "1000");
    assert_eq!(
        serde_json::from_value::<BatchSettlementPayload>(encoded).unwrap(),
        payload
    );
}

#[test]
fn client_refund_payload_round_trips() {
    let payload =
        BatchSettlementPayload::Refund(BatchSettlementRefundPayload::Client(RefundPayload {
            channel_config: sample_channel_config(),
            voucher: sample_voucher(),
            amount: Some(U256::from(500u64).into()),
        }));
    let encoded = serde_json::to_value(&payload).unwrap();
    assert_eq!(encoded["type"], "refund");
    assert_eq!(encoded["amount"], "500");
    assert!(encoded["refundNonce"].is_null());
    assert_eq!(
        serde_json::from_value::<BatchSettlementPayload>(encoded).unwrap(),
        payload
    );
}

#[test]
fn enriched_refund_payload_round_trips() {
    let payload = BatchSettlementPayload::Refund(BatchSettlementRefundPayload::Enriched(
        EnrichedRefundPayload {
            channel_config: sample_channel_config(),
            voucher: sample_voucher(),
            amount: U256::from(500u64).into(),
            refund_nonce: U256::from(1u64).into(),
            claims: vec![VoucherClaim {
                voucher: VoucherClaimVoucher {
                    channel: sample_channel_config(),
                    max_claimable_amount: U128::from(700u128).into(),
                },
                signature: Bytes::from_static(&[0xaa, 0xbb]),
                total_claimed: U128::from(700u128).into(),
            }],
            refund_authorizer_signature: Some(Bytes::from_static(&[0xcc, 0xdd])),
            claim_authorizer_signature: None,
        },
    ));
    let encoded = serde_json::to_value(&payload).unwrap();
    assert_eq!(encoded["refundNonce"], "1");
    assert_eq!(encoded["claims"][0]["totalClaimed"], "700");
    assert_eq!(
        serde_json::from_value::<BatchSettlementPayload>(encoded).unwrap(),
        payload
    );
}

#[test]
fn claim_payload_round_trips() {
    let payload = BatchSettlementPayload::Claim(ClaimPayload {
        claims: vec![VoucherClaim {
            voucher: VoucherClaimVoucher {
                channel: sample_channel_config(),
                max_claimable_amount: U128::from(5_000u128).into(),
            },
            signature: Bytes::from_static(&[0x11]),
            total_claimed: U128::from(5_000u128).into(),
        }],
        claim_authorizer_signature: Some(Bytes::from_static(&[0x22])),
    });
    let encoded = serde_json::to_value(&payload).unwrap();
    assert_eq!(encoded["type"], "claim");
    assert_eq!(
        serde_json::from_value::<BatchSettlementPayload>(encoded).unwrap(),
        payload
    );
}

#[test]
fn settle_payload_round_trips() {
    let payload = BatchSettlementPayload::Settle(SettlePayload {
        receiver: "0x0000000000000000000000000000000000000003"
            .parse()
            .unwrap(),
        token: "0x0000000000000000000000000000000000000005"
            .parse()
            .unwrap(),
    });
    let encoded = serde_json::to_value(&payload).unwrap();
    assert_eq!(encoded["type"], "settle");
    assert_eq!(
        serde_json::from_value::<BatchSettlementPayload>(encoded).unwrap(),
        payload
    );
}

#[test]
fn unknown_payload_type_is_rejected() {
    let error = serde_json::from_value::<BatchSettlementPayload>(json!({ "type": "withdraw" }))
        .unwrap_err();
    assert!(error.to_string().contains("withdraw"), "{error}");
}

#[test]
fn payment_requirements_extra_round_trips() {
    let extra = BatchSettlementPaymentRequirementsExtra {
        receiver_authorizer: Some(
            "0x0000000000000000000000000000000000000004"
                .parse()
                .unwrap(),
        ),
        withdraw_delay: Some(900),
        name: Some("USDC".into()),
        version: Some("2".into()),
        asset_transfer_method: Some(AssetTransferMethod::Eip3009),
        channel_state: Some(ChannelStateExtra {
            channel_id: B256::repeat_byte(0x55),
            balance: U128::from(100_000u128).into(),
            total_claimed: U128::from(3_200u128).into(),
            withdraw_requested_at: 0,
            refund_nonce: U256::from(1u64).into(),
            charged_cumulative_amount: Some(U128::from(3_900u128).into()),
        }),
        voucher_state: Some(VoucherStateExtra {
            signed_max_claimable: Some(U128::from(3_900u128).into()),
            signature: Some(Bytes::from_static(&[0xab, 0xcd])),
        }),
    };
    let encoded = serde_json::to_value(&extra).unwrap();
    assert_eq!(encoded["assetTransferMethod"], "eip3009");
    assert_eq!(encoded["channelState"]["chargedCumulativeAmount"], "3900");
    assert_eq!(encoded["channelState"]["balance"], "100000");
    assert_eq!(
        serde_json::from_value::<BatchSettlementPaymentRequirementsExtra>(encoded).unwrap(),
        extra
    );
}

/// The token EIP-712 domain is only needed for ERC-3009 deposits, so a claim
/// or settle request must parse without it.
#[test]
fn payment_requirements_extra_parses_without_the_token_domain() {
    let encoded = json!({
        "receiverAuthorizer": "0x0000000000000000000000000000000000000004",
        "withdrawDelay": 900
    });
    let extra: BatchSettlementPaymentRequirementsExtra = serde_json::from_value(encoded).unwrap();
    assert!(extra.name.is_none());
    assert!(extra.version.is_none());
}

/// The SDK channel managers send `extra: {}` with claim, settle, and refund.
/// Unknown hints such as the Go server's `minDeposit` are ignored.
#[test]
fn payment_requirements_extra_parses_an_empty_object() {
    let extra: BatchSettlementPaymentRequirementsExtra = serde_json::from_value(json!({})).unwrap();
    assert_eq!(extra, BatchSettlementPaymentRequirementsExtra::default());
    assert_eq!(serde_json::to_value(&extra).unwrap(), json!({}));
    let hinted = json!({ "minDeposit": "1000", "withdrawDelay": 900 });
    let extra: BatchSettlementPaymentRequirementsExtra = serde_json::from_value(hinted).unwrap();
    assert_eq!(extra.withdraw_delay, Some(900));
    assert!(extra.receiver_authorizer.is_none());
}

#[test]
fn scheme_literal_accepts_only_batch_settlement() {
    let scheme: BatchSettlementScheme = "batch-settlement".parse().unwrap();
    assert_eq!(scheme.to_string(), "batch-settlement");
    assert!("exact".parse::<BatchSettlementScheme>().is_err());
}

/// Address fields go out EIP-55 checksummed, which is what the reference
/// implementations compare against.
#[test]
fn channel_config_serializes_checksummed_addresses() {
    let config = ChannelConfig {
        payer: Address::from_word(B256::repeat_byte(0xab)).into(),
        ..sample_channel_config()
    };
    let encoded = serde_json::to_value(&config).unwrap();
    let payer = encoded["payer"].as_str().unwrap();
    assert!(
        payer.chars().any(|c| c.is_ascii_uppercase()),
        "payer is not checksummed: {payer}"
    );
}
