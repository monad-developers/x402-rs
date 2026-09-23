use super::*;
use alloy_primitives::{b256, keccak256};

use crate::v2_eip155_batch_settlement::types::{
    BatchSettlementPaymentRequirementsExtra, BatchSettlementScheme, ChannelConfig, DepositSegment,
    Permit2Permitted, Permit2Witness, VoucherFields,
};

fn channel_config() -> ChannelConfig {
    ChannelConfig {
        payer: "0x57b0eF875DeB5A37301F1640E469a2129Da9490E"
            .parse()
            .unwrap(),
        payer_authorizer: "0x57b0eF875DeB5A37301F1640E469a2129Da9490E"
            .parse()
            .unwrap(),
        receiver: "0x2707390BC2E69FF9637106b6a43Cc85183392c6A"
            .parse()
            .unwrap(),
        receiver_authorizer: "0x2707390BC2E69FF9637106b6a43Cc85183392c6A"
            .parse()
            .unwrap(),
        token: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
            .parse()
            .unwrap(),
        withdraw_delay: 900u64.try_into().unwrap(),
        salt: B256::ZERO,
    }
}

fn erc3009_payload() -> DepositPayload {
    DepositPayload {
        channel_config: channel_config(),
        voucher: VoucherFields {
            channel_id: B256::ZERO,
            max_claimable_amount: U128::from(10_000u128).into(),
            signature: Bytes::from(vec![0x11; 65]),
        },
        deposit: DepositSegment {
            amount: U256::from(100_000u64).into(),
            authorization: DepositAuthorization::Erc3009(Erc3009Authorization {
                valid_after: U256::ZERO.into(),
                valid_before: U256::from(1_782_471_206u64).into(),
                salt: b256!("0x2222222222222222222222222222222222222222222222222222222222222222"),
                signature: Bytes::from(vec![0x11; 65]),
            }),
        },
    }
}

fn permit2_authorization(spender: &str, amount: u64, channel_id: B256) -> Permit2Authorization {
    Permit2Authorization {
        from: "0x57b0eF875DeB5A37301F1640E469a2129Da9490E"
            .parse()
            .unwrap(),
        permitted: Permit2Permitted {
            token: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
                .parse()
                .unwrap(),
            amount: U256::from(amount).into(),
        },
        spender: spender.parse().unwrap(),
        nonce: U256::from(7u64).into(),
        deadline: U256::from(1_782_471_206u64).into(),
        witness: Permit2Witness { channel_id },
        signature: Bytes::from(vec![0x22; 65]),
    }
}

/// Pinned against the calldata the canonical TypeScript facilitator
/// produces for the same payload: selector `0x140f1e75` and a byte-exact
/// body. Any encoding drift moves funds through the wrong collector.
#[test]
fn erc3009_deposit_calldata_matches_the_typescript_reference() {
    let calldata = build_deposit_calldata(&erc3009_payload(), U128::from(100_000u128));
    assert_eq!(calldata.len(), 612);
    assert_eq!(&calldata[..4], &[0x14, 0x0f, 0x1e, 0x75]);
    assert_eq!(
        keccak256(calldata.as_ref()),
        b256!("0x597b162bcb662f450e0352297afdceabef1416829e1dfa26e42a9a86a4532a6c")
    );
}

#[test]
fn collector_follows_the_authorization_variant() {
    let erc3009 = erc3009_payload();
    assert_eq!(
        deposit_collector(&erc3009.deposit.authorization),
        ERC3009_DEPOSIT_COLLECTOR_ADDRESS
    );
    let permit2 = DepositAuthorization::Permit2(permit2_authorization(
        "0x4020425FAf3B746C082C2f942b4E5159887B0005",
        100_000,
        B256::ZERO,
    ));
    assert_eq!(
        deposit_collector(&permit2),
        PERMIT2_DEPOSIT_COLLECTOR_ADDRESS
    );
}

#[test]
fn permit2_fields_accept_a_well_formed_authorization() {
    let payload = erc3009_payload();
    let auth = permit2_authorization(
        "0x4020425FAf3B746C082C2f942b4E5159887B0005",
        100_000,
        payload.voucher.channel_id,
    );
    assert_eq!(fields(&payload, &auth), Ok(()));
}

/// A spender that is not the canonical collector would let a third party
/// pull the payer's tokens somewhere else.
#[test]
fn permit2_fields_reject_a_foreign_spender() {
    let payload = erc3009_payload();
    let auth = permit2_authorization(
        "0x000000000000000000000000000000000000dEaD",
        100_000,
        payload.voucher.channel_id,
    );
    assert_eq!(
        fields(&payload, &auth),
        Err(err::ERR_PERMIT2_INVALID_SPENDER)
    );
}

#[test]
fn permit2_fields_reject_an_amount_that_is_not_the_deposit() {
    let payload = erc3009_payload();
    let auth = permit2_authorization(
        "0x4020425FAf3B746C082C2f942b4E5159887B0005",
        999_999,
        payload.voucher.channel_id,
    );
    assert_eq!(
        fields(&payload, &auth),
        Err(err::ERR_PERMIT2_AMOUNT_MISMATCH)
    );
}

/// The witness is what ties the pulled tokens to this channel. A witness
/// for another channel would credit the wrong escrow.
#[test]
fn permit2_fields_reject_a_witness_for_another_channel() {
    let payload = erc3009_payload();
    let auth = permit2_authorization(
        "0x4020425FAf3B746C082C2f942b4E5159887B0005",
        100_000,
        B256::repeat_byte(0x99),
    );
    assert_eq!(fields(&payload, &auth), Err(err::ERR_CHANNEL_ID_MISMATCH));
}

#[test]
fn authorization_window_rejects_an_expired_authorization() {
    let now = now_seconds();
    assert_eq!(
        assert_authorization_window(U256::ZERO, U256::from(now.saturating_sub(1))),
        Err(err::ERR_VALID_BEFORE_EXPIRED)
    );
}

/// An authorization that expires inside the grace window cannot land
/// before it expires, so it is rejected up front.
#[test]
fn authorization_window_rejects_an_imminent_expiry() {
    let now = now_seconds();
    assert_eq!(
        assert_authorization_window(U256::ZERO, U256::from(now + 1)),
        Err(err::ERR_VALID_BEFORE_EXPIRED)
    );
}

#[test]
fn authorization_window_rejects_a_future_start() {
    let now = now_seconds();
    assert_eq!(
        assert_authorization_window(U256::from(now + 600), U256::from(now + 1_000)),
        Err(err::ERR_VALID_AFTER_IN_FUTURE)
    );
}

#[test]
fn authorization_window_accepts_a_live_authorization() {
    let now = now_seconds();
    assert_eq!(
        assert_authorization_window(U256::from(now.saturating_sub(10)), U256::from(now + 600)),
        Ok(())
    );
}

fn fields(payload: &DepositPayload, auth: &Permit2Authorization) -> Result<(), &'static str> {
    let requirements = PaymentRequirements {
        scheme: BatchSettlementScheme,
        network: x402_types::chain::ChainId::new("eip155", "143"),
        amount: U256::from(1u64).into(),
        pay_to: payload.channel_config.receiver,
        max_timeout_seconds: 300,
        asset: payload.channel_config.token,
        extra: BatchSettlementPaymentRequirementsExtra {
            receiver_authorizer: Some(payload.channel_config.receiver_authorizer),
            withdraw_delay: Some(900),
            ..Default::default()
        },
    };
    let check = DepositCheck {
        payload,
        requirements: &requirements,
        chain_id: 143,
    };
    assert_permit2_fields(check, auth)
}
