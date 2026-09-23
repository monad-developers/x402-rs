//! Cross-implementation digest vectors.
//!
//! The Base Sepolia vectors come from viem `hashTypedData`, the library that
//! the official client signs with. The Monad vector comes from a read-only
//! `eth_call` of `getChannelId` and `getVoucherDigest` on the deployed
//! contract on eip155:143.

#![cfg(feature = "facilitator")]

use alloy_primitives::{Address, B256, Signature, U128, b256, hex};
use x402_chain_eip155::v2_eip155_batch_settlement::ChannelConfig;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::{
    compute_channel_id, compute_voucher_digest,
};

const BASE_SEPOLIA: u64 = 84_532;
const VIEM_PAYER: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const VIEM_CHANNEL_ID: B256 =
    b256!("0x5fafb915f0dbee350d7f84d91802dea47e8e3a71929c3cd79da161c291fb28bd");
const VIEM_SIGNATURE: &str = "0x6ad7a9c0cd0172b09704c56dd22de6d2877cf912de007dcdc7757a68756b84af\
2d2767327e6b84836fe2b48fd1b09675957c2fa4ec6c33a146dddd0e823cf1341c";

fn viem_config(salt: B256) -> ChannelConfig {
    ChannelConfig {
        payer: VIEM_PAYER.parse().unwrap(),
        payer_authorizer: VIEM_PAYER.parse().unwrap(),
        receiver: "0x19ee5100D3a1e687F85B952bd3FbEc108Ab6A8d7"
            .parse()
            .unwrap(),
        receiver_authorizer: "0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf"
            .parse()
            .unwrap(),
        token: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
            .parse()
            .unwrap(),
        withdraw_delay: 900u64.try_into().unwrap(),
        salt,
    }
}

#[test]
fn channel_ids_match_viem() {
    assert_eq!(
        compute_channel_id(&viem_config(B256::ZERO), BASE_SEPOLIA),
        VIEM_CHANNEL_ID
    );
    assert_eq!(
        compute_channel_id(&viem_config(B256::repeat_byte(0x42)), BASE_SEPOLIA),
        b256!("0x7b3bf678a448e1882ab277b789987b5dee3b7cc6fc2c7e91687a74b54b474423")
    );
    assert_eq!(
        compute_channel_id(&viem_config(B256::ZERO), 1),
        b256!("0x511b6617e235c4e0c4837f7b51700a3b324110c88225aee727a74536cce36192")
    );
}

#[test]
fn voucher_digests_match_viem_at_the_uint128_edges() {
    let cases = [
        (
            U128::from(1_000u128),
            b256!("0xa2874adbecca0abb1884b4ac1c100e3906d25208ad0c9e6a8fcf9790ccfa2246"),
        ),
        (
            U128::ZERO,
            b256!("0x4187c22619aeed9d5381a1d0c37c9e936e6dfe666f963f7ccfd524e3b8f55173"),
        ),
        (
            U128::MAX,
            b256!("0x9d774906d7e4dbe91d887f3845e83c17c8fed29ca225d14d809d75bea7c3e547"),
        ),
    ];
    for (amount, expected) in cases {
        assert_eq!(
            compute_voucher_digest(VIEM_CHANNEL_ID, amount, BASE_SEPOLIA),
            expected
        );
    }
}

/// A real viem signature recovers to the payer through this crate's digest.
#[test]
fn viem_voucher_signature_recovers_to_the_payer() {
    let digest = compute_voucher_digest(VIEM_CHANNEL_ID, U128::from(1_000u128), BASE_SEPOLIA);
    let signature = Signature::from_raw(&hex::decode(VIEM_SIGNATURE).unwrap()).unwrap();
    let recovered = signature.recover_address_from_prehash(&digest).unwrap();
    assert_eq!(recovered, VIEM_PAYER.parse::<Address>().unwrap());
}

#[test]
fn monad_mainnet_digests_match_the_deployed_contract() {
    let config = ChannelConfig {
        payer: Address::with_last_byte(1).into(),
        payer_authorizer: Address::with_last_byte(2).into(),
        receiver: Address::with_last_byte(3).into(),
        receiver_authorizer: Address::with_last_byte(4).into(),
        token: "0x754704Bc059F8C67012fEd69BC8A327a5aafb603"
            .parse()
            .unwrap(),
        withdraw_delay: 900u64.try_into().unwrap(),
        salt: B256::ZERO,
    };
    let channel_id = compute_channel_id(&config, 143);
    assert_eq!(
        channel_id,
        b256!("0x7f463c6d37509f153434ce328282cf4b9a867598df73db29412c1cd5cfdee27a")
    );
    assert_eq!(
        compute_voucher_digest(channel_id, U128::from(123_456u128), 143),
        b256!("0x560a21eb166b8eb743038f773bcd382a07f421ed6a533d90585adcb6ceb4142d")
    );
}
