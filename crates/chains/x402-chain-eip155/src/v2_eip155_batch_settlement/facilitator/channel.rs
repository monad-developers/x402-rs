//! Channel-configuration checks and onchain channel-state reads.

use alloy_primitives::{Address, B256, U128, U256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::BlockId;
use alloy_sol_types::SolCall;

use super::abi::X402BatchSettlement::{self, channelsCall};
use super::digest::compute_channel_id;
use super::rpc_error::log_rpc_error;
use crate::v2_eip155_batch_settlement::constants::{
    BATCH_SETTLEMENT_ADDRESS, MAX_WITHDRAW_DELAY, MIN_WITHDRAW_DELAY,
};
use crate::v2_eip155_batch_settlement::errors as err;
use crate::v2_eip155_batch_settlement::types::{ChannelConfig, PaymentRequirements};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnchainChannelState {
    pub balance: U128,
    pub total_claimed: U128,
    pub withdraw_requested_at: u64,
    pub refund_nonce: U256,
}

impl OnchainChannelState {
    /// A channel with no escrow has never been funded, or is fully drained.
    pub fn is_empty(&self) -> bool {
        self.balance == U128::ZERO
    }
}

/// `balance` and `totalClaimed`, the only channel fields a claim reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelTotals {
    pub balance: U128,
    pub total_claimed: U128,
}

/// Checks that the config hashes to the claimed channel id on this chain.
pub fn validate_channel_id(
    config: &ChannelConfig,
    channel_id: B256,
    chain_id: u64,
) -> Result<(), &'static str> {
    if compute_channel_id(config, chain_id) != channel_id {
        return Err(err::ERR_CHANNEL_ID_MISMATCH);
    }
    Ok(())
}

/// Checks a channel config against the claimed channel id and the server's
/// payment requirements. `/verify` and deposits use it.
pub fn validate_channel_config(
    config: &ChannelConfig,
    channel_id: B256,
    requirements: &PaymentRequirements,
    chain_id: u64,
) -> Result<(), &'static str> {
    validate_channel_id(config, channel_id, chain_id)?;
    if Address::from(config.receiver) != Address::from(requirements.pay_to) {
        return Err(err::ERR_RECEIVER_MISMATCH);
    }
    if Address::from(config.token) != Address::from(requirements.asset) {
        return Err(err::ERR_TOKEN_MISMATCH);
    }
    validate_channel_authorizer(config, requirements)?;
    let withdraw_delay = u64::from(config.withdraw_delay);
    let expected = requirements.extra.withdraw_delay;
    if expected.is_some_and(|expected| expected != withdraw_delay) {
        return Err(err::ERR_WITHDRAW_DELAY_MISMATCH);
    }
    validate_withdraw_delay(withdraw_delay)
}

/// Checks that the channel names the receiver authorizer the server published.
///
/// A missing or zero authorizer is rejected. Without it, nothing shows that
/// the merchant consents to this channel. `deposit` also reverts on a zero
/// authorizer, which would leave no party able to claim or refund.
fn validate_channel_authorizer(
    config: &ChannelConfig,
    requirements: &PaymentRequirements,
) -> Result<(), &'static str> {
    match requirements.extra.receiver_authorizer.map(Address::from) {
        Some(required)
            if required != Address::ZERO
                && Address::from(config.receiver_authorizer) == required =>
        {
            Ok(())
        }
        _ => Err(err::ERR_RECEIVER_AUTHORIZER_MISMATCH),
    }
}

pub fn validate_withdraw_delay(withdraw_delay: u64) -> Result<(), &'static str> {
    if !(MIN_WITHDRAW_DELAY..=MAX_WITHDRAW_DELAY).contains(&withdraw_delay) {
        return Err(err::ERR_WITHDRAW_DELAY_OUT_OF_RANGE);
    }
    Ok(())
}

/// The latest block number, so that a read and a later simulation see one state.
pub async fn pinned_block<P: Provider>(provider: &P) -> Result<BlockId, &'static str> {
    match provider.get_block_number().await {
        Ok(number) => Ok(BlockId::number(number)),
        Err(error) => {
            log_rpc_error(&error);
            Err(err::ERR_RPC_READ_FAILED)
        }
    }
}

/// Reads `channels`, `pendingWithdrawals`, and `refundNonce` at the latest block.
pub async fn read_channel_state<P: Provider>(
    provider: &P,
    channel_id: B256,
) -> Result<OnchainChannelState, &'static str> {
    read_channel_state_at(provider, channel_id, BlockId::latest()).await
}

/// Reads the same three views at an explicit block. At a receipt's block this
/// is end-of-block state: it includes the transaction and any later ones in
/// the same block, but nothing from later blocks.
pub async fn read_channel_state_at<P: Provider>(
    provider: &P,
    channel_id: B256,
    block: BlockId,
) -> Result<OnchainChannelState, &'static str> {
    let contract = X402BatchSettlement::new(BATCH_SETTLEMENT_ADDRESS, provider);
    let channels = contract.channels(channel_id).block(block);
    let pending = contract.pendingWithdrawals(channel_id).block(block);
    let refund_nonce = contract.refundNonce(channel_id).block(block);
    let (channels, pending, refund_nonce) =
        tokio::join!(channels.call(), pending.call(), refund_nonce.call());

    let channels = channels.map_err(|_| err::ERR_CHANNEL_STATE_READ_FAILED)?;
    let pending = pending.map_err(|_| err::ERR_CHANNEL_STATE_READ_FAILED)?;
    let refund_nonce = refund_nonce.map_err(|_| err::ERR_CHANNEL_STATE_READ_FAILED)?;

    Ok(OnchainChannelState {
        balance: U128::from(channels.balance),
        total_claimed: U128::from(channels.totalClaimed),
        withdraw_requested_at: pending.initiatedAt.to::<u64>(),
        refund_nonce,
    })
}

/// Reads `channels(id)` for every id in one `eth_call` at `block`, through the
/// settlement contract's own `multicall`. The result has the order of `ids`.
pub async fn read_channel_totals_at<P: Provider>(
    provider: &P,
    ids: &[B256],
    block: BlockId,
) -> Result<Vec<ChannelTotals>, &'static str> {
    let reads = ids
        .iter()
        .map(|id| channelsCall { channelId: *id }.abi_encode().into())
        .collect();
    let contract = X402BatchSettlement::new(BATCH_SETTLEMENT_ADDRESS, provider);
    let results = contract
        .multicall(reads)
        .block(block)
        .call()
        .await
        .map_err(|error| {
            log_rpc_error(&error);
            err::ERR_CHANNEL_STATE_READ_FAILED
        })?;
    if results.len() != ids.len() {
        return Err(err::ERR_CHANNEL_STATE_READ_FAILED);
    }
    results
        .iter()
        .map(|result| {
            let channel = channelsCall::abi_decode_returns(result)
                .map_err(|_| err::ERR_CHANNEL_STATE_READ_FAILED)?;
            Ok(ChannelTotals {
                balance: U128::from(channel.balance),
                total_claimed: U128::from(channel.totalClaimed),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use x402_types::chain::ChainId;

    use crate::v2_eip155_batch_settlement::types::{
        BatchSettlementPaymentRequirementsExtra, BatchSettlementScheme, U256String,
    };

    const CHAIN_ID: u64 = 84_532;
    const RECEIVER: &str = "0x0000000000000000000000000000000000000003";
    const AUTHORIZER: &str = "0x0000000000000000000000000000000000000004";
    const TOKEN: &str = "0x0000000000000000000000000000000000000005";

    fn requirements(
        receiver: &str,
        authorizer: &str,
        token: &str,
        withdraw_delay: u64,
    ) -> PaymentRequirements {
        PaymentRequirements {
            scheme: BatchSettlementScheme,
            network: ChainId::new("eip155", "84532"),
            amount: U256String(U256::from(1_000u64)),
            pay_to: receiver.parse().unwrap(),
            max_timeout_seconds: 300,
            asset: token.parse().unwrap(),
            extra: BatchSettlementPaymentRequirementsExtra {
                receiver_authorizer: Some(authorizer.parse().unwrap()),
                withdraw_delay: Some(withdraw_delay),
                name: Some("USDC".into()),
                version: Some("2".into()),
                ..Default::default()
            },
        }
    }

    fn config(receiver: &str, authorizer: &str, token: &str, withdraw_delay: u64) -> ChannelConfig {
        ChannelConfig {
            payer: "0x0000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            payer_authorizer: "0x0000000000000000000000000000000000000002"
                .parse()
                .unwrap(),
            receiver: receiver.parse().unwrap(),
            receiver_authorizer: authorizer.parse().unwrap(),
            token: token.parse().unwrap(),
            withdraw_delay: withdraw_delay.try_into().unwrap(),
            salt: B256::ZERO,
        }
    }

    fn check(
        config: &ChannelConfig,
        requirements: &PaymentRequirements,
    ) -> Result<(), &'static str> {
        let channel_id = compute_channel_id(config, CHAIN_ID);
        validate_channel_config(config, channel_id, requirements, CHAIN_ID)
    }

    #[test]
    fn accepts_a_config_that_matches_the_requirements() {
        let config = config(RECEIVER, AUTHORIZER, TOKEN, 900);
        assert_eq!(
            check(&config, &requirements(RECEIVER, AUTHORIZER, TOKEN, 900)),
            Ok(())
        );
    }

    #[test]
    fn rejects_a_channel_id_that_does_not_hash_from_the_config() {
        let config = config(RECEIVER, AUTHORIZER, TOKEN, 900);
        let requirements = requirements(RECEIVER, AUTHORIZER, TOKEN, 900);
        assert_eq!(
            validate_channel_config(&config, B256::repeat_byte(0xff), &requirements, CHAIN_ID),
            Err(err::ERR_CHANNEL_ID_MISMATCH)
        );
    }

    /// The channel id binds the chain. A payload built for another chain must
    /// not verify here, even when every other field lines up.
    #[test]
    fn rejects_a_channel_id_computed_on_another_chain() {
        let config = config(RECEIVER, AUTHORIZER, TOKEN, 900);
        let requirements = requirements(RECEIVER, AUTHORIZER, TOKEN, 900);
        let other_chain_id = compute_channel_id(&config, 1);
        assert_eq!(
            validate_channel_config(&config, other_chain_id, &requirements, CHAIN_ID),
            Err(err::ERR_CHANNEL_ID_MISMATCH)
        );
    }

    #[test]
    fn rejects_a_receiver_that_is_not_the_payee() {
        let config = config(
            "0x0000000000000000000000000000000000000099",
            AUTHORIZER,
            TOKEN,
            900,
        );
        assert_eq!(
            check(&config, &requirements(RECEIVER, AUTHORIZER, TOKEN, 900)),
            Err(err::ERR_RECEIVER_MISMATCH)
        );
    }

    #[test]
    fn rejects_a_token_that_is_not_the_asset() {
        let config = config(
            RECEIVER,
            AUTHORIZER,
            "0x0000000000000000000000000000000000000099",
            900,
        );
        assert_eq!(
            check(&config, &requirements(RECEIVER, AUTHORIZER, TOKEN, 900)),
            Err(err::ERR_TOKEN_MISMATCH)
        );
    }

    #[test]
    fn rejects_an_authorizer_that_the_server_did_not_publish() {
        let config = config(
            RECEIVER,
            "0x0000000000000000000000000000000000000099",
            TOKEN,
            900,
        );
        assert_eq!(
            check(&config, &requirements(RECEIVER, AUTHORIZER, TOKEN, 900)),
            Err(err::ERR_RECEIVER_AUTHORIZER_MISMATCH)
        );
    }

    /// A zero authorizer leaves nobody able to claim or refund, and `deposit`
    /// reverts on it, so it is rejected before any RPC call.
    #[test]
    fn rejects_a_zero_authorizer() {
        let zero = "0x0000000000000000000000000000000000000000";
        let config = config(RECEIVER, zero, TOKEN, 900);
        assert_eq!(
            check(&config, &requirements(RECEIVER, zero, TOKEN, 900)),
            Err(err::ERR_RECEIVER_AUTHORIZER_MISMATCH)
        );
    }

    /// A channel manager sends `extra: {}`. On `/verify` or a deposit, no
    /// published authorizer means no merchant consent.
    #[test]
    fn rejects_requirements_without_a_receiver_authorizer() {
        let config = config(RECEIVER, AUTHORIZER, TOKEN, 900);
        let mut requirements = requirements(RECEIVER, AUTHORIZER, TOKEN, 900);
        requirements.extra = BatchSettlementPaymentRequirementsExtra::default();
        assert_eq!(
            check(&config, &requirements),
            Err(err::ERR_RECEIVER_AUTHORIZER_MISMATCH)
        );
    }

    /// The references compare `withdrawDelay` only when the server sends it.
    /// The onchain bounds still apply.
    #[test]
    fn an_absent_withdraw_delay_is_not_compared() {
        let mut requirements = requirements(RECEIVER, AUTHORIZER, TOKEN, 900);
        requirements.extra.withdraw_delay = None;
        let longer = config(RECEIVER, AUTHORIZER, TOKEN, 1_800);
        assert_eq!(check(&longer, &requirements), Ok(()));
        let too_short = config(RECEIVER, AUTHORIZER, TOKEN, MIN_WITHDRAW_DELAY - 1);
        assert_eq!(
            check(&too_short, &requirements),
            Err(err::ERR_WITHDRAW_DELAY_OUT_OF_RANGE)
        );
    }

    #[test]
    fn rejects_a_withdraw_delay_the_server_did_not_publish() {
        let config = config(RECEIVER, AUTHORIZER, TOKEN, 1_800);
        assert_eq!(
            check(&config, &requirements(RECEIVER, AUTHORIZER, TOKEN, 900)),
            Err(err::ERR_WITHDRAW_DELAY_MISMATCH)
        );
    }

    #[test]
    fn rejects_a_withdraw_delay_outside_the_onchain_bounds() {
        for delay in [MIN_WITHDRAW_DELAY - 1, MAX_WITHDRAW_DELAY + 1] {
            let config = config(RECEIVER, AUTHORIZER, TOKEN, delay);
            assert_eq!(
                check(&config, &requirements(RECEIVER, AUTHORIZER, TOKEN, delay)),
                Err(err::ERR_WITHDRAW_DELAY_OUT_OF_RANGE)
            );
        }
    }

    #[test]
    fn accepts_the_withdraw_delay_bounds_themselves() {
        for delay in [MIN_WITHDRAW_DELAY, MAX_WITHDRAW_DELAY] {
            assert_eq!(validate_withdraw_delay(delay), Ok(()));
        }
    }
}
