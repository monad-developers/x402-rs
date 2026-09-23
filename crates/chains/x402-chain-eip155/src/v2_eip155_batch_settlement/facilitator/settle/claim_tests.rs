use alloy_primitives::Address;

use super::*;
use crate::v2_eip155_batch_settlement::types::{ChannelConfig, U128String, VoucherClaimVoucher};

const CHAIN_ID: u64 = 143;

fn config(salt: u8) -> ChannelConfig {
    ChannelConfig {
        payer: Address::repeat_byte(1).into(),
        payer_authorizer: Address::repeat_byte(2).into(),
        receiver: Address::repeat_byte(3).into(),
        receiver_authorizer: Address::repeat_byte(4).into(),
        token: Address::repeat_byte(5).into(),
        withdraw_delay: 900u64.try_into().unwrap(),
        salt: B256::repeat_byte(salt),
    }
}

fn claim(salt: u8, max_claimable: u128, total: u128) -> VoucherClaim {
    VoucherClaim {
        voucher: VoucherClaimVoucher {
            channel: config(salt),
            max_claimable_amount: U128String(U128::from(max_claimable)),
        },
        signature: Bytes::new(),
        total_claimed: U128String(U128::from(total)),
    }
}

fn states(entries: &[(u8, u128, u128)]) -> HashMap<B256, ChannelTotals> {
    entries
        .iter()
        .map(|(salt, balance, total)| {
            let state = ChannelTotals {
                balance: U128::from(*balance),
                total_claimed: U128::from(*total),
            };
            (compute_channel_id(&config(*salt), CHAIN_ID), state)
        })
        .collect()
}

#[test]
fn all_stale_rows_project_no_effective_row() {
    let claims = [claim(1, 500, 500), claim(2, 100, 50)];
    let projection = project_claims(
        &claims,
        &states(&[(1, 1_000, 500), (2, 1_000, 80)]),
        CHAIN_ID,
    )
    .unwrap();
    assert!(projection.effective_rows.is_empty());
}

/// A stale row next to a new row stays valid: the contract skips the stale row.
#[test]
fn stale_and_new_rows_keep_the_new_row() {
    let claims = [claim(1, 500, 500), claim(2, 300, 200)];
    let projection = project_claims(
        &claims,
        &states(&[(1, 1_000, 500), (2, 1_000, 80)]),
        CHAIN_ID,
    )
    .unwrap();
    assert_eq!(projection.effective_rows, vec![1]);
    let second = compute_channel_id(&config(2), CHAIN_ID);
    assert_eq!(projection.totals[&second], U128::from(200u128));
}

/// Rows for one channel run in order; a later lower row is a no-op.
#[test]
fn repeated_channel_rows_use_the_running_total() {
    let claims = [claim(1, 900, 700), claim(1, 900, 600), claim(1, 900, 800)];
    let projection = project_claims(&claims, &states(&[(1, 1_000, 500)]), CHAIN_ID).unwrap();
    assert_eq!(projection.effective_rows, vec![0, 2]);
    let id = compute_channel_id(&config(1), CHAIN_ID);
    assert_eq!(projection.totals[&id], U128::from(800u128));
}

#[test]
fn row_above_its_voucher_ceiling_is_rejected() {
    let claims = [claim(1, 600, 700)];
    assert_eq!(
        project_claims(&claims, &states(&[(1, 1_000, 0)]), CHAIN_ID).unwrap_err(),
        err::ERR_CLAIM_PAYLOAD
    );
}

#[test]
fn row_above_the_channel_balance_is_rejected() {
    let claims = [claim(1, 2_000, 1_500)];
    assert_eq!(
        project_claims(&claims, &states(&[(1, 1_000, 0)]), CHAIN_ID).unwrap_err(),
        err::ERR_CUMULATIVE_EXCEEDS_BALANCE
    );
}

/// A stale row is never checked against its ceiling, exactly like the contract.
#[test]
fn stale_row_skips_the_ceiling_check() {
    let claims = [claim(1, 10, 400)];
    let projection = project_claims(&claims, &states(&[(1, 1_000, 500)]), CHAIN_ID).unwrap();
    assert!(projection.effective_rows.is_empty());
}
