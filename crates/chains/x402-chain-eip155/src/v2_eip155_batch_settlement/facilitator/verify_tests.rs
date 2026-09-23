use super::*;

fn state(balance: u128, total_claimed: u128) -> OnchainChannelState {
    OnchainChannelState {
        balance: U128::from(balance),
        total_claimed: U128::from(total_claimed),
        withdraw_requested_at: 0,
        refund_nonce: U256::ZERO,
    }
}

fn amount(value: u128) -> U128 {
    U128::from(value)
}

#[test]
fn voucher_on_an_empty_channel_is_not_found() {
    assert_eq!(
        assert_voucher_bounds(&state(0, 0), amount(1), false),
        Err(err::ERR_CHANNEL_NOT_FOUND)
    );
}

#[test]
fn voucher_above_the_balance_is_rejected() {
    assert_eq!(
        assert_voucher_bounds(&state(1_000, 0), amount(1_001), false),
        Err(err::ERR_CUMULATIVE_EXCEEDS_BALANCE)
    );
}

#[test]
fn paid_voucher_must_exceed_the_claimed_total() {
    assert_eq!(
        assert_voucher_bounds(&state(1_000, 500), amount(500), false),
        Err(err::ERR_CUMULATIVE_AMOUNT_BELOW_CLAIMED)
    );
    assert_eq!(
        assert_voucher_bounds(&state(1_000, 500), amount(501), false),
        Ok(())
    );
}

#[test]
fn refund_voucher_may_equal_the_claimed_total() {
    assert_eq!(
        assert_voucher_bounds(&state(1_000, 500), amount(500), true),
        Ok(())
    );
    assert_eq!(
        assert_voucher_bounds(&state(1_000, 500), amount(499), true),
        Err(err::ERR_CUMULATIVE_AMOUNT_BELOW_CLAIMED)
    );
}

/// TypeScript order: the balance check wins when both fail.
#[test]
fn balance_check_precedes_the_claimed_check() {
    assert_eq!(
        assert_voucher_bounds(&state(100, 500), amount(200), false),
        Err(err::ERR_CUMULATIVE_EXCEEDS_BALANCE)
    );
}

#[test]
fn deposit_counts_toward_the_voucher_ceiling() {
    assert_eq!(
        assert_deposit_bounds(&state(100, 0), amount(900), amount(1_000)),
        Ok(())
    );
    assert_eq!(
        assert_deposit_bounds(&state(100, 0), amount(900), amount(1_001)),
        Err(err::ERR_CUMULATIVE_EXCEEDS_BALANCE)
    );
}

#[test]
fn deposit_voucher_may_equal_but_not_undercut_the_claimed_total() {
    assert_eq!(
        assert_deposit_bounds(&state(500, 500), amount(1), amount(500)),
        Ok(())
    );
    assert_eq!(
        assert_deposit_bounds(&state(500, 500), amount(1), amount(499)),
        Err(err::ERR_CUMULATIVE_AMOUNT_BELOW_CLAIMED)
    );
}

/// `deposit` reverts with `DepositOverflow`; saturating would hide it.
#[test]
fn deposit_that_overflows_the_balance_is_rejected() {
    assert_eq!(
        assert_deposit_bounds(&state(u128::MAX, 0), amount(1), amount(1)),
        Err(err::ERR_DEPOSIT_PAYLOAD)
    );
}

#[test]
fn deposit_amount_must_be_a_nonzero_uint128() {
    assert_eq!(deposit_amount(U256::ZERO), Err(err::ERR_DEPOSIT_PAYLOAD));
    assert_eq!(
        deposit_amount(U256::from(u128::MAX) + U256::from(1u64)),
        Err(err::ERR_DEPOSIT_PAYLOAD)
    );
    assert_eq!(deposit_amount(U256::from(5u64)), Ok(amount(5)));
}
