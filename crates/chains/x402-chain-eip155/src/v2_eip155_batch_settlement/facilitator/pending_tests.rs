use super::*;
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};

use alloy_primitives::{Bytes, U128, U256};

use crate::v2_eip155_batch_settlement::types::{
    ChannelConfig, DepositSegment, Erc3009Authorization, Permit2Authorization, Permit2Permitted,
    Permit2Witness, VoucherFields,
};

const CHAIN_ID: u64 = 143;

fn record(byte: u8) -> PendingDeposit {
    PendingDeposit {
        request: B256::repeat_byte(byte),
        tx_hash: TxHash::repeat_byte(byte),
        sender: Address::repeat_byte(byte),
    }
}

fn channel_config() -> ChannelConfig {
    ChannelConfig {
        payer: Address::repeat_byte(0x11).into(),
        payer_authorizer: Address::repeat_byte(0x11).into(),
        receiver: Address::repeat_byte(0x33).into(),
        receiver_authorizer: Address::repeat_byte(0x44).into(),
        token: Address::repeat_byte(0x55).into(),
        withdraw_delay: 900u64.try_into().unwrap(),
        salt: B256::ZERO,
    }
}

fn deposit(authorization: DepositAuthorization) -> DepositPayload {
    DepositPayload {
        channel_config: channel_config(),
        voucher: VoucherFields {
            channel_id: B256::repeat_byte(0xcc),
            max_claimable_amount: U128::from(100u128).into(),
            signature: Bytes::from(vec![0x01; 65]),
        },
        deposit: DepositSegment {
            amount: U256::from(1_000u64).into(),
            authorization,
        },
    }
}

fn erc3009(salt: u8, signature: u8) -> DepositAuthorization {
    DepositAuthorization::Erc3009(Erc3009Authorization {
        valid_after: U256::ZERO.into(),
        valid_before: U256::from(2_000_000_000u64).into(),
        salt: B256::repeat_byte(salt),
        signature: Bytes::from(vec![signature; 65]),
    })
}

fn permit2(nonce: u64, token: u8) -> DepositAuthorization {
    DepositAuthorization::Permit2(Permit2Authorization {
        from: Address::repeat_byte(0x11).into(),
        permitted: Permit2Permitted {
            token: Address::repeat_byte(token).into(),
            amount: U256::from(1_000u64).into(),
        },
        spender: Address::repeat_byte(0x66).into(),
        nonce: U256::from(nonce).into(),
        deadline: U256::from(2_000_000_000u64).into(),
        witness: Permit2Witness {
            channel_id: B256::repeat_byte(0xcc),
        },
        signature: Bytes::from(vec![0x02; 65]),
    })
}

fn reserve(store: &PendingDeposits, key: B256, byte: u8, now: Instant) -> Reservation<'_> {
    match store.try_claim(key, B256::repeat_byte(byte), now) {
        Ok(Claim::Broadcast(reservation)) => reservation,
        other => panic!("expected a reservation: {other:?}"),
    }
}

/// Records `record(byte)` for `key` at `now`.
fn put(store: &PendingDeposits, key: B256, byte: u8, now: Instant) {
    let reservation = reserve(store, key, byte, now);
    reservation.record_at(TxHash::repeat_byte(byte), Address::repeat_byte(byte), now);
}

fn recorded(store: &PendingDeposits, key: B256, byte: u8, now: Instant) -> Option<PendingDeposit> {
    match store.try_claim(key, B256::repeat_byte(byte), now) {
        Ok(Claim::Recorded(deposit)) => Some(deposit),
        _ => None,
    }
}

/// One poll with no waker: `None` means that the future waits.
fn poll_once<F: Future>(future: Pin<&mut F>) -> Option<F::Output> {
    let mut context = Context::from_waker(Waker::noop());
    match future.poll(&mut context) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
}

#[test]
fn a_record_expires_after_the_ttl() {
    let store = PendingDeposits::default();
    let now = Instant::now();
    put(&store, B256::ZERO, 1, now);
    let half = now + PENDING_TTL / 2;
    assert_eq!(recorded(&store, B256::ZERO, 1, half), Some(record(1)));
    let expired = now + PENDING_TTL;
    assert!(matches!(
        store.try_claim(B256::ZERO, B256::repeat_byte(1), expired),
        Ok(Claim::Broadcast(_))
    ));
    assert!(
        store.lock().is_empty(),
        "the dropped reservation frees the key"
    );
}

#[test]
fn a_full_store_drops_its_oldest_record() {
    let store = PendingDeposits::default();
    let start = Instant::now();
    for index in 0..MAX_PENDING {
        let key = B256::from(U256::from(index));
        put(&store, key, 1, start + Duration::from_millis(index as u64));
    }
    let late = start + Duration::from_secs(60);
    put(&store, B256::repeat_byte(0xff), 2, late);
    assert_eq!(store.lock().len(), MAX_PENDING);
    assert!(!store.lock().contains_key(&B256::ZERO));
    assert_eq!(
        recorded(&store, B256::repeat_byte(0xff), 2, late),
        Some(record(2))
    );
    assert!(recorded(&store, B256::from(U256::from(1u64)), 1, late).is_some());
}

/// A request in progress keeps its key, so a store full of them refuses.
#[test]
fn a_store_full_of_requests_in_progress_refuses_a_new_key() {
    let store = PendingDeposits::default();
    let now = Instant::now();
    let mut held: Vec<_> = (0..MAX_PENDING)
        .map(|index| reserve(&store, B256::from(U256::from(index)), 1, now))
        .collect();
    let late = now + PENDING_TTL * 2;
    let key = B256::repeat_byte(0xff);
    assert!(matches!(
        store.try_claim(key, B256::ZERO, late),
        Ok(Claim::Full)
    ));
    held.pop();
    assert!(matches!(
        store.try_claim(key, B256::ZERO, late),
        Ok(Claim::Broadcast(_))
    ));
}

/// A reader of an older transaction must not remove a newer record.
#[test]
fn remove_keeps_a_record_for_another_transaction() {
    let store = PendingDeposits::default();
    let now = Instant::now();
    put(&store, B256::ZERO, 1, now);
    store.remove(B256::ZERO, TxHash::repeat_byte(9));
    assert_eq!(recorded(&store, B256::ZERO, 1, now), Some(record(1)));
    store.remove(B256::ZERO, TxHash::repeat_byte(1));
    assert!(store.lock().is_empty());
}

/// `remove` is for records only. It never frees a key in progress.
#[test]
fn remove_keeps_a_request_in_progress() {
    let store = PendingDeposits::default();
    let _held = reserve(&store, B256::ZERO, 1, Instant::now());
    store.remove(B256::ZERO, TxHash::ZERO);
    assert!(matches!(
        store.try_claim(B256::ZERO, B256::repeat_byte(2), Instant::now()),
        Ok(Claim::Taken)
    ));
}

#[test]
fn an_identical_request_waits_for_the_record() {
    let store = PendingDeposits::default();
    let held = reserve(&store, B256::ZERO, 1, Instant::now());
    let mut waiter = pin!(store.claim(B256::ZERO, B256::repeat_byte(1)));
    assert!(poll_once(waiter.as_mut()).is_none());
    assert!(
        poll_once(waiter.as_mut()).is_none(),
        "it waits until release"
    );
    held.record(TxHash::repeat_byte(1), Address::repeat_byte(1));
    let claim = poll_once(waiter.as_mut()).expect("the record wakes the waiter");
    assert!(matches!(claim, Claim::Recorded(deposit) if deposit == record(1)));
}

/// A reservation that goes with no record lets the next request broadcast.
#[test]
fn a_dropped_reservation_passes_the_key_to_one_waiter() {
    let store = PendingDeposits::default();
    let held = reserve(&store, B256::ZERO, 1, Instant::now());
    let mut first = pin!(store.claim(B256::ZERO, B256::repeat_byte(1)));
    let mut second = pin!(store.claim(B256::ZERO, B256::repeat_byte(1)));
    assert!(poll_once(first.as_mut()).is_none());
    assert!(poll_once(second.as_mut()).is_none());
    drop(held);
    let claim = poll_once(first.as_mut()).expect("the release wakes the waiter");
    assert!(matches!(claim, Claim::Broadcast(_)));
    assert!(
        poll_once(second.as_mut()).is_none(),
        "one broadcaster at a time"
    );
}

#[test]
fn a_changed_request_or_another_key_does_not_wait() {
    let store = PendingDeposits::default();
    let _held = reserve(&store, B256::ZERO, 1, Instant::now());
    let changed = pin!(store.claim(B256::ZERO, B256::repeat_byte(2)));
    assert!(matches!(poll_once(changed), Some(Claim::Taken)));
    let other = pin!(store.claim(B256::repeat_byte(9), B256::repeat_byte(1)));
    assert!(matches!(poll_once(other), Some(Claim::Broadcast(_))));
}

/// Different signature bytes for one ERC-3009 nonce spend the same nonce.
#[test]
fn erc3009_key_follows_the_onchain_nonce() {
    let key = authorization_key(CHAIN_ID, &deposit(erc3009(0x77, 0x01)));
    assert_eq!(
        key,
        authorization_key(CHAIN_ID, &deposit(erc3009(0x77, 0x09)))
    );
    assert_ne!(
        key,
        authorization_key(CHAIN_ID, &deposit(erc3009(0x78, 0x01)))
    );
    assert_ne!(
        key,
        authorization_key(CHAIN_ID + 1, &deposit(erc3009(0x77, 0x01)))
    );
    let mut other_channel = deposit(erc3009(0x77, 0x01));
    other_channel.voucher.channel_id = B256::repeat_byte(0xcd);
    assert_ne!(key, authorization_key(CHAIN_ID, &other_channel));
}

/// A Permit2 nonce belongs to the owner, not to one token.
#[test]
fn permit2_key_follows_the_owner_nonce() {
    let key = authorization_key(CHAIN_ID, &deposit(permit2(7, 0x55)));
    assert_eq!(key, authorization_key(CHAIN_ID, &deposit(permit2(7, 0x56))));
    assert_ne!(key, authorization_key(CHAIN_ID, &deposit(permit2(8, 0x55))));
    assert_ne!(
        key,
        authorization_key(CHAIN_ID, &deposit(erc3009(0x07, 0x01)))
    );
}

#[test]
fn pending_hash_reads_only_a_settlement_pending_response() {
    let hash = TxHash::repeat_byte(0xab);
    let pending = BatchSettlementSettleResponse::settlement_pending("eip155:143", hash, "t".into());
    assert_eq!(pending_hash(&pending), Some(hash));
    let reverted = BatchSettlementSettleResponse::mined_failure(
        "eip155:143",
        err::ERR_DEPOSIT_TRANSACTION_FAILED,
        hash,
        "reverted".into(),
    );
    assert_eq!(pending_hash(&reverted), None);
}
