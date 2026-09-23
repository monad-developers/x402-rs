//! Deposit broadcasts, kept in memory for an identical retry.
//!
//! The resource-server SDK retries a `settlement_pending` settle one time with
//! the same body. A proxy can also send one request two times. A second
//! broadcast of that deposit spends gas and reverts, or it lands from a
//! different signer. So only one request for each authorization can broadcast
//! at a time. An identical request waits for it, then reads the receipt of its
//! transaction instead.
//!
//! The key is the onchain authorization that the deposit spends. The record
//! holds a hash of the full request that passed the deposit checks. Only an
//! identical request gets the reconciled result.
//!
//! The store is per process. A restart loses it, and other replicas do not
//! see it. A retry that misses the store runs the full deposit checks again.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use alloy_primitives::{Address, B256, TxHash, keccak256};
use alloy_sol_types::SolValue;
use tokio::sync::watch;

use super::response::BatchSettlementSettleResponse;
use crate::chain::permit2::PERMIT2_ADDRESS;
use crate::v2_eip155_batch_settlement::encoding::build_erc3009_deposit_nonce;
use crate::v2_eip155_batch_settlement::errors as err;
use crate::v2_eip155_batch_settlement::types::{
    DepositAuthorization, DepositPayload, PaymentPayload, PaymentRequirements,
};

/// The SDK retry comes immediately. The TypeScript reference uses the same TTL.
pub const PENDING_TTL: Duration = Duration::from_secs(5 * 60);

/// A memory bound for records and requests in progress together.
pub const MAX_PENDING: usize = 10_000;

/// One broadcast of a deposit authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingDeposit {
    /// [`request_hash`] of the request that made the broadcast.
    pub request: B256,
    pub tx_hash: TxHash,
    /// The facilitator signer that sent the transaction.
    pub sender: Address,
}

#[derive(Debug)]
enum Entry {
    /// A request holds the key. `release` closes when its [`Reservation`] goes.
    Busy {
        request: B256,
        release: watch::Receiver<()>,
    },
    Recorded {
        deposit: PendingDeposit,
        at: Instant,
    },
}

impl Entry {
    fn recorded_at(&self) -> Option<Instant> {
        match self {
            Entry::Busy { .. } => None,
            Entry::Recorded { at, .. } => Some(*at),
        }
    }
}

/// The result of [`PendingDeposits::claim`].
#[derive(Debug)]
pub enum Claim<'a> {
    /// The caller is the only request that can broadcast this authorization.
    Broadcast(Reservation<'a>),
    /// The identical request broadcast this authorization.
    Recorded(PendingDeposit),
    /// A different request holds or broadcast this authorization.
    Taken,
    /// All [`MAX_PENDING`] entries are requests in progress.
    Full,
}

/// The right to broadcast one authorization. If it goes without
/// [`Reservation::record`], the next request can broadcast.
#[derive(Debug)]
pub struct Reservation<'a> {
    store: &'a PendingDeposits,
    key: B256,
    request: B256,
    /// Drops after [`Drop::drop`] changes the map, so a waiter sees the change.
    _release: watch::Sender<()>,
}

impl Reservation<'_> {
    pub fn record(self, tx_hash: TxHash, sender: Address) {
        self.record_at(tx_hash, sender, Instant::now());
    }

    fn record_at(self, tx_hash: TxHash, sender: Address, now: Instant) {
        let deposit = PendingDeposit {
            request: self.request,
            tx_hash,
            sender,
        };
        let entry = Entry::Recorded { deposit, at: now };
        self.store.lock().insert(self.key, entry);
    }
}

/// While a reservation exists, its key holds its `Busy` entry: nothing else
/// removes or replaces a `Busy` entry.
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        let mut entries = self.store.lock();
        if matches!(entries.get(&self.key), Some(Entry::Busy { .. })) {
            entries.remove(&self.key);
        }
    }
}

#[derive(Debug, Default)]
pub struct PendingDeposits {
    entries: Mutex<HashMap<B256, Entry>>,
}

impl PendingDeposits {
    /// Waits while the identical request holds `key`. The wait holds no lock,
    /// and a request for another key does not wait.
    pub async fn claim(&self, key: B256, request: B256) -> Claim<'_> {
        loop {
            let mut release = match self.try_claim(key, request, Instant::now()) {
                Ok(claim) => return claim,
                Err(release) => release,
            };
            // Nothing sends on the channel, so this returns when it closes.
            let _ = release.changed().await;
        }
    }

    /// Removes the record only if it still names `tx_hash`.
    pub fn remove(&self, key: B256, tx_hash: TxHash) {
        let mut entries = self.lock();
        if let Some(Entry::Recorded { deposit, .. }) = entries.get(&key)
            && deposit.tx_hash == tx_hash
        {
            entries.remove(&key);
        }
    }

    /// `Err` holds the channel to wait on.
    fn try_claim(
        &self,
        key: B256,
        request: B256,
        now: Instant,
    ) -> Result<Claim<'_>, watch::Receiver<()>> {
        let mut entries = self.lock();
        match entries.get(&key) {
            Some(Entry::Busy {
                request: held,
                release,
            }) if *held == request => return Err(release.clone()),
            Some(Entry::Busy { .. }) => return Ok(Claim::Taken),
            Some(Entry::Recorded { deposit, at }) if now.duration_since(*at) < PENDING_TTL => {
                if deposit.request == request {
                    return Ok(Claim::Recorded(*deposit));
                }
                return Ok(Claim::Taken);
            }
            _ => {}
        }
        if !make_room(&mut entries, now) {
            return Ok(Claim::Full);
        }
        let (sender, release) = watch::channel(());
        entries.insert(key, Entry::Busy { request, release });
        Ok(Claim::Broadcast(Reservation {
            store: self,
            key,
            request,
            _release: sender,
        }))
    }

    /// Every critical section changes the map in one step and never waits,
    /// so a poisoned map is still consistent.
    fn lock(&self) -> MutexGuard<'_, HashMap<B256, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Removes expired records, then the oldest record if the map is full. A
/// request in progress keeps its entry, so `false` means no room.
fn make_room(entries: &mut HashMap<B256, Entry>, now: Instant) -> bool {
    entries.retain(|_, entry| {
        entry
            .recorded_at()
            .is_none_or(|at| now.duration_since(at) < PENDING_TTL)
    });
    if entries.len() < MAX_PENDING {
        return true;
    }
    let oldest = entries
        .iter()
        .filter_map(|(key, entry)| Some((entry.recorded_at()?, *key)))
        .min();
    oldest.is_some_and(|(_, key)| entries.remove(&key).is_some())
}

/// Identifies the nonce that the deposit spends onchain. ERC-3009 nonces
/// live in the token for each payer. Permit2 nonces live in Permit2 for each
/// owner. Two requests that spend one nonce get the same key, whatever their
/// signature bytes.
///
/// The caller must first check the channel config against the voucher's
/// channel id, because the ERC-3009 nonce uses that id.
pub fn authorization_key(chain_id: u64, deposit: &DepositPayload) -> B256 {
    let payer = Address::from(deposit.channel_config.payer);
    let (nonce_owner, nonce) = match &deposit.deposit.authorization {
        DepositAuthorization::Erc3009(auth) => (
            Address::from(deposit.channel_config.token),
            build_erc3009_deposit_nonce(deposit.voucher.channel_id, auth.salt),
        ),
        DepositAuthorization::Permit2(auth) => (PERMIT2_ADDRESS, B256::from(auth.nonce.0)),
    };
    keccak256((chain_id, nonce_owner, payer, nonce).abi_encode())
}

/// Hash of the full request as the facilitator parsed it: the payload with
/// its voucher and authorization, `accepted`, and the requirements.
pub fn request_hash(
    chain_id: u64,
    payment: &PaymentPayload,
    requirements: &PaymentRequirements,
) -> B256 {
    let encoded = serde_json::to_vec(&(chain_id, payment, requirements))
        .expect("settle request serialization cannot fail");
    keccak256(encoded)
}

/// The broadcast hash of a `settlement_pending` response.
pub fn pending_hash(response: &BatchSettlementSettleResponse) -> Option<TxHash> {
    if response.error_reason.as_deref() != Some(err::ERR_SETTLEMENT_PENDING) {
        return None;
    }
    response.transaction.parse().ok()
}

#[cfg(test)]
#[path = "pending_tests.rs"]
mod tests;
