//! Decimal-string numeric wrappers for the batch-settlement wire format.
//!
//! The x402 wire format encodes every amount and nonce as a decimal string.
//! `alloy_primitives::Uint` serializes as `0x`-prefixed hex, so the scheme
//! uses these wrappers instead. They reject hex input as well, because a
//! silently truncated amount is worse than a rejected payload.

use alloy_primitives::aliases::U40;
use alloy_primitives::{U128, U256};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{self, Formatter};

/// A `U256` that serializes as a decimal string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct U256String(pub U256);

/// A `U128` that serializes as a decimal string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct U128String(pub U128);

macro_rules! decimal_string_wrapper {
    ($name:ident, $inner:ty) => {
        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $inner {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                // ruint skips `_` and reads "" as 0, so only plain ASCII digits reach it.
                if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(serde::de::Error::custom(format!(
                        "expected a decimal integer, got {raw:?}"
                    )));
                }
                <$inner>::from_str_radix(&raw, 10)
                    .map(Self)
                    .map_err(serde::de::Error::custom)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

decimal_string_wrapper!(U256String, U256);
decimal_string_wrapper!(U128String, U128);

/// A `withdrawDelay` that serializes as a JSON number and fits the contract's `uint40`.
///
/// The channel id hashes this field. A wider value fails to parse; it is never
/// narrowed, because a narrowed value would name a different channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WithdrawDelay(U40);

impl TryFrom<u64> for WithdrawDelay {
    type Error = String;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        U40::try_from(value)
            .map(Self)
            .map_err(|_| format!("withdrawDelay {value} does not fit uint40"))
    }
}

impl From<WithdrawDelay> for U40 {
    fn from(value: WithdrawDelay) -> Self {
        value.0
    }
}

impl From<WithdrawDelay> for u64 {
    fn from(value: WithdrawDelay) -> Self {
        value.0.as_limbs()[0]
    }
}

impl Serialize for WithdrawDelay {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(u64::from(*self))
    }
}

impl<'de> Deserialize<'de> for WithdrawDelay {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = u64::deserialize(deserializer)?;
        Self::try_from(raw).map_err(serde::de::Error::custom)
    }
}

/// Narrows a `U256` to a `U128`, or returns `None` when the value does not fit.
///
/// Onchain balances, claim totals, and refund amounts are `uint128`. A payload
/// that carries a wider value cannot settle, so it must be rejected early
/// rather than truncated.
pub fn u256_to_u128(value: U256) -> Option<U128> {
    let bytes: [u8; 32] = value.to_be_bytes();
    if bytes[..16].iter().any(|byte| *byte != 0) {
        return None;
    }
    let mut narrow = [0u8; 16];
    narrow.copy_from_slice(&bytes[16..]);
    Some(U128::from_be_bytes(narrow))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn u256_string_round_trips_as_decimal() {
        let value = U256String(U256::from(100_000u64));
        let encoded = serde_json::to_value(value).unwrap();
        assert_eq!(encoded, json!("100000"));
        assert_eq!(
            serde_json::from_value::<U256String>(encoded).unwrap(),
            value
        );
    }

    #[test]
    fn u128_string_round_trips_as_decimal() {
        let value = U128String(U128::from(42u128));
        let encoded = serde_json::to_value(value).unwrap();
        assert_eq!(encoded, json!("42"));
        assert_eq!(
            serde_json::from_value::<U128String>(encoded).unwrap(),
            value
        );
    }

    /// A hex amount must not decode. `0x64` would otherwise become 0 or 64 and
    /// change the money the facilitator moves.
    #[test]
    fn decimal_wrappers_reject_hex_input() {
        assert!(serde_json::from_value::<U128String>(json!("0x64")).is_err());
        assert!(serde_json::from_value::<U256String>(json!("0x64")).is_err());
    }

    /// ruint alone reads "" and "_" as 0 and "1_000" as 1000.
    #[test]
    fn decimal_wrappers_reject_anything_but_ascii_digits() {
        for raw in ["", "_", "1_000", "+1", "-1", " 1", "1 ", "1.0", "1e3", "١"] {
            assert!(
                serde_json::from_value::<U128String>(json!(raw)).is_err(),
                "{raw:?}"
            );
            assert!(
                serde_json::from_value::<U256String>(json!(raw)).is_err(),
                "{raw:?}"
            );
        }
    }

    /// Both references accept leading zeros.
    #[test]
    fn decimal_wrappers_accept_leading_zeros() {
        let value = serde_json::from_value::<U128String>(json!("007")).unwrap();
        assert_eq!(value, U128String(U128::from(7u128)));
    }

    #[test]
    fn decimal_wrappers_keep_their_bounds() {
        let max = u128::MAX.to_string();
        let parsed = serde_json::from_value::<U128String>(json!(max)).unwrap();
        assert_eq!(parsed, U128String(U128::MAX));
        let above = (U256::from(u128::MAX) + U256::from(1u64)).to_string();
        assert!(serde_json::from_value::<U128String>(json!(above)).is_err());
        let above_u256 = format!("{}0", U256::MAX);
        assert!(serde_json::from_value::<U256String>(json!(above_u256)).is_err());
    }

    #[test]
    fn decimal_wrappers_reject_non_string_input() {
        assert!(serde_json::from_value::<U128String>(json!(100)).is_err());
        assert!(serde_json::from_value::<U256String>(json!(100)).is_err());
    }

    #[test]
    fn withdraw_delay_round_trips_as_a_json_number() {
        let max = (1u64 << 40) - 1;
        let delay = serde_json::from_value::<WithdrawDelay>(json!(max)).unwrap();
        assert_eq!(u64::from(delay), max);
        assert_eq!(serde_json::to_value(delay).unwrap(), json!(max));
    }

    /// A delay above `uint40` must not decode. Clamping it to a valid delay
    /// would change the channel id.
    #[test]
    fn withdraw_delay_rejects_values_above_uint40() {
        assert!(serde_json::from_value::<WithdrawDelay>(json!(1u64 << 40)).is_err());
        assert!(serde_json::from_value::<WithdrawDelay>(json!(u64::MAX)).is_err());
        assert!(WithdrawDelay::try_from(1u64 << 40).is_err());
    }

    #[test]
    fn withdraw_delay_rejects_non_numeric_input() {
        assert!(serde_json::from_value::<WithdrawDelay>(json!("900")).is_err());
        assert!(serde_json::from_value::<WithdrawDelay>(json!(-1)).is_err());
    }

    #[test]
    fn u256_to_u128_keeps_values_inside_the_range() {
        assert_eq!(u256_to_u128(U256::ZERO), Some(U128::ZERO));
        assert_eq!(
            u256_to_u128(U256::from(u128::MAX)),
            Some(U128::from(u128::MAX))
        );
    }

    #[test]
    fn u256_to_u128_rejects_values_above_the_range() {
        assert_eq!(u256_to_u128(U256::from(u128::MAX) + U256::from(1u64)), None);
        assert_eq!(u256_to_u128(U256::MAX), None);
    }
}
