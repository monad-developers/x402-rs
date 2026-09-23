//! Shared fixtures for the tests of the zero-`payerAuthorizer` log events.
//!
//! [`send_logged`] sends each request two times through the public
//! facilitator, with and without a recorder. It compares the two responses and
//! checks that no event field repeats a signature or a response message.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256, Bytes, U128};
use alloy_signer_local::PrivateKeySigner;
use serde_json::Value;
use serde_json::value::RawValue;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};
use x402_chain_eip155::V2Eip155BatchSettlement;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::compute_voucher_digest;
use x402_chain_eip155::v2_eip155_batch_settlement::{
    ChannelConfig, U128String, VoucherClaim, VoucherClaimVoucher,
};
use x402_types::proto;
use x402_types::scheme::{X402SchemeFacilitator, X402SchemeFacilitatorBuilder};

use crate::batch_settlement_common::{
    CHAIN_ID, MockProvider, channel_config, channel_id, run, sign,
};

const TARGET: &str =
    "x402_chain_eip155::v2_eip155_batch_settlement::facilitator::zero_authorizer_log";
pub const AUTHORIZER: Address = Address::repeat_byte(0x44);
pub const REVERT_DATA: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

#[derive(Debug)]
pub struct Captured {
    level: Level,
    fields: BTreeMap<String, String>,
}

#[derive(Default)]
struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
}

/// Records the events of the log module with every field.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Captured>>>);

impl Subscriber for Recorder {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if event.metadata().target() != TARGET {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        let level = *event.metadata().level();
        let fields = fields.0;
        self.0.lock().unwrap().push(Captured { level, fields });
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

pub type Call = fn(Box<dyn X402SchemeFacilitator>, &str) -> Value;

pub fn verify(facilitator: Box<dyn X402SchemeFacilitator>, body: &str) -> Value {
    let request = proto::VerifyRequest::from(RawValue::from_string(body.into()).unwrap());
    run(facilitator.verify(&request)).unwrap().0
}

pub fn settle(facilitator: Box<dyn X402SchemeFacilitator>, body: &str) -> Value {
    let request = proto::SettleRequest::from(RawValue::from_string(body.into()).unwrap());
    run(facilitator.settle(&request)).unwrap().0
}

/// Sends `body` to a fresh provider with no subscriber, then with a recorder.
pub fn send_logged(
    send: Call,
    body: &str,
    provider: impl Fn() -> Arc<MockProvider>,
) -> (Value, Vec<Captured>) {
    let facilitator = || V2Eip155BatchSettlement.build(provider(), None).unwrap();
    let plain = send(facilitator(), body);
    let recorder = Recorder::default();
    let logged = {
        let _guard = tracing::subscriber::set_default(recorder.clone());
        send(facilitator(), body)
    };
    assert_eq!(logged, plain, "a recorder must not change the response");
    let events = std::mem::take(&mut *recorder.0.lock().unwrap());
    // Signature hex from the request, and the free text of the response.
    let mut forbidden = signatures(&serde_json::from_str(body).unwrap());
    assert!(!forbidden.is_empty(), "every request carries a signature");
    let messages = ["invalidMessage", "errorMessage"].map(|key| logged[key].as_str());
    forbidden.extend(messages.into_iter().flatten().map(String::from));
    for event in &events {
        assert_bounded(event, &forbidden);
    }
    (logged, events)
}

fn signatures(value: &Value) -> Vec<String> {
    let signature = |(key, value): (&String, &Value)| match value.as_str() {
        Some(hex) if key.ends_with("ignature") => vec![hex[2..].to_string()],
        _ => signatures(value),
    };
    match value {
        Value::Object(object) => object.iter().flat_map(signature).collect(),
        Value::Array(items) => items.iter().flat_map(signatures).collect(),
        _ => Vec::new(),
    }
}

/// No value is longer than a hash or repeats a signature or a response
/// message. A reason is a canonical code.
fn assert_bounded(event: &Captured, forbidden: &[String]) {
    for (name, value) in &event.fields {
        let bounded = name == "message" || value.len() <= 66;
        assert!(bounded, "{name} is too long: {value}");
        for text in forbidden {
            assert!(!value.contains(text.as_str()), "{name} repeats {text}");
        }
    }
    if let Some(reason) = event.fields.get("reason") {
        let prefixed = reason.starts_with("invalid_batch_settlement_evm_");
        assert!(prefixed || reason == "settlement_pending", "{reason}");
    }
}

/// Asserts the only event: its level and its exact fields apart from the
/// message. `expected` holds `name=value` pairs separated by spaces.
pub fn assert_only_event(events: &[Captured], level: Level, expected: &str) {
    let [event] = events else {
        panic!("expected one event, got {events:?}");
    };
    assert_eq!(event.level, level, "{event:?}");
    let actual: BTreeSet<String> = event
        .fields
        .iter()
        .filter(|(name, _)| *name != "message")
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    assert_eq!(actual, expected.split(' ').map(String::from).collect());
}

/// The fields of an event for a request with one zero-authorizer voucher.
pub fn one_voucher(operation: &str, payload_type: &str, config: &ChannelConfig) -> String {
    let id = channel_id(config);
    let payer = Address::from(config.payer);
    format!(
        "operation={operation} payload_type={payload_type} chain_id=143 vouchers=1 \
         zero_authorizer_vouchers=1 channel_id={id} payer={payer}"
    )
}

pub fn voucher_signature(signer: &PrivateKeySigner, config: &ChannelConfig) -> Bytes {
    let digest = compute_voucher_digest(channel_id(config), U128::from(300u128), CHAIN_ID);
    sign(signer, digest)
}

/// The receiver authorizer of every claim row.
pub fn claim_authorizer() -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::repeat_byte(0x07)).unwrap()
}

pub fn claim_row(payer: &PrivateKeySigner, payer_authorizer: Address, salt: u8) -> VoucherClaim {
    let authorizer = claim_authorizer().address();
    let config = ChannelConfig {
        salt: B256::repeat_byte(salt),
        ..channel_config(payer.address(), payer_authorizer, authorizer)
    };
    VoucherClaim {
        signature: voucher_signature(payer, &config),
        voucher: VoucherClaimVoucher {
            channel: config,
            max_claimable_amount: U128String(U128::from(300u128)),
        },
        total_claimed: U128String(U128::from(300u128)),
    }
}
