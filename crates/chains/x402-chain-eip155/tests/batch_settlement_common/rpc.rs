//! A mock RPC transport that records every request it answers.
//!
//! Responses still come from a FIFO `Asserter`. The record lets a test check
//! the target, sender, input, block, and override of each outbound call.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use alloy_primitives::{Address, Bytes};
use alloy_transport::mock::{Asserter, MockResponse, MockTransport};
use alloy_transport::{TransportError, TransportErrorKind};
use serde::Serialize;
use serde_json::Value;

/// A queued failure with this code fails the request in the transport, as a
/// lost connection does, instead of answering with a JSON-RPC error.
const TRANSPORT_FAILURE: i64 = i64::MIN;

/// Queues a transport failure whose text stands for a secret RPC URL.
pub fn push_transport_failure(asserter: &Asserter, text: &'static str) {
    let payload = serde_json::json!({ "code": TRANSPORT_FAILURE, "message": text });
    asserter.push_failure(serde_json::from_value(payload).unwrap());
}

/// An EVM revert with `data`, as a node returns it for `eth_call`.
pub fn revert(data: &[u8]) -> MockResponse {
    let data = Bytes::copy_from_slice(data);
    let payload = serde_json::json!({ "code": 3, "message": "execution reverted", "data": data });
    MockResponse::Failure(serde_json::from_value(payload).unwrap())
}

pub fn success(value: impl Serialize) -> MockResponse {
    let raw = serde_json::to_string(&value).unwrap();
    MockResponse::Success(serde_json::value::RawValue::from_string(raw).unwrap())
}

pub fn push_revert(asserter: &Asserter, data: &[u8]) {
    asserter.push(revert(data));
}

/// One JSON-RPC request as the facilitator sent it.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub params: Value,
}

impl Request {
    fn tx_field(&self, name: &str) -> Option<&Value> {
        self.params.get(0)?.get(name)
    }

    pub fn to(&self) -> Option<Address> {
        serde_json::from_value(self.tx_field("to")?.clone()).ok()
    }

    pub fn from(&self) -> Option<Address> {
        serde_json::from_value(self.tx_field("from")?.clone()).ok()
    }

    pub fn input(&self) -> Bytes {
        let input = self.tx_field("input").or_else(|| self.tx_field("data"));
        input
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .unwrap_or_default()
    }

    /// The block tag or number of an `eth_call` or `eth_estimateGas`.
    pub fn block(&self) -> Option<&str> {
        self.params.get(1)?.as_str()
    }

    /// The explicit `gas` of a call. `None` means that the node uses its cap.
    pub fn gas(&self) -> Option<u64> {
        let gas = self.tx_field("gas")?.as_str()?.strip_prefix("0x")?;
        u64::from_str_radix(gas, 16).ok()
    }

    /// `eth_call` takes a state override as its third parameter.
    pub fn has_state_override(&self) -> bool {
        self.params.get(2).is_some_and(|value| !value.is_null())
    }
}

/// Answers the requests it recognizes, as an EVM would. `None` falls back to
/// the FIFO queue. A route lets a test model a wallet whose reply depends on
/// how it is called, so the answer does not depend on the call order.
pub type Route = Arc<dyn Fn(&Request) -> Option<MockResponse> + Send + Sync>;

#[derive(Clone)]
pub struct RecordingTransport {
    inner: MockTransport,
    asserter: Asserter,
    requests: Arc<Mutex<Vec<Request>>>,
    route: Option<Route>,
}

impl RecordingTransport {
    pub fn new(asserter: Asserter, route: Option<Route>) -> Self {
        Self {
            inner: MockTransport::new(asserter.clone()),
            asserter,
            requests: Arc::default(),
            route,
        }
    }

    pub fn requests(&self) -> Arc<Mutex<Vec<Request>>> {
        self.requests.clone()
    }

    /// Records the packet and puts any routed answer at the queue front.
    fn record(&self, packet: &impl Serialize) {
        let value = serde_json::to_value(packet).unwrap();
        let requests = match value {
            Value::Array(batch) => batch,
            single => vec![single],
        };
        for request in requests {
            let request = Request {
                method: request["method"].as_str().unwrap_or_default().to_string(),
                params: request["params"].clone(),
            };
            let routed = self.route.as_ref().and_then(|route| route(&request));
            if let Some(response) = routed {
                self.asserter.write_q().push_front(response);
            }
            self.requests.lock().unwrap().push(request);
        }
    }

    fn take_transport_failure(&self) -> Option<String> {
        let mut queue = self.asserter.write_q();
        let front = queue.front()?.as_error()?;
        if front.code != TRANSPORT_FAILURE {
            return None;
        }
        let message = front.message.to_string();
        queue.pop_front();
        Some(message)
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send>>;

impl<R, T> tower::Service<R> for RecordingTransport
where
    R: Serialize,
    T: Send + 'static,
    MockTransport: tower::Service<R, Response = T, Error = TransportError, Future = BoxFuture<T>>,
{
    type Response = T;
    type Error = TransportError;
    type Future = BoxFuture<T>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, packet: R) -> Self::Future {
        self.record(&packet);
        if let Some(message) = self.take_transport_failure() {
            return Box::pin(async move { Err(TransportErrorKind::custom_str(&message)) });
        }
        self.inner.call(packet)
    }
}
