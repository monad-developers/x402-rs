//! Client-safe text for RPC failures.
//!
//! A transport error can carry the RPC URL, and many providers put the API
//! key in that URL. Responses therefore carry fixed text for every failure.
//! An EVM revert adds only its revert data, which comes from the chain. The
//! full error goes only to the log.

use alloy_primitives::Bytes;
use alloy_transport::TransportError;

/// Client text for a failed RPC request that is not a revert.
pub const RPC_FAILED: &str = "RPC request failed";

/// Client text for an EVM revert. The node message is never sent.
const EXECUTION_REVERTED: &str = "execution reverted";

/// The execution-revert code that Monad uses for `eth_call` and `eth_estimateGas`.
const EXECUTION_REVERTED_CODE: i64 = 3;

/// The node ran the call and the EVM reverted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revert {
    pub data: Option<Bytes>,
}

impl Revert {
    /// Fixed revert text and the raw revert data.
    pub fn client_message(&self) -> String {
        match &self.data {
            Some(data) => format!("{EXECUTION_REVERTED}: {data}"),
            None => EXECUTION_REVERTED.to_string(),
        }
    }
}

/// `Some` only for JSON-RPC code 3. A message that says "revert" under a
/// different code is not a revert. Rate limits, internal errors, and
/// transport errors are `None`.
pub fn as_revert(error: &TransportError) -> Option<Revert> {
    let payload = error.as_error_resp()?;
    if payload.code != EXECUTION_REVERTED_CODE {
        return None;
    }
    Some(Revert {
        data: payload.as_revert_data(),
    })
}

/// Logs the full error and returns text that is safe to send to a client.
pub fn client_message(error: &TransportError) -> String {
    log_rpc_error(error);
    match as_revert(error) {
        Some(revert) => revert.client_message(),
        None => RPC_FAILED.to_string(),
    }
}

pub fn log_rpc_error(error: &dyn std::fmt::Display) {
    #[cfg(feature = "telemetry")]
    tracing::warn!(error = %error, "batch-settlement RPC request failed");
    #[cfg(not(feature = "telemetry"))]
    let _ = error;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_transport::{RpcError, TransportErrorKind};

    const SECRET: &str = "SECRET-TOKEN";

    fn error_resp(code: i64, message: &str, data: Option<&str>) -> TransportError {
        let payload = serde_json::json!({ "code": code, "message": message, "data": data });
        RpcError::ErrorResp(serde_json::from_value(payload).unwrap())
    }

    #[test]
    fn a_revert_keeps_its_data() {
        let error = error_resp(3, "execution reverted", Some("0x8baa579f"));
        let revert = as_revert(&error).unwrap();
        let selector = Bytes::from_static(&[0x8b, 0xaa, 0x57, 0x9f]);
        assert_eq!(revert.data, Some(selector));
        assert_eq!(client_message(&error), "execution reverted: 0x8baa579f");
    }

    /// The node message is not chain data, so a revert sends fixed text only.
    #[test]
    fn a_revert_never_sends_the_node_message() {
        let message = format!("execution reverted: see https://rpc.example/v2/{SECRET}");
        let error = error_resp(3, &message, Some("0x"));
        assert_eq!(client_message(&error), "execution reverted: 0x");
        let error = error_resp(3, &message, None);
        assert_eq!(client_message(&error), EXECUTION_REVERTED);
    }

    /// A rate limit or node fault is retryable, never a verdict on the payload.
    #[test]
    fn node_errors_that_are_not_reverts_are_not_reverts() {
        for error in [
            error_resp(429, "too many requests", None),
            error_resp(-32603, "internal error", None),
        ] {
            assert_eq!(as_revert(&error), None);
            assert_eq!(client_message(&error), RPC_FAILED);
        }
    }

    /// A gateway, internal, or rate-limit error that says "revert" is not a
    /// revert, and its text never reaches the client.
    #[test]
    fn revert_text_under_another_code_is_not_a_revert() {
        let url = format!("https://rpc.example/v2/{SECRET}");
        for (code, message) in [
            (
                -32603,
                format!("internal error: upstream {url} execution reverted"),
            ),
            (-32000, format!("gateway: execution reverted at {url}")),
            (429, format!("rate limit exceeded, revert to {url}")),
            (-32005, format!("revert later, key {SECRET}")),
        ] {
            let error = error_resp(code, &message, Some("0xdead"));
            assert_eq!(as_revert(&error), None, "{code}");
            let text = client_message(&error);
            assert_eq!(text, RPC_FAILED, "{code}");
            assert!(!text.contains(SECRET));
        }
    }

    #[test]
    fn transport_error_text_never_reaches_the_client() {
        let error = TransportErrorKind::custom_str("error sending request for url (test-url)");
        assert_eq!(as_revert(&error), None);
        assert_eq!(client_message(&error), RPC_FAILED);
        let error = TransportErrorKind::custom_str("execution reverted at https://rpc.example/key");
        assert_eq!(as_revert(&error), None);
        assert_eq!(client_message(&error), RPC_FAILED);
    }
}
