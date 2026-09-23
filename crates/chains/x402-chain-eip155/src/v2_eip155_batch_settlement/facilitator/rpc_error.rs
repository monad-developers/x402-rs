//! Client-safe text for RPC failures.
//!
//! A transport error can carry the RPC URL, and many providers put the API
//! key in that URL. Responses therefore carry fixed text for every failure
//! except an EVM revert, whose reason and data come from the chain. The full
//! error goes only to the log.

use alloy_primitives::Bytes;
use alloy_transport::{RpcError, TransportError};

/// Client text for a failed RPC request that is not a revert.
pub const RPC_FAILED: &str = "RPC request failed";

/// The node ran the call and the EVM reverted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revert {
    pub message: String,
    pub data: Option<Bytes>,
}

impl Revert {
    /// The node's revert message and the raw revert data.
    pub fn client_message(&self) -> String {
        match &self.data {
            Some(data) => format!("{}: {data}", self.message),
            None => self.message.clone(),
        }
    }
}

/// `Some` only for an execution revert (code 3, or a message that says
/// "revert"). Rate limits, internal errors, and transport errors are `None`.
pub fn as_revert(error: &TransportError) -> Option<Revert> {
    let RpcError::ErrorResp(payload) = error else {
        return None;
    };
    if payload.code != 3 && !payload.message.contains("revert") {
        return None;
    }
    Some(Revert {
        message: payload.message.to_string(),
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
    use alloy_transport::TransportErrorKind;

    fn error_resp(code: i64, message: &'static str, data: Option<&str>) -> TransportError {
        let payload = serde_json::json!({ "code": code, "message": message, "data": data });
        RpcError::ErrorResp(serde_json::from_value(payload).unwrap())
    }

    #[test]
    fn a_revert_keeps_its_message_and_data() {
        let error = error_resp(3, "execution reverted", Some("0x8baa579f"));
        let revert = as_revert(&error).unwrap();
        let selector = Bytes::from_static(&[0x8b, 0xaa, 0x57, 0x9f]);
        assert_eq!(revert.data, Some(selector));
        assert_eq!(client_message(&error), "execution reverted: 0x8baa579f");
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

    #[test]
    fn transport_error_text_never_reaches_the_client() {
        let error = TransportErrorKind::custom_str("error sending request for url (test-url)");
        assert_eq!(as_revert(&error), None);
        assert_eq!(client_message(&error), RPC_FAILED);
    }
}
