//! Simulation, broadcast, and receipt classification for contract writes.
//!
//! Every write targets the canonical `x402BatchSettlement` address and is
//! simulated from the same sender that later broadcasts it. A broadcast is
//! never retried: an unconfirmed transaction becomes `settlement_pending`
//! with its hash, and a mined revert keeps its hash.

use alloy_primitives::{Address, Bytes};
use alloy_provider::Provider;
use alloy_rpc_types_eth::{BlockId, TransactionReceipt, TransactionRequest};
use alloy_sol_types::SolEvent;

use super::response::BatchSettlementSettleResponse;
use super::rpc_error::{client_message, log_rpc_error};
use crate::chain::{Eip155MetaTransactionProvider, MetaTransaction, MetaTransactionSendError};
use crate::v2_eip155_batch_settlement::constants::BATCH_SETTLEMENT_ADDRESS;

/// Shared inputs for every settle action.
pub struct SettleContext<'a, P> {
    pub provider: &'a P,
    pub chain_id: u64,
    pub network: &'a str,
    pub sender: Address,
}

/// One contract write and the error codes for its two failure stages.
pub struct ContractWrite {
    pub calldata: Bytes,
    pub gas_limit: Option<u64>,
    pub simulation_failed: &'static str,
    pub transaction_failed: &'static str,
}

/// `eth_call` against the canonical contract from `sender`. A write that
/// broadcasts with a gas limit must pass the same limit here. With `None`, the
/// node uses its call gas cap. The error is client-safe text: the revert
/// detail, or fixed text for an RPC failure.
pub async fn simulate<P: Provider>(
    provider: &P,
    sender: Address,
    calldata: &Bytes,
    gas_limit: Option<u64>,
) -> Result<(), String> {
    let mut request = TransactionRequest::default()
        .from(sender)
        .to(BATCH_SETTLEMENT_ADDRESS)
        .input(calldata.clone().into());
    request.gas = gas_limit;
    provider
        .call(request)
        .await
        .map(|_| ())
        .map_err(|error| client_message(&error))
}

/// Simulates, broadcasts once, and returns the successful receipt.
///
/// Every other outcome is already a complete failure response.
pub async fn simulate_and_submit<P>(
    context: &SettleContext<'_, P>,
    write: ContractWrite,
) -> Result<TransactionReceipt, BatchSettlementSettleResponse>
where
    P: Eip155MetaTransactionProvider,
    P::Error: Into<MetaTransactionSendError>,
{
    let network = context.network;
    let inner = context.provider.inner();
    if let Err(message) = simulate(inner, context.sender, &write.calldata, write.gas_limit).await {
        let reason = write.simulation_failed;
        return Err(BatchSettlementSettleResponse::failure_with_message(
            network, reason, message,
        ));
    }

    let mut transaction =
        MetaTransaction::new(BATCH_SETTLEMENT_ADDRESS, write.calldata).with_from(context.sender);
    if let Some(gas_limit) = write.gas_limit {
        transaction = transaction.with_gas_limit(gas_limit);
    }
    let receipt = match context.provider.send_transaction(transaction).await {
        Ok(receipt) => receipt,
        Err(error) => {
            return Err(send_failure(
                network,
                write.transaction_failed,
                error.into(),
            ));
        }
    };
    if !receipt.status() {
        return Err(BatchSettlementSettleResponse::mined_failure(
            network,
            write.transaction_failed,
            receipt.transaction_hash,
            "transaction reverted".into(),
        ));
    }
    Ok(receipt)
}

fn send_failure(
    network: &str,
    reason: &str,
    error: MetaTransactionSendError,
) -> BatchSettlementSettleResponse {
    let message = send_error_message(&error);
    match error.broadcast_tx_hash() {
        Some(tx_hash) => {
            BatchSettlementSettleResponse::settlement_pending(network, tx_hash, message)
        }
        None => BatchSettlementSettleResponse::failure_with_message(network, reason, message),
    }
}

/// Only a revert (for example in the gas estimate) keeps its detail; the rest
/// can carry transport text, so it goes to the log.
fn send_error_message(error: &MetaTransactionSendError) -> String {
    match error {
        MetaTransactionSendError::Transport(error) => client_message(error),
        MetaTransactionSendError::Unconfirmed { .. } => {
            log_rpc_error(error);
            UNCONFIRMED.to_string()
        }
        MetaTransactionSendError::Custom(_) => {
            log_rpc_error(error);
            NOT_SENT.to_string()
        }
    }
}

const UNCONFIRMED: &str = "transaction was broadcast, but no receipt was confirmed";
const NOT_SENT: &str = "transaction submission failed";

/// Decodes every `E` the canonical contract emitted in this receipt.
pub fn contract_events<E: SolEvent>(receipt: &TransactionReceipt) -> Vec<E> {
    receipt
        .inner
        .logs()
        .iter()
        .filter(|log| log.address() == BATCH_SETTLEMENT_ADDRESS)
        .filter_map(|log| E::decode_log_data(log.data()).ok())
        .collect()
}

/// The block that holds the receipt, for block-scoped state reads.
pub fn receipt_block(receipt: &TransactionReceipt) -> Option<BlockId> {
    receipt.block_number.map(BlockId::number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, LogData, U256};
    use alloy_sol_types::SolEvent;

    use crate::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::Settled;

    fn receipt_with_log(address: Address, data: LogData) -> TransactionReceipt {
        let log = serde_json::json!({
            "address": address,
            "topics": data.topics(),
            "data": data.data,
            "blockHash": B256::repeat_byte(2),
            "blockNumber": "0x10",
            "transactionHash": B256::repeat_byte(1),
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "removed": false,
        });
        serde_json::from_value(serde_json::json!({
            "transactionHash": B256::repeat_byte(1),
            "blockHash": B256::repeat_byte(2),
            "blockNumber": "0x10",
            "logsBloom": format!("0x{}", "00".repeat(256)),
            "gasUsed": "0x1",
            "status": "0x1",
            "contractAddress": null,
            "cumulativeGasUsed": "0x1",
            "transactionIndex": "0x0",
            "from": Address::repeat_byte(3),
            "to": BATCH_SETTLEMENT_ADDRESS,
            "type": "0x2",
            "effectiveGasPrice": "0x1",
            "logs": [log]
        }))
        .unwrap()
    }

    fn settled(amount: u128) -> LogData {
        Settled {
            receiver: Address::repeat_byte(4),
            token: Address::repeat_byte(5),
            sender: Address::repeat_byte(6),
            amount,
        }
        .encode_log_data()
    }

    #[test]
    fn decodes_events_from_the_canonical_contract() {
        let receipt = receipt_with_log(BATCH_SETTLEMENT_ADDRESS, settled(700));
        let events = contract_events::<Settled>(&receipt);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].amount, 700);
        assert_eq!(receipt_block(&receipt), Some(BlockId::number(16)));
    }

    /// A lookalike event from another contract must not count as success.
    #[test]
    fn ignores_events_from_other_contracts() {
        let receipt = receipt_with_log(Address::repeat_byte(9), settled(700));
        assert!(contract_events::<Settled>(&receipt).is_empty());
    }

    #[test]
    fn unconfirmed_broadcast_becomes_settlement_pending() {
        let tx_hash = B256::from(U256::from(7u64));
        let error = MetaTransactionSendError::Unconfirmed {
            tx_hash,
            message: "timeout".into(),
        };
        let response = send_failure("eip155:143", "reason", error);
        assert_eq!(response.error_reason.as_deref(), Some("settlement_pending"));
        assert_eq!(response.transaction, format!("{tx_hash:#x}"));
    }

    #[test]
    fn send_failure_before_broadcast_has_no_hash() {
        let error = MetaTransactionSendError::Custom("rejected".into());
        let response = send_failure("eip155:143", "reason", error);
        assert_eq!(response.error_reason.as_deref(), Some("reason"));
        assert!(response.transaction.is_empty());
    }
}
