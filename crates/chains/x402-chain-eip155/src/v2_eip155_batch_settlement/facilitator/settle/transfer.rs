//! `settle(receiver, token)`: sweep claimed funds to the receiver.
//!
//! `settle` is permissionless and idempotent. When nothing is owed, an
//! earlier settle already swept the funds, so the facilitator broadcasts
//! nothing and reports success with amount `0`. A settle that mines with no
//! `Settled` event (another settle landed first) is also a success with amount
//! `0`. The SDK channel managers clear their pending settle only on success.

use alloy_primitives::{Address, Bytes};
use alloy_provider::Provider;
use alloy_rpc_types_eth::{BlockId, TransactionRequest};
use alloy_sol_types::SolCall;

use crate::chain::{Eip155MetaTransactionProvider, MetaTransactionSendError};
use crate::v2_eip155_batch_settlement::constants::BATCH_SETTLEMENT_ADDRESS;
use crate::v2_eip155_batch_settlement::errors as err;
use crate::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::{
    self, Settled, settleCall,
};
use crate::v2_eip155_batch_settlement::facilitator::channel::pinned_block;
use crate::v2_eip155_batch_settlement::facilitator::response::BatchSettlementSettleResponse;
use crate::v2_eip155_batch_settlement::facilitator::rpc_error::{client_message, log_rpc_error};
use crate::v2_eip155_batch_settlement::facilitator::submit::{
    ContractWrite, SettleContext, contract_events, simulate_and_submit,
};
use crate::v2_eip155_batch_settlement::types::SettlePayload;

/// Whether the receiver has claimed funds that are not yet settled at `block`.
async fn is_owed<P>(
    context: &SettleContext<'_, P>,
    payload: &SettlePayload,
    block: BlockId,
) -> Result<bool, BatchSettlementSettleResponse>
where
    P: Eip155MetaTransactionProvider,
{
    let contract = X402BatchSettlement::new(BATCH_SETTLEMENT_ADDRESS, context.provider.inner());
    let totals = contract
        .receivers(payload.receiver.into(), payload.token.into())
        .block(block)
        .call()
        .await
        .map_err(|error| {
            log_rpc_error(&error);
            BatchSettlementSettleResponse::failure(context.network, err::ERR_RPC_READ_FAILED)
        })?;
    Ok(totals.totalClaimed > totals.totalSettled)
}

/// Builds the `settle` write with a gas limit estimated for the transfer path,
/// or `None` when nothing is owed.
///
/// `settle` is cheap when nothing is owed, and the token sets the cost of the
/// transfer path, so no fixed limit fits every token. An estimate from a node
/// that has not seen the last claim prices the cheap path, and the broadcast
/// then runs out of gas. The owed read and the estimate use one block, so the
/// estimate prices the transfer.
async fn transfer_write<P>(
    context: &SettleContext<'_, P>,
    payload: &SettlePayload,
) -> Result<Option<ContractWrite>, BatchSettlementSettleResponse>
where
    P: Eip155MetaTransactionProvider,
{
    let network = context.network;
    let provider = context.provider.inner();
    let block = pinned_block(provider)
        .await
        .map_err(|reason| BatchSettlementSettleResponse::failure(network, reason))?;
    if !is_owed(context, payload, block).await? {
        return Ok(None);
    }

    let calldata: Bytes = settleCall {
        receiver: payload.receiver.into(),
        token: payload.token.into(),
    }
    .abi_encode()
    .into();
    let request = TransactionRequest::default()
        .from(context.sender)
        .to(BATCH_SETTLEMENT_ADDRESS)
        .input(calldata.clone().into());
    let gas_limit = provider
        .estimate_gas(request)
        .block(block)
        .await
        .map_err(|error| {
            let reason = err::ERR_SETTLE_SIMULATION_FAILED;
            BatchSettlementSettleResponse::failure_with_message(
                network,
                reason,
                client_message(&error),
            )
        })?;
    Ok(Some(ContractWrite {
        calldata,
        gas_limit: Some(gas_limit),
        simulation_failed: err::ERR_SETTLE_SIMULATION_FAILED,
        transaction_failed: err::ERR_SETTLE_TRANSACTION_FAILED,
    }))
}

pub async fn settle_transfer<P>(
    context: &SettleContext<'_, P>,
    payload: &SettlePayload,
) -> BatchSettlementSettleResponse
where
    P: Eip155MetaTransactionProvider,
    P::Error: Into<MetaTransactionSendError>,
{
    let network = context.network;
    let receiver: Address = payload.receiver.into();
    let token: Address = payload.token.into();

    let write = match transfer_write(context, payload).await {
        Ok(Some(write)) => write,
        Ok(None) => {
            return BatchSettlementSettleResponse::success_without_transaction(network, "0".into());
        }
        Err(response) => return response,
    };
    let receipt = match simulate_and_submit(context, write).await {
        Ok(receipt) => receipt,
        Err(response) => return response,
    };
    let amount = contract_events::<Settled>(&receipt)
        .into_iter()
        .find(|event| event.receiver == receiver && event.token == token)
        .map_or(0, |event| event.amount);
    BatchSettlementSettleResponse::success(network, receipt.transaction_hash, amount.to_string())
}
