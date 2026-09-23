//! Shared fixtures for the batch-settlement integration tests.
//!
//! `MockProvider` answers reads from a queued `Asserter` (strict FIFO, so each
//! test pins the exact RPC order) or from an optional route. It records every
//! RPC request, and it records every write instead of sending it.

#![allow(dead_code)]

pub mod rpc;

use std::sync::{Arc, Mutex};

use rpc::{RecordingTransport, Request, Route};

use alloy_network::Ethereum;
use alloy_primitives::{Address, B256, Bytes, LogData, U256};
use alloy_provider::RootProvider;
use alloy_rpc_client::RpcClient;
use alloy_rpc_types_eth::TransactionReceipt;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolValue;
use alloy_transport::mock::Asserter;
use serde_json::{Value, json};
use x402_chain_eip155::chain::{
    Eip155ChainReference, Eip155MetaTransactionProvider, Eip155SignerAddresses, MetaTransaction,
    MetaTransactionSendError,
};
use x402_chain_eip155::v2_eip155_batch_settlement::constants::BATCH_SETTLEMENT_ADDRESS;
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::compute_channel_id;
use x402_chain_eip155::v2_eip155_batch_settlement::{
    BatchSettlementPaymentRequirementsExtra, BatchSettlementScheme, ChannelConfig,
    PaymentRequirements, U256String,
};
use x402_types::chain::{ChainId, ChainProviderOps};

pub const CHAIN_ID: u64 = 143;
pub const NETWORK: &str = "eip155:143";
pub const TOKEN: Address = Address::repeat_byte(0x55);
pub const RECEIVER: Address = Address::repeat_byte(0x33);

/// A write the facilitator asked the provider to broadcast.
#[derive(Debug, Clone)]
pub struct SentWrite {
    pub to: Address,
    pub from: Option<Address>,
    pub calldata: Bytes,
    pub gas_limit: Option<u64>,
}

pub struct MockProvider {
    inner: RootProvider<Ethereum>,
    chain: Eip155ChainReference,
    signer: Address,
    outcome: Mutex<Option<Result<TransactionReceipt, MetaTransactionSendError>>>,
    pub sent: Mutex<Vec<SentWrite>>,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl MockProvider {
    pub fn new(asserter: Asserter) -> Self {
        Self::routed(asserter, None)
    }

    /// `route` answers the requests it recognizes; the queue answers the rest.
    pub fn routed(asserter: Asserter, route: Option<Route>) -> Self {
        let transport = RecordingTransport::new(asserter, route);
        let requests = transport.requests();
        Self {
            inner: RootProvider::new(RpcClient::new(transport, true)),
            chain: Eip155ChainReference::new(CHAIN_ID),
            signer: Address::repeat_byte(0xfa),
            outcome: Mutex::new(None),
            sent: Mutex::new(Vec::new()),
            requests,
        }
    }

    /// Every RPC request in send order.
    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    /// The requests for one method, in send order.
    pub fn requests_for(&self, method: &str) -> Vec<Request> {
        let requests = self.requests();
        requests
            .into_iter()
            .filter(|r| r.method == method)
            .collect()
    }

    /// The single broadcast outcome for this test.
    pub fn with_outcome(
        self,
        outcome: Result<TransactionReceipt, MetaTransactionSendError>,
    ) -> Self {
        *self.outcome.lock().unwrap() = Some(outcome);
        self
    }

    pub fn signer(&self) -> Address {
        self.signer
    }

    pub fn sent(&self) -> Vec<SentWrite> {
        self.sent.lock().unwrap().clone()
    }
}

impl Eip155MetaTransactionProvider for MockProvider {
    type Error = MetaTransactionSendError;
    type Inner = RootProvider<Ethereum>;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    fn chain(&self) -> &Eip155ChainReference {
        &self.chain
    }

    async fn send_transaction(
        &self,
        tx: MetaTransaction,
    ) -> Result<TransactionReceipt, Self::Error> {
        self.sent.lock().unwrap().push(SentWrite {
            to: tx.to,
            from: tx.from,
            calldata: tx.calldata,
            gas_limit: tx.gas_limit,
        });
        self.outcome
            .lock()
            .unwrap()
            .take()
            .expect("test broadcast more than once")
    }
}

impl ChainProviderOps for MockProvider {
    fn signer_addresses(&self) -> Vec<String> {
        vec![self.signer.to_string()]
    }

    fn chain_id(&self) -> ChainId {
        self.chain.into()
    }
}

impl Eip155SignerAddresses for MockProvider {
    fn signer_addresses(&self) -> Vec<Address> {
        vec![self.signer]
    }
}

pub fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Runtime::new().unwrap().block_on(future)
}

/// Queues ABI-encoded `eth_call` / `eth_getCode` results in call order.
pub fn push_bytes(asserter: &Asserter, bytes: Vec<u8>) {
    asserter.push_success(&Bytes::from(bytes));
}

/// Queues the three channel reads: `channels`, `pendingWithdrawals`, `refundNonce`.
pub fn push_channel_state(asserter: &Asserter, balance: u128, total: u128, nonce: u64) {
    push_bytes(asserter, (balance, total).abi_encode_params());
    push_bytes(asserter, (0u128, U256::ZERO).abi_encode_params());
    push_bytes(asserter, U256::from(nonce).abi_encode());
}

/// Queues one settlement `multicall` of `channels` views. It returns
/// `(balance, totalClaimed)` for each channel.
pub fn push_channel_totals(asserter: &Asserter, totals: &[(u128, u128)]) {
    let results: Vec<Bytes> = totals
        .iter()
        .map(|totals| totals.abi_encode_params().into())
        .collect();
    push_bytes(asserter, results.abi_encode());
}

/// Queues the claim reads: the pinned block number, then the channel totals.
pub fn push_claim_totals(asserter: &Asserter, block: &str, totals: &[(u128, u128)]) {
    asserter.push_success(&block);
    push_channel_totals(asserter, totals);
}

pub fn no_code(asserter: &Asserter) {
    push_bytes(asserter, Vec::new());
}

pub fn channel_config(
    payer: Address,
    payer_authorizer: Address,
    authorizer: Address,
) -> ChannelConfig {
    ChannelConfig {
        payer: payer.into(),
        payer_authorizer: payer_authorizer.into(),
        receiver: RECEIVER.into(),
        receiver_authorizer: authorizer.into(),
        token: TOKEN.into(),
        withdraw_delay: 900u64.try_into().unwrap(),
        salt: B256::ZERO,
    }
}

pub fn requirements(authorizer: Address) -> PaymentRequirements {
    PaymentRequirements {
        scheme: BatchSettlementScheme,
        network: NETWORK.parse().unwrap(),
        amount: U256String(U256::from(100u64)),
        pay_to: RECEIVER.into(),
        max_timeout_seconds: 300,
        asset: TOKEN.into(),
        extra: BatchSettlementPaymentRequirementsExtra {
            receiver_authorizer: Some(authorizer.into()),
            withdraw_delay: Some(900),
            name: Some("USDC".into()),
            version: Some("2".into()),
            ..Default::default()
        },
    }
}

pub fn sign(signer: &PrivateKeySigner, digest: B256) -> Bytes {
    Bytes::from(signer.sign_hash_sync(&digest).unwrap().as_bytes().to_vec())
}

pub fn channel_id(config: &ChannelConfig) -> B256 {
    compute_channel_id(config, CHAIN_ID)
}

/// A request body in the wire shape the HTTP layer hands the facilitator.
pub fn request(payload: Value, requirements: &PaymentRequirements) -> String {
    json!({
        "x402Version": 2,
        "paymentPayload": {
            "x402Version": 2,
            "accepted": requirements,
            "payload": payload,
        },
        "paymentRequirements": requirements,
    })
    .to_string()
}

pub fn receipt(status: bool, logs: &[LogData]) -> TransactionReceipt {
    let logs: Vec<Value> = logs
        .iter()
        .enumerate()
        .map(|(index, data)| {
            json!({
                "address": BATCH_SETTLEMENT_ADDRESS,
                "topics": data.topics(),
                "data": data.data,
                "blockHash": B256::repeat_byte(2),
                "blockNumber": "0x10",
                "transactionHash": B256::repeat_byte(1),
                "transactionIndex": "0x0",
                "logIndex": format!("{index:#x}"),
                "removed": false,
            })
        })
        .collect();
    serde_json::from_value(json!({
        "transactionHash": B256::repeat_byte(1),
        "blockHash": B256::repeat_byte(2),
        "blockNumber": "0x10",
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "gasUsed": "0x1",
        "status": if status { "0x1" } else { "0x0" },
        "contractAddress": null,
        "cumulativeGasUsed": "0x1",
        "transactionIndex": "0x0",
        "from": Address::repeat_byte(0xfa),
        "to": BATCH_SETTLEMENT_ADDRESS,
        "type": "0x2",
        "effectiveGasPrice": "0x1",
        "logs": logs,
    }))
    .unwrap()
}

/// A signed ERC-3009 deposit of 1000 with a voucher for 100.
pub fn erc3009_deposit(payer: &PrivateKeySigner, authorizer: Address) -> Value {
    let config = channel_config(payer.address(), payer.address(), authorizer);
    erc3009_deposit_on(payer, &config)
}

/// A signed ERC-3009 deposit of 1000 on `config`, with a voucher for 100.
pub fn erc3009_deposit_on(payer: &PrivateKeySigner, config: &ChannelConfig) -> Value {
    use alloy_sol_types::{SolStruct, eip712_domain};
    use x402_chain_eip155::v2_eip155_batch_settlement::constants::ERC3009_DEPOSIT_COLLECTOR_ADDRESS;
    use x402_chain_eip155::v2_eip155_batch_settlement::encoding::build_erc3009_deposit_nonce;
    use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::ReceiveWithAuthorization;
    use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::compute_voucher_digest;

    let id = channel_id(config);
    let valid_before = U256::from(x402_types::timestamp::UnixTimestamp::now().as_secs() + 600);
    let salt = B256::repeat_byte(0x77);
    let authorization = ReceiveWithAuthorization {
        from: payer.address(),
        to: ERC3009_DEPOSIT_COLLECTOR_ADDRESS,
        value: U256::from(1_000u64),
        validAfter: U256::ZERO,
        validBefore: valid_before,
        nonce: build_erc3009_deposit_nonce(id, salt),
    };
    let domain = eip712_domain! {
        name: "USDC", version: "2", chain_id: CHAIN_ID, verifying_contract: TOKEN,
    };
    let voucher_digest =
        compute_voucher_digest(id, alloy_primitives::U128::from(100u128), CHAIN_ID);
    json!({
        "type": "deposit",
        "channelConfig": config,
        "voucher": {
            "channelId": id,
            "maxClaimableAmount": "100",
            "signature": sign(payer, voucher_digest),
        },
        "deposit": {
            "amount": "1000",
            "authorization": { "erc3009Authorization": {
                "validAfter": "0",
                "validBefore": valid_before.to_string(),
                "salt": salt,
                "signature": sign(payer, authorization.eip712_signing_hash(&domain)),
            }},
        },
    })
}

/// Queues the reads a deposit check makes before its simulation.
pub fn push_deposit_reads(asserter: &Asserter, payer_balance: u64) {
    no_code(asserter);
    push_channel_state(asserter, 0, 0, 0);
    push_bytes(asserter, U256::from(payer_balance).abi_encode());
}
