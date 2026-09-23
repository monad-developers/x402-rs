//! Concurrent first deposit requests for one authorization, through the
//! public facilitator. The first broadcast stops until the test releases it,
//! so each overlap is fixed and does not depend on timing.

#![cfg(feature = "facilitator")]

mod batch_settlement_common;

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use alloy_network::Ethereum;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_provider::RootProvider;
use alloy_rpc_types_eth::TransactionReceipt;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, SolEvent, SolValue};
use alloy_transport::mock::{Asserter, MockResponse};
use batch_settlement_common::rpc::{Request, Route, success};
use batch_settlement_common::*;
use serde_json::{Value, json};
use tokio::sync::{Notify, oneshot};
use x402_chain_eip155::V2Eip155BatchSettlement;
use x402_chain_eip155::chain::{
    Eip155ChainReference, Eip155MetaTransactionProvider, Eip155SignerAddresses, MetaTransaction,
    MetaTransactionSendError,
};
use x402_chain_eip155::v2_eip155_batch_settlement::facilitator::abi::X402BatchSettlement::{
    Deposited, channelsCall, pendingWithdrawalsCall, refundNonceCall,
};
use x402_types::chain::{ChainId, ChainProviderOps};
use x402_types::proto;
use x402_types::scheme::{X402SchemeFacilitator, X402SchemeFacilitatorBuilder};

const AUTHORIZER: Address = Address::repeat_byte(0x44);
/// The first signer is the `from` of the `receipt` fixture.
const SIGNERS: [Address; 2] = [Address::repeat_byte(0xfa), Address::repeat_byte(0xfb)];
/// The hash of the `receipt` fixture.
const TX: B256 = B256::repeat_byte(1);
const DEPOSIT_PAYLOAD: &str = "invalid_batch_settlement_evm_deposit_payload";

type Outcome = Result<TransactionReceipt, MetaTransactionSendError>;

/// The first broadcast waits for the outcome that the test sends. A later
/// broadcast ends at once as unconfirmed, with a hash from its index.
struct GatedProvider {
    mock: MockProvider,
    next_signer: AtomicUsize,
    senders: Mutex<Vec<Option<Address>>>,
    entered: Notify,
    first: Mutex<Option<oneshot::Receiver<Outcome>>>,
}

impl GatedProvider {
    fn sends(&self) -> Vec<Option<Address>> {
        self.senders.lock().unwrap().clone()
    }
}

impl Eip155MetaTransactionProvider for GatedProvider {
    type Error = MetaTransactionSendError;
    type Inner = RootProvider<Ethereum>;

    fn inner(&self) -> &Self::Inner {
        self.mock.inner()
    }

    fn chain(&self) -> &Eip155ChainReference {
        self.mock.chain()
    }

    async fn send_transaction(&self, tx: MetaTransaction) -> Outcome {
        let index = {
            let mut senders = self.senders.lock().unwrap();
            senders.push(tx.from);
            senders.len() - 1
        };
        let gate = self.first.lock().unwrap().take();
        let Some(gate) = gate else {
            let tx_hash = B256::from(U256::from(0x100 + index));
            let message = "timeout".into();
            return Err(MetaTransactionSendError::Unconfirmed { tx_hash, message });
        };
        self.entered.notify_one();
        gate.await.expect("the test sends the first outcome")
    }
}

impl ChainProviderOps for GatedProvider {
    fn signer_addresses(&self) -> Vec<String> {
        SIGNERS.iter().map(Address::to_string).collect()
    }

    fn chain_id(&self) -> ChainId {
        self.mock.chain().into()
    }
}

/// Each settle gets the next signer, so two identical requests use
/// different signers.
impl Eip155SignerAddresses for GatedProvider {
    fn signer_addresses(&self) -> Vec<Address> {
        let index = self.next_signer.fetch_add(1, Ordering::SeqCst);
        vec![SIGNERS[index % SIGNERS.len()]]
    }
}

fn bytes(encoded: Vec<u8>) -> Option<MockResponse> {
    Some(success(Bytes::from(encoded)))
}

/// Answers every read by method and target, so that concurrent requests do
/// not depend on a FIFO order. The channel holds 1000 at the receipt block.
fn route(receipt: Arc<Mutex<Option<Value>>>) -> Route {
    Arc::new(move |request: &Request| match request.method.as_str() {
        "eth_getCode" => bytes(Vec::new()),
        "eth_getTransactionReceipt" => Some(success(receipt.lock().unwrap().clone())),
        "eth_call" if request.to() == Some(TOKEN) => bytes(U256::from(5_000u64).abi_encode()),
        "eth_call" => {
            let balance = if request.block() == Some("0x10") {
                1_000u128
            } else {
                0
            };
            let input = request.input();
            match input.get(..4) {
                Some(s) if s == channelsCall::SELECTOR => {
                    bytes((balance, 0u128).abi_encode_params())
                }
                Some(s) if s == pendingWithdrawalsCall::SELECTOR => {
                    bytes((0u128, U256::ZERO).abi_encode_params())
                }
                Some(s) if s == refundNonceCall::SELECTOR => bytes(U256::ZERO.abi_encode()),
                _ => bytes(Vec::new()),
            }
        }
        _ => None,
    })
}

struct Race {
    provider: Arc<GatedProvider>,
    facilitator: Arc<dyn X402SchemeFacilitator>,
    release: Option<oneshot::Sender<Outcome>>,
    receipt: Arc<Mutex<Option<Value>>>,
    payer: PrivateKeySigner,
    payload: Value,
}

impl Race {
    fn new() -> Self {
        let receipt = Arc::new(Mutex::new(None));
        let mock = MockProvider::routed(Asserter::new(), Some(route(receipt.clone())));
        let (release, gate) = oneshot::channel();
        let provider = Arc::new(GatedProvider {
            mock,
            next_signer: AtomicUsize::new(0),
            senders: Mutex::new(Vec::new()),
            entered: Notify::new(),
            first: Mutex::new(Some(gate)),
        });
        let facilitator = V2Eip155BatchSettlement
            .build(provider.clone(), None)
            .unwrap();
        let payer = PrivateKeySigner::random();
        let payload = erc3009_deposit(&payer, AUTHORIZER);
        Self {
            provider,
            facilitator: Arc::from(facilitator),
            release: Some(release),
            receipt,
            payer,
            payload,
        }
    }

    fn body(&self) -> String {
        request(self.payload.clone(), &requirements(AUTHORIZER))
    }

    fn settle(&self, body: String) -> impl Future<Output = Value> + Send + 'static {
        let facilitator = self.facilitator.clone();
        async move {
            let raw = serde_json::value::RawValue::from_string(body).unwrap();
            let request = proto::SettleRequest::from(raw);
            facilitator.settle(&request).await.unwrap().0
        }
    }

    /// Starts the first request and returns when it is inside its broadcast.
    async fn start_first(&self) -> tokio::task::JoinHandle<Value> {
        let first = tokio::spawn(self.settle(self.body()));
        self.provider.entered.notified().await;
        assert_eq!(self.provider.sends(), [Some(SIGNERS[0])]);
        first
    }

    /// Starts an identical request, polls it one time, and checks that it
    /// waits with no broadcast.
    async fn start_waiting(&self) -> Pin<Box<dyn Future<Output = Value> + Send>> {
        let mut second = Box::pin(self.settle(self.body()));
        let early = poll_fn(|context| match second.as_mut().poll(context) {
            Poll::Ready(output) => Poll::Ready(Some(output)),
            Poll::Pending => Poll::Ready(None),
        })
        .await;
        assert_eq!(
            self.provider.sends().len(),
            1,
            "second broadcast: {early:?}"
        );
        assert!(early.is_none(), "the second request waits: {early:?}");
        second
    }

    /// Ends the first broadcast. The RPC then serves the same receipt.
    fn release_first(&mut self, outcome: Outcome) {
        let mined = outcome
            .as_ref()
            .ok()
            .map(|r| serde_json::to_value(r).unwrap());
        *self.receipt.lock().unwrap() = mined;
        let release = self.release.take().unwrap();
        release.send(outcome).unwrap();
    }

    fn mined_deposit(&self) -> TransactionReceipt {
        let config = channel_config(self.payer.address(), self.payer.address(), AUTHORIZER);
        let event = Deposited {
            channelId: channel_id(&config),
            sender: SIGNERS[0],
            amount: 1_000,
            newBalance: 1_000,
        };
        receipt(true, &[event.encode_log_data()])
    }

    fn receipt_reads(&self) -> Vec<Request> {
        self.provider.mock.requests_for("eth_getTransactionReceipt")
    }
}

/// A current-thread runtime runs one task at a time, so the routed answers
/// cannot interleave.
fn run_local<F: Future>(future: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(future)
}

fn assert_success(response: &Value) {
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["transaction"], format!("{TX:#x}"), "{response}");
    assert_eq!(response["amount"], "1000", "{response}");
    assert_eq!(response["extra"]["channelState"]["balance"], "1000");
}

#[test]
fn an_identical_request_during_the_first_broadcast_gets_its_receipt() {
    let mut race = Race::new();
    run_local(async {
        let first = race.start_first().await;
        let second = race.start_waiting().await;

        race.release_first(Ok(race.mined_deposit()));
        let first = first.await.unwrap();
        let second = second.await;
        assert_success(&first);
        assert_success(&second);
        assert_eq!(first["extra"], second["extra"]);
    });
    assert_eq!(race.provider.sends(), [Some(SIGNERS[0])], "one broadcast");
    let reads = race.receipt_reads();
    assert_eq!(reads.len(), 1, "the second request reads the first receipt");
    assert_eq!(reads[0].params[0], json!(TX));
}

/// The reported race: the losing broadcast must not replace the first hash.
#[test]
fn an_identical_request_during_an_unconfirmed_broadcast_keeps_its_hash() {
    let mut race = Race::new();
    run_local(async {
        let first = race.start_first().await;
        let second = race.start_waiting().await;

        let message = "timeout".into();
        race.release_first(Err(MetaTransactionSendError::Unconfirmed {
            tx_hash: TX,
            message,
        }));
        for response in [first.await.unwrap(), second.await] {
            assert_eq!(response["errorReason"], "settlement_pending", "{response}");
            assert_eq!(response["transaction"], format!("{TX:#x}"), "{response}");
        }

        *race.receipt.lock().unwrap() = Some(serde_json::to_value(race.mined_deposit()).unwrap());
        assert_success(&race.settle(race.body()).await);
    });
    assert_eq!(race.provider.sends().len(), 1, "one broadcast");
}

type Change = fn(&mut Value, &mut Value);

#[test]
fn a_changed_request_during_the_first_broadcast_is_refused() {
    let changes: [(&str, Change); 3] = [
        ("voucher amount", |payload, _| {
            payload["voucher"]["maxClaimableAmount"] = json!("200")
        }),
        ("voucher signature", |payload, _| {
            payload["voucher"]["signature"] = json!(format!("0x{}", "1b".repeat(65)))
        }),
        ("requirement amount", |_, requirements| {
            requirements["amount"] = json!("5")
        }),
    ];
    let mut race = Race::new();
    run_local(async {
        let first = race.start_first().await;
        let requests = race.provider.mock.requests().len();
        for (name, change) in changes {
            let mut payload = race.payload.clone();
            let mut requirements = serde_json::to_value(requirements(AUTHORIZER)).unwrap();
            change(&mut payload, &mut requirements);
            let requirements = serde_json::from_value(requirements).unwrap();
            let response = race.settle(request(payload, &requirements)).await;
            assert_eq!(response["success"], false, "{name}: {response}");
            assert_eq!(
                response["errorReason"], DEPOSIT_PAYLOAD,
                "{name}: {response}"
            );
            assert_eq!(response["transaction"], "", "{name}");
        }
        assert_eq!(race.provider.mock.requests().len(), requests, "no RPC read");

        race.release_first(Ok(race.mined_deposit()));
        assert_success(&first.await.unwrap());
    });
    assert_eq!(race.provider.sends().len(), 1, "one broadcast");
}

#[test]
fn another_authorization_broadcasts_during_the_first_broadcast() {
    let mut race = Race::new();
    run_local(async {
        let first = race.start_first().await;
        let other = erc3009_deposit(&PrivateKeySigner::random(), AUTHORIZER);
        let response = race.settle(request(other, &requirements(AUTHORIZER))).await;
        assert_eq!(response["errorReason"], "settlement_pending", "{response}");
        let other_hash = B256::from(U256::from(0x101));
        assert_eq!(response["transaction"], format!("{other_hash:#x}"));
        assert_eq!(race.provider.sends(), [Some(SIGNERS[0]), Some(SIGNERS[1])]);

        race.release_first(Ok(race.mined_deposit()));
        assert_success(&first.await.unwrap());
    });
    assert_eq!(race.provider.sends().len(), 2);
}

/// The first attempt sends nothing, so the waiting request runs every check
/// and broadcasts from its own signer.
#[test]
fn an_identical_request_broadcasts_after_an_unsent_first_attempt() {
    let mut race = Race::new();
    run_local(async {
        let first = race.start_first().await;
        let second = race.start_waiting().await;

        let unsent = MetaTransactionSendError::Custom("nonce too low".into());
        race.release_first(Err(unsent));
        let first = first.await.unwrap();
        assert_eq!(first["transaction"], "", "{first}");
        let second = second.await;
        assert_eq!(second["errorReason"], "settlement_pending", "{second}");
    });
    assert_eq!(race.provider.sends(), [Some(SIGNERS[0]), Some(SIGNERS[1])]);
    assert!(race.receipt_reads().is_empty());
}

#[test]
fn the_success_record_serves_the_signer_that_broadcast() {
    let mut race = Race::new();
    run_local(async {
        let first = race.start_first().await;
        race.release_first(Ok(race.mined_deposit()));
        assert_success(&first.await.unwrap());
        // This request gets the second signer. The receipt is from the first.
        assert_success(&race.settle(race.body()).await);
    });
    assert_eq!(race.provider.sends().len(), 1, "no second broadcast");
    assert_eq!(race.receipt_reads().len(), 1);
}
