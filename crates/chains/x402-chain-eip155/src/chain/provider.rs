use alloy_network::{Ethereum as AlloyEthereum, EthereumWallet, NetworkWallet, TransactionBuilder};
use alloy_primitives::{Address, B256, Bytes};
use alloy_provider::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
use alloy_provider::{
    Identity, PendingTransactionError, Provider, ProviderBuilder, RootProvider, WalletProvider,
};
use alloy_rpc_client::RpcClient;
use alloy_rpc_types_eth::{BlockId, TransactionReceipt, TransactionRequest};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_transport::TransportError;
use alloy_transport::layers::{FallbackLayer, ThrottleLayer};
use alloy_transport_http::Http;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use tower::ServiceBuilder;
use x402_types::chain::{ChainId, ChainProviderOps, FromConfig};

#[cfg(feature = "telemetry")]
use tracing::Instrument;

use crate::chain::config::{Eip155ChainConfig, RpcConfig};
use crate::chain::pending_nonce_manager::PendingNonceManager;
use crate::chain::permit2::{EXACT_PERMIT2_PROXY_ADDRESS, PERMIT2_ADDRESS};
use crate::chain::types::Eip155ChainReference;
use crate::v1_eip155_exact::VALIDATOR_ADDRESS;

/// Combined filler type for gas, blob gas, nonce, and chain ID.
pub type InnerFiller = JoinFill<
    GasFiller,
    JoinFill<BlobGasFiller, JoinFill<NonceFiller<PendingNonceManager>, ChainIdFiller>>,
>;

static REQUIRED_CONTRACT_ADDRESSES: LazyLock<Vec<Address>> = LazyLock::new(|| {
    vec![
        VALIDATOR_ADDRESS,
        PERMIT2_ADDRESS,
        EXACT_PERMIT2_PROXY_ADDRESS,
    ]
});

/// The fully composed Ethereum provider type used in this project.
///
/// Combines multiple filler layers for gas, nonce, chain ID, blob gas, and wallet signing,
/// and wraps a [`RootProvider`] for actual JSON-RPC communication.
pub type InnerProvider = FillProvider<
    JoinFill<JoinFill<Identity, InnerFiller>, WalletFiller<EthereumWallet>>,
    RootProvider,
>;

/// Provider for interacting with EVM-compatible blockchains.
///
/// This provider handles:
/// - Transaction signing with multiple signers (round-robin selection)
/// - Nonce management with automatic reset on failures
/// - Gas estimation and pricing (EIP-1559 and legacy)
/// - Transaction receipt fetching with configurable timeouts
///
/// # Multiple Signers
///
/// The provider supports multiple signers for load distribution. When sending
/// transactions, signers are selected in round-robin fashion to distribute
/// the transaction load and avoid nonce conflicts.
///
/// # Nonce Management
///
/// Uses [`PendingNonceManager`] to track nonces locally and query pending
/// transactions on initialization. If a transaction fails, the nonce is
/// automatically reset to force a fresh query on the next transaction.
#[derive(Debug)]
pub struct Eip155ChainProvider {
    chain: Eip155ChainReference,
    eip1559: bool,
    flashblocks: bool,
    /// Whether to submit transactions via `eth_sendRawTransactionSync` (EIP-7966).
    sync_send: bool,
    receipt_timeout_secs: u64,
    inner: InnerProvider,
    /// Available signer addresses for round-robin selection.
    signer_addresses: Arc<Vec<Address>>,
    /// Current position in round-robin signer rotation.
    signer_cursor: Arc<AtomicUsize>,
    /// Nonce manager for resetting nonces on transaction failures.
    nonce_manager: PendingNonceManager,
}

impl Eip155ChainProvider {
    #[allow(unused_variables)] // chain_id is needed for tracing only here
    pub fn rpc_client(
        chain_id: ChainId,
        rpc: &[RpcConfig],
        poll_interval_ms: Option<u64>,
    ) -> RpcClient {
        let transports = rpc
            .iter()
            .filter_map(|provider_config| {
                let scheme = provider_config.http.scheme();
                let is_http = scheme == "http" || scheme == "https";
                if !is_http {
                    return None;
                }
                let rpc_url = provider_config.http.deref().clone();
                #[cfg(feature = "telemetry")]
                tracing::info!(chain=%chain_id, rpc_url=%rpc_url, rate_limit=?provider_config.rate_limit, "Using HTTP transport");
                let rate_limit = provider_config.rate_limit.unwrap_or(u32::MAX);
                let service = ServiceBuilder::new()
                    .layer(ThrottleLayer::new(rate_limit))
                    .service(Http::new(rpc_url));
                Some(service)
            })
            .collect::<Vec<_>>();
        let fallback = ServiceBuilder::new()
            .layer(
                FallbackLayer::default().with_active_transport_count(
                    NonZeroUsize::new(transports.len())
                        .expect("Non-zero amount of stateless transports"),
                ),
            )
            .service(transports);
        let client = RpcClient::new(fallback, false);
        // Override the receipt poll interval on fast-finality chains (e.g. Monad).
        // Ignored when `sync_send` is enabled (no polling occurs in that path).
        if let Some(ms) = poll_interval_ms {
            client.with_poll_interval(std::time::Duration::from_millis(ms))
        } else {
            client
        }
    }

    /// Round-robin selection of next signer from wallet.
    fn next_signer_address(&self) -> Address {
        debug_assert!(!self.signer_addresses.is_empty());
        if self.signer_addresses.len() == 1 {
            self.signer_addresses[0]
        } else {
            let next =
                self.signer_cursor.fetch_add(1, Ordering::Relaxed) % self.signer_addresses.len();
            self.signer_addresses[next]
        }
    }

    /// Submit `txr` via `eth_sendRawTransactionSync` (EIP-7966): alloy fills and locally
    /// signs the transaction, then sends the raw signed envelope and returns the receipt
    /// in a single RPC round-trip — no separate send + poll.
    ///
    /// Bounded by `receipt_timeout_secs` as a client-side timeout: the HTTP transport has
    /// no request timeout of its own, so without this bound a stalled RPC would hold the
    /// settle handler open indefinitely (whereas the poll path frees it after its timeout).
    /// On any failure the nonce is reset so the next attempt re-queries it — a transaction
    /// that lands after a timeout is still counted by the pending-nonce requery.
    async fn send_sync(
        &self,
        txr: TransactionRequest,
        from_address: Address,
    ) -> Result<TransactionReceipt, MetaTransactionSendError> {
        let timeout = std::time::Duration::from_secs(self.receipt_timeout_secs);
        match tokio::time::timeout(timeout, self.inner.send_transaction_sync(txr)).await {
            Ok(Ok(receipt)) => Ok(receipt),
            Ok(Err(e)) => {
                self.nonce_manager.reset_nonce(from_address).await;
                Err(MetaTransactionSendError::Transport(e))
            }
            Err(_elapsed) => {
                // The node accepted the request but returned no receipt in time. The tx may
                // still land, so this is surfaced distinctly from a submission failure.
                self.nonce_manager.reset_nonce(from_address).await;
                Err(MetaTransactionSendError::Custom(format!(
                    "sync_send receipt not returned within {}s",
                    self.receipt_timeout_secs
                )))
            }
        }
    }

    /// Standard path: submit the transaction, then poll for the receipt up to
    /// `receipt_timeout_secs`, waiting for `confirmations` confirmations. On any failure
    /// the nonce is reset so the next attempt re-queries it.
    async fn send_and_poll(
        &self,
        txr: TransactionRequest,
        confirmations: u64,
        from_address: Address,
    ) -> Result<TransactionReceipt, MetaTransactionSendError> {
        let pending_tx = match self.inner.send_transaction(txr).await {
            Ok(pending) => pending,
            Err(e) => {
                self.nonce_manager.reset_nonce(from_address).await;
                return Err(MetaTransactionSendError::Transport(e));
            }
        };

        let timeout = std::time::Duration::from_secs(self.receipt_timeout_secs);
        let watcher = pending_tx
            .with_required_confirmations(confirmations)
            .with_timeout(Some(timeout));

        match watcher.get_receipt().await {
            Ok(receipt) => Ok(receipt),
            Err(e) => {
                self.nonce_manager.reset_nonce(from_address).await;
                Err(MetaTransactionSendError::PendingTransaction(e))
            }
        }
    }
}

/// Creates a new provider from configuration.
///
/// Initializes signers, RPC transports, and the nonce manager.
///
/// # Errors
///
/// Returns an error if:
/// - No signers are configured
/// - Signer private keys are invalid
/// - RPC transport initialization fails
#[async_trait::async_trait]
impl FromConfig<Eip155ChainConfig> for Eip155ChainProvider {
    async fn from_config(config: &Eip155ChainConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // 1. Signers
        let signers = config
            .signers()
            .iter()
            .map(|s| B256::from_slice(s.inner().as_bytes()))
            .map(|b| {
                PrivateKeySigner::from_bytes(&b)
                    .map(|s| s.with_chain_id(Some(config.chain_reference().inner())))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if signers.is_empty() {
            return Err("at least one signer should be provided".into());
        }
        let wallet = {
            let mut iter = signers.into_iter();
            let first_signer = iter
                .next()
                .expect("iterator contains at least one element by construction");
            let mut wallet = EthereumWallet::from(first_signer);
            for signer in iter {
                wallet.register_signer(signer);
            }
            wallet
        };
        let signer_addresses =
            NetworkWallet::<AlloyEthereum>::signer_addresses(&wallet).collect::<Vec<_>>();
        let signer_addresses = Arc::new(signer_addresses);
        let signer_cursor = Arc::new(AtomicUsize::new(0));

        // 2. Transports
        let client = Self::rpc_client(config.chain_id(), config.rpc(), config.poll_interval_ms());

        // 3. Provider
        // Create nonce manager explicitly so we can store a reference for error handling
        let nonce_manager = PendingNonceManager::default();
        // Build the filler stack: Gas -> BlobGas -> Nonce -> ChainId
        // This mirrors the InnerFiller type but with our custom nonce manager
        let filler = JoinFill::new(
            GasFiller::default(),
            JoinFill::new(
                BlobGasFiller::default(),
                JoinFill::new(
                    NonceFiller::new(nonce_manager.clone()),
                    ChainIdFiller::default(),
                ),
            ),
        );
        let inner: InnerProvider = ProviderBuilder::default()
            .filler(filler)
            .wallet(wallet)
            .connect_client(client);

        assert_contracts_exists(&inner).await?;

        #[cfg(feature = "telemetry")]
        tracing::info!(chain=%config.chain_id(), signers=?signer_addresses, "Using EVM provider");

        #[cfg(feature = "telemetry")]
        if config.sync_send() && config.poll_interval_ms().is_some() {
            tracing::info!(
                chain=%config.chain_id(),
                "sync_send is enabled; poll_interval_ms has no effect on transaction settlement"
            );
        }

        Ok(Self {
            chain: config.chain_reference(),
            eip1559: config.eip1559(),
            flashblocks: config.flashblocks(),
            sync_send: config.sync_send(),
            receipt_timeout_secs: config.receipt_timeout_secs(),
            inner,
            signer_addresses,
            signer_cursor,
            nonce_manager,
        })
    }
}

impl Eip155MetaTransactionProvider for Eip155ChainProvider {
    type Error = MetaTransactionSendError;
    type Inner = InnerProvider;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }

    fn chain(&self) -> &Eip155ChainReference {
        &self.chain
    }

    /// Send a meta-transaction with provided `to`, `calldata`, and automatically selected signer.
    ///
    /// This method constructs a transaction from the provided [`MetaTransaction`], automatically
    /// selects the next available signer using round-robin selection, and handles gas pricing
    /// based on whether the network supports EIP-1559.
    ///
    /// If the transaction fails at any point (during submission or receipt fetching), the nonce
    /// for the sending address is reset to force a fresh query on the next transaction. This
    /// ensures correctness even when transactions partially succeed (e.g., submitted but receipt
    /// fetch times out).
    ///
    /// # Gas Pricing Strategy
    ///
    /// - **EIP-1559 networks**: Uses automatic gas pricing via the provider's fillers.
    /// - **Legacy networks**: Fetches the current gas price using `get_gas_price()` and sets it explicitly.
    ///
    /// # Timeout Configuration
    ///
    /// Receipt fetching is subject to a configurable timeout:
    /// - Default: 30 seconds
    /// - Override via `TX_RECEIPT_TIMEOUT_SECS` environment variable
    /// - If the timeout expires, the nonce is reset and an error is returned
    ///
    /// # Parameters
    ///
    /// - `tx`: A [`MetaTransaction`] containing the target address and calldata.
    ///
    /// # Returns
    ///
    /// A [`TransactionReceipt`] once the transaction has been mined and confirmed.
    ///
    /// # Errors
    ///
    /// Returns [`FacilitatorLocalError::ContractCall`] if:
    /// - Gas price fetching fails (on legacy networks)
    /// - Transaction sending fails
    /// - Receipt retrieval fails or times out
    async fn send_transaction(
        &self,
        tx: MetaTransaction,
    ) -> Result<TransactionReceipt, Self::Error> {
        let from_address = tx.from.unwrap_or_else(|| self.next_signer_address());
        let mut txr = TransactionRequest::default()
            .with_to(tx.to)
            .with_from(from_address)
            .with_input(tx.calldata);

        if !self.eip1559 {
            let provider = &self.inner;
            let gas_fut = provider.get_gas_price();
            #[cfg(feature = "telemetry")]
            let gas: u128 = gas_fut
                .instrument(tracing::info_span!("get_gas_price"))
                .await?;
            #[cfg(not(feature = "telemetry"))]
            let gas: u128 = gas_fut.await?;
            txr.set_gas_price(gas);
        }

        // Estimate gas if not provided
        if txr.gas.is_none() {
            let block_id = if self.flashblocks {
                BlockId::latest()
            } else {
                BlockId::pending()
            };
            let gas_limit = self.inner.estimate_gas(txr.clone()).block(block_id).await?;
            txr.set_gas_limit(gas_limit)
        }

        if self.sync_send {
            self.send_sync(txr, from_address).await
        } else {
            self.send_and_poll(txr, tx.confirmations, from_address)
                .await
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MetaTransactionSendError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    PendingTransaction(#[from] PendingTransactionError),
    #[allow(dead_code)] // Public for consumption by downstream crates.
    #[error("{0}")]
    Custom(String),
}

impl ChainProviderOps for Eip155ChainProvider {
    fn signer_addresses(&self) -> Vec<String> {
        self.inner
            .signer_addresses()
            .map(|a| a.to_string())
            .collect()
    }

    fn chain_id(&self) -> ChainId {
        self.chain.into()
    }
}

/// Provides access to the EIP-155 signer addresses held by a facilitator provider.
///
/// Implementations return the set of addresses whose private keys the provider
/// controls and can use to submit on-chain transactions. The facilitator exposes
/// one of these addresses to clients via the `supported()` endpoint so they can
/// embed it in the Permit2 witness, ensuring only this facilitator can settle the
/// authorized payment.
pub trait Eip155SignerAddresses {
    /// Returns an iterator over the signer addresses available on this provider.
    fn signer_addresses(&self) -> Vec<Address>;
}

impl<T> Eip155SignerAddresses for Arc<T>
where
    T: Eip155SignerAddresses,
{
    fn signer_addresses(&self) -> Vec<Address> {
        (**self).signer_addresses()
    }
}

impl Eip155SignerAddresses for Eip155ChainProvider {
    fn signer_addresses(&self) -> Vec<Address> {
        (*self.signer_addresses).clone()
    }
}

/// Meta-transaction parameters: target address, calldata, and required confirmations.
pub struct MetaTransaction {
    /// Target contract address.
    pub to: Address,
    /// Transaction calldata (encoded function call).
    pub calldata: Bytes,
    /// Number of block confirmations to wait for.
    pub confirmations: u64,
    /// Optional sender address.
    pub from: Option<Address>,
}

impl MetaTransaction {
    pub fn new(to: Address, calldata: Bytes) -> Self {
        Self {
            to,
            calldata,
            confirmations: 1,
            from: None,
        }
    }

    pub fn with_from(mut self, from: Address) -> Self {
        self.from = Some(from);
        self
    }
}

/// Trait for sending meta-transactions with custom target and calldata.
pub trait Eip155MetaTransactionProvider {
    /// Error type for operations.
    type Error;
    /// Underlying provider type.
    type Inner: Provider;

    /// Returns reference to underlying provider.
    fn inner(&self) -> &Self::Inner;
    /// Returns reference to chain descriptor.
    fn chain(&self) -> &Eip155ChainReference;

    /// Sends a meta-transaction to the network.
    fn send_transaction(
        &self,
        tx: MetaTransaction,
    ) -> impl Future<Output = Result<TransactionReceipt, Self::Error>> + Send;
}

impl<T: Eip155MetaTransactionProvider> Eip155MetaTransactionProvider for Arc<T> {
    type Error = T::Error;
    type Inner = T::Inner;

    fn inner(&self) -> &Self::Inner {
        (**self).inner()
    }

    fn chain(&self) -> &Eip155ChainReference {
        (**self).chain()
    }

    fn send_transaction(
        &self,
        tx: MetaTransaction,
    ) -> impl Future<Output = Result<TransactionReceipt, Self::Error>> + Send {
        (**self).send_transaction(tx)
    }
}

pub async fn assert_contracts_exists<P: Provider>(
    provider: &P,
) -> Result<(), Box<dyn std::error::Error>> {
    for address in REQUIRED_CONTRACT_ADDRESSES.deref() {
        let code = provider.get_code_at(*address).await?;
        if code.is_empty() {
            return Err(
                format!("Contract at address {address} does not exist (empty code)").into(),
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod sync_send_tests {
    //! Mock-`Asserter` coverage for the `sync_send` (EIP-7966) submission path.
    //!
    //! No live node. The request is fully pre-filled so the fillers issue no RPCs, and
    //! the heartbeat block-poller stays paused (it only unpauses once a pending-tx
    //! watcher is registered, which `send_transaction_sync` never does). So the only
    //! outbound call is `eth_sendRawTransactionSync`, which consumes the single queued
    //! receipt. The wallet filler signs locally — converting the request into an
    //! envelope, which is what routes alloy to `send_raw_transaction_sync` (raw) rather
    //! than node-side `eth_sendTransactionSync`.

    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use alloy_network::{EthereumWallet, TransactionBuilder};
    use alloy_primitives::{Address, Bytes, U256, address};
    use alloy_provider::ProviderBuilder;
    use alloy_provider::fillers::{BlobGasFiller, ChainIdFiller, GasFiller, JoinFill, NonceFiller};
    use alloy_rpc_types_eth::{TransactionReceipt, TransactionRequest};
    use alloy_signer::Signer;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_transport::mock::Asserter;

    use super::{Eip155ChainProvider, InnerProvider, MetaTransactionSendError};
    use crate::chain::pending_nonce_manager::PendingNonceManager;
    use crate::chain::types::Eip155ChainReference;

    const CHAIN_ID: u64 = 10143; // Monad testnet
    // Deterministic throwaway key (never used on-chain).
    const TEST_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

    // A known-good, deserializable successful receipt.
    fn canned_receipt() -> TransactionReceipt {
        serde_json::from_str(
            r#"{
                "transactionHash": "0xea1093d492a1dcb1bef708f771a99a96ff05dcab81ca76c31940300177fcf49f",
                "blockHash": "0x8e38b4dbf6b11fcc3b9dee84fb7986e29ca0a02cecd8977c161ff7333329681e",
                "blockNumber": "0xf4240",
                "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "gasUsed": "0x723c",
                "status": "0x1",
                "contractAddress": null,
                "cumulativeGasUsed": "0x723c",
                "transactionIndex": "0x0",
                "from": "0x39fa8c5f2793459d6622857e7d9fbb4bd91766d3",
                "to": "0xc083e9947cf02b8ffc7d3090ae9aea72df98fd47",
                "type": "0x0",
                "effectiveGasPrice": "0x12bfb19e60",
                "logs": []
            }"#,
        )
        .expect("canned receipt should deserialize")
    }

    fn mocked_provider(
        asserter: Asserter,
        nonce_manager: PendingNonceManager,
    ) -> Eip155ChainProvider {
        let signer = TEST_KEY
            .parse::<PrivateKeySigner>()
            .expect("valid test key")
            .with_chain_id(Some(CHAIN_ID));
        let signer_addr = signer.address();
        let wallet = EthereumWallet::from(signer);

        // Mirror `from_config`'s filler stack (Gas -> BlobGas -> Nonce -> ChainId),
        // but connect a mocked client instead of live transports.
        let filler = JoinFill::new(
            GasFiller::default(),
            JoinFill::new(
                BlobGasFiller::default(),
                JoinFill::new(
                    NonceFiller::new(nonce_manager.clone()),
                    ChainIdFiller::default(),
                ),
            ),
        );
        let inner: InnerProvider = ProviderBuilder::default()
            .filler(filler)
            .wallet(wallet)
            .connect_mocked_client(asserter);

        Eip155ChainProvider {
            chain: Eip155ChainReference::new(CHAIN_ID),
            eip1559: false,
            flashblocks: false,
            sync_send: true,
            receipt_timeout_secs: 30,
            inner,
            signer_addresses: Arc::new(vec![signer_addr]),
            signer_cursor: Arc::new(AtomicUsize::new(0)),
            nonce_manager,
        }
    }

    // Fully specified so no filler needs an RPC. Legacy (gas_price) keeps signing simple.
    fn prefilled_tx(from: Address) -> TransactionRequest {
        TransactionRequest::default()
            .with_from(from)
            .with_to(address!("00000000000000000000000000000000000000aa"))
            .with_input(Bytes::from_static(&[0x00]))
            .with_value(U256::ZERO)
            .with_nonce(0)
            .with_gas_limit(21_000)
            .with_gas_price(20_000_000_000u128)
            .with_chain_id(CHAIN_ID)
    }

    #[test]
    fn sync_send_submits_raw_and_returns_receipt() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let asserter = Asserter::new();
            let receipt = canned_receipt();
            asserter.push_success(&receipt);

            let provider = mocked_provider(asserter, PendingNonceManager::default());
            let from = provider.signer_addresses[0];

            let got = provider
                .send_sync(prefilled_tx(from), from)
                .await
                .expect("sync_send should return the mocked receipt");
            assert_eq!(got.transaction_hash, receipt.transaction_hash);
        });
    }

    #[test]
    fn sync_send_error_maps_to_transport() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let asserter = Asserter::new();
            asserter.push_failure_msg("node rejected submission");

            let provider = mocked_provider(asserter, PendingNonceManager::default());
            let from = provider.signer_addresses[0];

            let err = provider
                .send_sync(prefilled_tx(from), from)
                .await
                .unwrap_err();
            assert!(matches!(err, MetaTransactionSendError::Transport(_)));
        });
    }
}
