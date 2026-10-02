//! Polling-independent direct Bitcoin observation worker boundary.

use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bdk_electrum::{
    BdkElectrumClient,
    bdk_core::{BlockId, CheckPoint, spk_client::SyncRequest},
    electrum_client::{Client, ConfigBuilder, Error as ElectrumError},
};
use bitcoin::{Address, Network, constants::genesis_block};

use crate::{
    bitcoin::{ObservationTarget, ObservedOutput},
    config::{BitcoinNetwork, validate_electrum_endpoint},
    domain::payment::BitcoinOutpoint,
    persistence::{BitcoinObservationInput, InvoiceStore, PersistenceError},
};

/// Production Electrum adapters are injected here. This boundary deliberately
/// does not prescribe an Electrum wire protocol or invent payer messages.
#[async_trait]
pub trait ElectrumPort: Send + Sync {
    async fn observations(
        &self,
        targets: &[ObservationTarget],
    ) -> Result<Vec<ObservedOutput>, ObserverError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverError {
    Unavailable,
    WrongNetwork,
    InvalidObservation,
    Persistence,
}

/// Concrete synchronous Electrum client isolated behind the async observation port.
pub struct ElectrumAdapter {
    endpoint: Arc<str>,
    network: BitcoinNetwork,
    timeout: Duration,
    retries: u8,
}

impl ElectrumAdapter {
    /// Constructs a production adapter without requiring the remote endpoint to be online.
    pub fn configured(
        endpoint: impl Into<String>,
        network: BitcoinNetwork,
        timeout: Duration,
        retries: u8,
    ) -> Result<Self, ObserverError> {
        let endpoint = endpoint.into();
        validate_electrum_endpoint(&endpoint).map_err(|_| ObserverError::Unavailable)?;
        Ok(Self {
            endpoint: endpoint.into(),
            network,
            timeout,
            retries,
        })
    }

    pub async fn connect(
        endpoint: impl Into<String>,
        network: BitcoinNetwork,
        timeout: Duration,
        retries: u8,
    ) -> Result<Self, ObserverError> {
        let adapter = Self::configured(endpoint, network, timeout, retries)?;
        adapter.client().await?;
        Ok(adapter)
    }

    async fn client(&self) -> Result<Arc<BdkElectrumClient<Client>>, ObserverError> {
        let config = ConfigBuilder::new()
            .timeout(Some(self.timeout))
            .retry(self.retries)
            .build();
        let endpoint = self.endpoint.clone();
        let client = tokio::task::spawn_blocking(move || Client::from_config(&endpoint, config))
            .await
            .map_err(|_| ObserverError::Unavailable)?
            .map_err(|_| ObserverError::Unavailable)?;
        Ok(Arc::new(BdkElectrumClient::new(client)))
    }
}

#[async_trait]
impl ElectrumPort for ElectrumAdapter {
    async fn observations(
        &self,
        targets: &[ObservationTarget],
    ) -> Result<Vec<ObservedOutput>, ObserverError> {
        let client = self.client().await?;
        let network = self.network.clone();
        let targets = targets.to_vec();
        tokio::task::spawn_blocking(move || observe_blocking(&client, &network, &targets))
            .await
            .map_err(|_| ObserverError::Unavailable)?
    }
}

fn observe_blocking(
    client: &BdkElectrumClient<Client>,
    network: &BitcoinNetwork,
    targets: &[ObservationTarget],
) -> Result<Vec<ObservedOutput>, ObserverError> {
    let expected_network = network.as_bitcoin_network();
    let mut parsed_targets = Vec::with_capacity(targets.len());
    for target in targets {
        let address = parse_address(target.address(), expected_network)?;
        parsed_targets.push((
            address.to_string(),
            address.script_pubkey(),
            target.current(),
        ));
    }

    let genesis = CheckPoint::new(BlockId {
        height: 0,
        hash: genesis_block(expected_network).block_hash(),
    });
    let scripts = parsed_targets
        .iter()
        .map(|(_, script, _)| script.clone())
        .collect::<Vec<_>>();
    let expected_txids = parsed_targets
        .iter()
        .filter_map(|(_, script, current)| {
            current.map(|current| (script.clone(), current.outpoint().txid))
        })
        .collect::<Vec<_>>();
    let request = SyncRequest::builder()
        .chain_tip(genesis)
        .spks(scripts)
        .expected_spk_txids(expected_txids)
        .build();
    let response = client.sync(request, 100, false).map_err(map_electrum)?;
    let tip_height = response
        .chain_update
        .as_ref()
        .ok_or(ObserverError::Unavailable)?
        .height();
    let mut confirmations_by_txid = response
        .tx_update
        .seen_ats
        .iter()
        .map(|(txid, _)| (*txid, 0))
        .collect::<HashMap<_, _>>();
    for (anchor, txid) in &response.tx_update.anchors {
        let confirmations = tip_height
            .checked_sub(anchor.block_id.height)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(ObserverError::Unavailable)?;
        confirmations_by_txid.insert(*txid, confirmations);
    }
    let targets_by_script = parsed_targets
        .iter()
        .map(|(address, script, _)| (script.clone(), address.as_str()))
        .collect::<HashMap<_, _>>();
    let mut seen_outpoints = HashSet::new();
    let mut processed_txids = HashSet::new();
    let mut observations = Vec::new();
    for transaction in response.tx_update.txs {
        let txid = transaction.compute_txid();
        if !processed_txids.insert(txid) {
            continue;
        }
        let confirmations = confirmations_by_txid
            .get(&txid)
            .copied()
            .ok_or(ObserverError::InvalidObservation)?;
        for (vout, output) in transaction.output.iter().enumerate() {
            if let Some(address) = targets_by_script.get(&output.script_pubkey) {
                let outpoint = bitcoin::OutPoint::new(
                    txid,
                    u32::try_from(vout).map_err(|_| ObserverError::InvalidObservation)?,
                );
                seen_outpoints.insert(outpoint);
                observations.push(ObservedOutput {
                    network: network.clone(),
                    address: (*address).to_owned(),
                    outpoint,
                    sats: output.value.to_sat(),
                    confirmations,
                    present: true,
                });
            }
        }
    }
    for (address, _, current) in parsed_targets {
        if let Some(current) = current
            && !seen_outpoints.contains(&current.outpoint())
        {
            observations.push(ObservedOutput {
                network: network.clone(),
                address,
                outpoint: current.outpoint(),
                sats: current.sats(),
                confirmations: 0,
                present: false,
            });
        }
    }
    Ok(observations)
}

fn map_electrum(error: ElectrumError) -> ObserverError {
    match error {
        ElectrumError::Message(message)
            if message.contains("cannot find agreement block with server") =>
        {
            ObserverError::WrongNetwork
        }
        _ => ObserverError::Unavailable,
    }
}

fn parse_address(address: &str, network: Network) -> Result<Address, ObserverError> {
    Address::from_str(address)
        .map_err(|_| ObserverError::InvalidObservation)?
        .require_network(network)
        .map_err(|_| ObserverError::WrongNetwork)
}

/// Applies one fetched batch. Invalid networks or unrequested addresses fail
/// before any database write.
pub async fn observe_once(
    port: &dyn ElectrumPort,
    invoices: &InvoiceStore,
    network: &BitcoinNetwork,
    targets: &[ObservationTarget],
) -> Result<usize, ObserverError> {
    let observations = port.observations(targets).await?;
    let observations = validate_batch(observations, network, targets)?;
    invoices
        .apply_bitcoin_observation_batch(&observations)
        .await
        .map_err(map_persistence)
}

fn validate_batch(
    observations: Vec<ObservedOutput>,
    network: &BitcoinNetwork,
    targets: &[ObservationTarget],
) -> Result<Vec<BitcoinObservationInput>, ObserverError> {
    let expected_network = network.as_bitcoin_network();
    let mut targets_by_address = HashMap::with_capacity(targets.len());
    for target in targets {
        let address = parse_address(target.address(), expected_network)?;
        if address.to_string() != target.address()
            || targets_by_address
                .insert(target.address(), target)
                .is_some()
        {
            return Err(ObserverError::InvalidObservation);
        }
    }
    let mut outpoints = HashSet::with_capacity(observations.len());
    let mut validated = observations
        .into_iter()
        .map(|output| {
            if &output.network != network {
                return Err(ObserverError::WrongNetwork);
            }
            if i32::try_from(output.confirmations).is_err()
                || (!output.present && output.confirmations != 0)
            {
                return Err(ObserverError::InvalidObservation);
            }
            let address = parse_address(&output.address, expected_network)?;
            if address.to_string() != output.address {
                return Err(ObserverError::InvalidObservation);
            }
            let target = targets_by_address
                .get(output.address.as_str())
                .ok_or(ObserverError::InvalidObservation)?;
            if !output.present
                && !target.current().is_some_and(|current| {
                    current.outpoint() == output.outpoint && current.sats() == output.sats
                })
            {
                return Err(ObserverError::InvalidObservation);
            }
            if !outpoints.insert(output.outpoint) {
                return Err(ObserverError::InvalidObservation);
            }
            let outpoint = BitcoinOutpoint::from_bitcoin(output.outpoint);
            Ok(BitcoinObservationInput {
                address: output.address,
                outpoint,
                observed_sats: output.sats,
                confirmations: output.confirmations,
                present: output.present,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    validated.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then_with(|| left.outpoint.txid().cmp(right.outpoint.txid()))
            .then_with(|| left.outpoint.vout().cmp(&right.outpoint.vout()))
    });
    Ok(validated)
}

fn map_persistence(_: PersistenceError) -> ObserverError {
    ObserverError::Persistence
}
