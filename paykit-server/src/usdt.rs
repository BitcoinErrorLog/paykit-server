//! Direct Arbitrum USDT0 receipts and Paykit ERC-20 account attestations.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{SolStruct, eip712_domain, sol};
use paykit_sdk::PaymentProofRecord;
use secp256k1::{
    Message, Secp256k1,
    ecdsa::{RecoverableSignature, RecoveryId},
};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::domain::receiving::{USDT_CHAIN_ID, USDT_ENDPOINT, USDT_TOKEN, UsdtAddress};

sol! {
    struct RequestBinding {
        string payer;
        string payee;
        string paymentAppId;
        string paymentRequestId;
        string paymentReference;
        string paymentEndpointIdentifier;
        string periodStartsAt;
        string periodEndsAt;
        string conversionQuoteId;
    }
    struct Erc20Payment {
        bytes32 transactionHash;
        uint256 receiptLogIndex;
        RequestBinding request;
    }
}

/// Context resolved from the authenticated request and persisted invoice.
pub struct PaymentContext<'a> {
    pub payer: &'a str,
    pub payee: &'a str,
    pub request_id: &'a str,
    pub reference: &'a str,
    pub recipient: &'a UsdtAddress,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    #[serde(rename = "type")]
    kind: String,
    chain_id: String,
    transaction_hash: String,
    receipt_log_index: String,
    signature: String,
}

/// Only this module can construct verified receipt facts.
pub struct VerifiedTransfer {
    pub(crate) identity: String,
    pub(crate) amount: u64,
    pub(crate) timestamp: OffsetDateTime,
    pub(crate) confirmations: u32,
    pub(crate) finalized: bool,
    pub(crate) sender: [u8; 20],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationError {
    InvalidProof,
    Unavailable,
}

#[derive(Clone)]
pub struct ArbitrumVerifier {
    client: reqwest::Client,
    url: url::Url,
    chain_tip: Arc<Mutex<Option<(Instant, ChainTip)>>>,
    scans: Arc<Mutex<ScanCache>>,
}

const CHAIN_TIP_TTL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
struct ChainTip {
    head: u64,
    finalized: Option<u64>,
}

const MAX_REQUEST_PROOFS: usize = 128;
pub(crate) const MAX_SCAN_CANDIDATES: usize = 8;
const MAX_SCAN_REQUESTS: usize = 1024;
const UNMATCHED_RETRY_DELAY: Duration = Duration::from_secs(15);
const SCAN_IDLE_TTL: Duration = Duration::from_secs(5 * 60);

struct ScanState {
    fingerprint: blake3::Hash,
    // None reserves a slot whose first scan has not run.
    cursor: Option<usize>,
    sweep_complete: bool,
    retry_at: Instant,
    last_used: Instant,
}

#[derive(Default)]
struct ScanCache {
    requests: HashMap<blake3::Hash, ScanState>,
    waiting: Option<(blake3::Hash, blake3::Hash)>,
    last_admitted: Option<blake3::Hash>,
}

impl ScanCache {
    fn oldest_ready(&self, now: Instant, current: blake3::Hash) -> Option<blake3::Hash> {
        self.requests
            .iter()
            .filter(|(key, state)| {
                **key != current
                    && state.retry_at <= now
                    && (state.cursor.is_none()
                        || state.sweep_complete
                        || now.duration_since(state.last_used) >= SCAN_IDLE_TTL)
            })
            .min_by_key(|(_, state)| state.last_used)
            .map(|(key, _)| *key)
    }

    fn defer(&mut self, key: blake3::Hash, fingerprint: blake3::Hash) {
        // Circular key order prevents a stable reconciliation order from starving later requests.
        let rank = |key: blake3::Hash| {
            (
                self.last_admitted
                    .is_some_and(|last| key.as_bytes() <= last.as_bytes()),
                *key.as_bytes(),
            )
        };
        if self
            .waiting
            .is_none_or(|(waiting, _)| rank(key) <= rank(waiting))
        {
            self.waiting = Some((key, fingerprint));
        }
    }
}

#[derive(Clone)]
pub(crate) struct PaymentCandidate {
    pub(crate) identity: String,
    hash: B256,
    index: usize,
    senders: BTreeSet<Address>,
}

impl PaymentCandidate {
    pub(crate) fn from_proofs(
        context: &PaymentContext<'_>,
        proofs: &[PaymentProofRecord],
    ) -> Option<BTreeMap<String, Self>> {
        if proofs.len() > MAX_REQUEST_PROOFS {
            return None;
        }
        let mut candidates = BTreeMap::<String, PaymentCandidate>::new();
        for record in proofs {
            if let Ok((_, hash, index, sender)) = parse_proof(context, record) {
                let identity = format!("{USDT_CHAIN_ID}:{hash:#x}:{index}");
                candidates
                    .entry(identity.clone())
                    .or_insert_with(|| PaymentCandidate {
                        identity,
                        hash,
                        index,
                        senders: BTreeSet::new(),
                    })
                    .senders
                    .insert(sender);
            }
        }
        Some(candidates)
    }

    /// Uses the sender authenticated when the owned observation was recorded.
    pub(crate) fn from_observation(
        identity: &str,
        sender: [u8; 20],
    ) -> Result<Self, VerificationError> {
        let mut parts = identity.split(':');
        let (Some(chain), Some(hash), Some(index), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(VerificationError::InvalidProof);
        };
        if chain != USDT_CHAIN_ID {
            return Err(VerificationError::InvalidProof);
        }
        let hash = B256::from_str(canonical_hex(hash, 32)?)
            .map_err(|_| VerificationError::InvalidProof)?;
        let index = index
            .parse::<usize>()
            .map_err(|_| VerificationError::InvalidProof)?;
        if identity != format!("{USDT_CHAIN_ID}:{hash:#x}:{index}") {
            return Err(VerificationError::InvalidProof);
        }
        Ok(Self {
            identity: identity.to_owned(),
            hash,
            index,
            senders: BTreeSet::from([Address::from(sender)]),
        })
    }
}

pub(crate) struct PaymentScan {
    key: blake3::Hash,
    fingerprint: blake3::Hash,
    pub(crate) candidates: Vec<PaymentCandidate>,
}

impl ArbitrumVerifier {
    pub fn new(url: url::Url) -> Result<Self, VerificationError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| VerificationError::Unavailable)?;
        Ok(Self {
            client,
            url,
            chain_tip: Arc::new(Mutex::new(None)),
            scans: Arc::new(Mutex::new(ScanCache::default())),
        })
    }

    pub(crate) async fn payment_scan(
        &self,
        context: &PaymentContext<'_>,
        proofs: &[PaymentProofRecord],
    ) -> Option<PaymentScan> {
        self.payment_scan_at(context, proofs, Instant::now()).await
    }

    async fn payment_scan_at(
        &self,
        context: &PaymentContext<'_>,
        proofs: &[PaymentProofRecord],
        now: Instant,
    ) -> Option<PaymentScan> {
        // Keep all attestations for an event together; partial sets can hide its valid signer.
        if proofs.len() > MAX_REQUEST_PROOFS {
            return None;
        }
        let key = blake3::hash(
            &serde_json::to_vec(&(
                context.payer,
                context.payee,
                context.request_id,
                context.reference,
                context.recipient,
            ))
            .expect("payment context is serializable"),
        );
        let fingerprint = proof_fingerprint(proofs);
        let mut scan = PaymentScan {
            key,
            fingerprint,
            candidates: Vec::new(),
        };
        if proofs.is_empty() {
            return Some(scan);
        }
        let mut cache = self.scans.lock().await;
        if cache
            .requests
            .get(&key)
            .is_none_or(|state| state.cursor.is_some())
            && let Some((waiting, fingerprint)) = cache.waiting
            && let Some(oldest) = cache.oldest_ready(now, key)
        {
            cache.requests.remove(&oldest);
            cache.requests.insert(
                waiting,
                ScanState {
                    fingerprint,
                    cursor: None,
                    sweep_complete: false,
                    retry_at: now + UNMATCHED_RETRY_DELAY,
                    last_used: now,
                },
            );
            cache.waiting = None;
            cache.last_admitted = Some(waiting);
        }
        if !cache.requests.contains_key(&key) && cache.requests.len() >= MAX_SCAN_REQUESTS {
            let Some(oldest) = cache.oldest_ready(now, key) else {
                cache.defer(key, fingerprint);
                return Some(scan);
            };
            cache.requests.remove(&oldest);
        }
        let state = cache.requests.entry(key).or_insert(ScanState {
            fingerprint,
            cursor: None,
            sweep_complete: false,
            retry_at: now,
            last_used: now,
        });
        if state.fingerprint != fingerprint {
            state.fingerprint = fingerprint;
            state.retry_at = now;
            state.cursor = None;
            state.sweep_complete = false;
        }
        state.last_used = now;
        if state.retry_at > now && state.cursor.is_some() {
            return Some(scan);
        }
        let cursor = state.cursor.unwrap_or(0);
        // Proof count bounds a full sweep even when several proofs share one event.
        state.sweep_complete |= cursor.saturating_add(MAX_SCAN_CANDIDATES) >= proofs.len();
        state.cursor = Some(cursor.wrapping_add(MAX_SCAN_CANDIDATES));
        state.retry_at = now + UNMATCHED_RETRY_DELAY;
        drop(cache);

        let candidates = PaymentCandidate::from_proofs(context, proofs)?;
        let candidates: Vec<_> = candidates.into_values().collect();
        if !candidates.is_empty() {
            let cursor = cursor % candidates.len();
            scan.candidates = (0..candidates.len().min(MAX_SCAN_CANDIDATES))
                .map(|offset| candidates[(cursor + offset) % candidates.len()].clone())
                .collect();
        }
        Some(scan)
    }

    pub(crate) async fn finish_payment_scan(&self, scan: &PaymentScan, all_observed: bool) {
        if all_observed
            && !scan.candidates.is_empty()
            && let Some(state) = self.scans.lock().await.requests.get_mut(&scan.key)
            && state.fingerprint == scan.fingerprint
        {
            state.retry_at = Instant::now();
        }
    }

    async fn chain_tip(&self, minimum_block: u64) -> Result<ChainTip, VerificationError> {
        // Share one bounded snapshot across creators and coalesce concurrent refreshes.
        let mut cached = self.chain_tip.lock().await;
        if let Some((read_at, tip)) = *cached
            && read_at.elapsed() < CHAIN_TIP_TTL
            && tip.head >= minimum_block
        {
            return Ok(tip);
        }
        *cached = None;
        let read_at = Instant::now();
        if quantity(&self.call("eth_chainId", json!([])).await?)? != 42161 {
            return Err(VerificationError::Unavailable);
        }
        let finalized = self
            .call("eth_getBlockByNumber", json!(["finalized", false]))
            .await?;
        let finalized = if finalized.is_null() {
            None
        } else {
            Some(quantity(&finalized["number"])?)
        };
        let head = quantity(&self.call("eth_blockNumber", json!([])).await?)?;
        if head < minimum_block || finalized.is_some_and(|block| block > head) {
            return Err(VerificationError::Unavailable);
        }
        let tip = ChainTip { head, finalized };
        *cached = Some((read_at, tip));
        Ok(tip)
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, VerificationError> {
        let mut response = self
            .client
            .post(self.url.clone())
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .map_err(|_| VerificationError::Unavailable)?
            .error_for_status()
            .map_err(|_| VerificationError::Unavailable)?;
        let mut bytes = Vec::new();
        // Oversized receipts remain retryable; no truncated evidence is accepted.
        const RESPONSE_LIMIT: usize = 8 * 1024 * 1024;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| VerificationError::Unavailable)?
        {
            if bytes.len().saturating_add(chunk.len()) > RESPONSE_LIMIT {
                return Err(VerificationError::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| VerificationError::Unavailable)?;
        if value["id"] != 1 || value["jsonrpc"] != "2.0" || value.get("error").is_some() {
            return Err(VerificationError::Unavailable);
        }
        value
            .get("result")
            .cloned()
            .ok_or(VerificationError::Unavailable)
    }

    /// Missing receipts and reorgs are pending observations, never payment failures.
    pub async fn verify(
        &self,
        context: &PaymentContext<'_>,
        record: &PaymentProofRecord,
    ) -> Result<Option<VerifiedTransfer>, VerificationError> {
        let (_, hash, index, sender) = parse_proof(context, record)?;
        self.verify_candidate(
            context,
            &PaymentCandidate {
                identity: format!("{USDT_CHAIN_ID}:{hash:#x}:{index}"),
                hash,
                index,
                senders: BTreeSet::from([sender]),
            },
        )
        .await
    }

    pub(crate) async fn verify_candidate(
        &self,
        context: &PaymentContext<'_>,
        candidate: &PaymentCandidate,
    ) -> Result<Option<VerifiedTransfer>, VerificationError> {
        let hash = candidate.hash;
        let index = candidate.index;
        let mut tip = self.chain_tip(0).await?;
        let receipt = self
            .call("eth_getTransactionReceipt", json!([hash]))
            .await?;
        if receipt.is_null() {
            return Ok(None);
        }
        if parse_hash(&receipt["transactionHash"])? != hash {
            return Err(VerificationError::Unavailable);
        }
        if quantity(&receipt["status"])? != 1 {
            return Err(VerificationError::InvalidProof);
        }
        let number = quantity(&receipt["blockNumber"])?;
        if tip.head < number {
            tip = self.chain_tip(number).await?;
        }
        let block = self
            .call(
                "eth_getBlockByNumber",
                json!([format!("0x{number:x}"), false]),
            )
            .await?;
        if block.is_null() || parse_hash(&receipt["blockHash"])? != parse_hash(&block["hash"])? {
            return Ok(None);
        }
        if quantity(&block["number"])? != number {
            return Err(VerificationError::Unavailable);
        }
        let timestamp = i64::try_from(quantity(&block["timestamp"])?)
            .ok()
            .and_then(|value| OffsetDateTime::from_unix_timestamp(value).ok())
            .ok_or(VerificationError::Unavailable)?;
        let logs = receipt["logs"]
            .as_array()
            .ok_or(VerificationError::Unavailable)?;
        let log = logs.get(index).ok_or(VerificationError::InvalidProof)?;
        let sender = parse_hash(&log["topics"][1]).map_err(|_| VerificationError::InvalidProof)?;
        let sender = candidate
            .senders
            .iter()
            .find(|address| address.into_word() == sender)
            .ok_or(VerificationError::InvalidProof)?;
        let amount = transfer_amount(log, *sender, context.recipient, hash, &receipt["blockHash"])?;
        let confirmations = tip
            .head
            .checked_sub(number)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(VerificationError::Unavailable)?;
        let finalized = tip.finalized.is_some_and(|block| block >= number);
        Ok(Some(VerifiedTransfer {
            identity: format!("{USDT_CHAIN_ID}:{hash:#x}:{index}"),
            amount,
            timestamp,
            confirmations,
            finalized,
            sender: sender.into_array(),
        }))
    }
}

fn proof_fingerprint(proofs: &[PaymentProofRecord]) -> blake3::Hash {
    let bindings: Vec<_> = proofs
        .iter()
        .map(|proof| {
            (
                &proof.payment_app_id,
                &proof.payment_endpoint_identifier,
                &proof.payment_reference,
                &proof.billing_period,
                &proof.conversion_quote_id,
                &proof.proof,
            )
        })
        .collect();
    blake3::hash(&serde_json::to_vec(&bindings).expect("payment proofs are serializable"))
}

/// Validates account attestation before looking up a durable observation.
pub fn payment_identity(
    context: &PaymentContext<'_>,
    record: &PaymentProofRecord,
) -> Result<String, VerificationError> {
    let (_, hash, index, _) = parse_proof(context, record)?;
    Ok(format!("{USDT_CHAIN_ID}:{hash:#x}:{index}"))
}

fn parse_proof(
    context: &PaymentContext<'_>,
    record: &PaymentProofRecord,
) -> Result<(Proof, B256, usize, Address), VerificationError> {
    let invalid = VerificationError::InvalidProof;
    if record.payment_app_id.as_str() != crate::config::PAYKIT_APP_ID
        || record.payment_endpoint_identifier != USDT_ENDPOINT
        || record.payment_reference != context.reference
        || record.billing_period.is_some()
        || record.conversion_quote_id.is_some()
    {
        return Err(invalid);
    }
    let proof: Proof =
        serde_json::from_value(Value::Object(record.proof.clone())).map_err(|_| invalid)?;
    if proof.kind != "erc20-transfer-eip712" || proof.chain_id != USDT_CHAIN_ID {
        return Err(invalid);
    }
    let hash: B256 = canonical_hex(&proof.transaction_hash, 32)?
        .parse()
        .map_err(|_| invalid)?;
    let index_text = &proof.receipt_log_index;
    if index_text.is_empty()
        || (index_text.len() > 1 && index_text.starts_with('0'))
        || !index_text.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(invalid);
    }
    let index = U256::from_str_radix(index_text, 10).map_err(|_| invalid)?;
    let index_usize = usize::try_from(index).map_err(|_| invalid)?;
    let digest = Erc20Payment {
        transactionHash: hash,
        receiptLogIndex: index,
        request: RequestBinding {
            payer: context.payer.into(),
            payee: context.payee.into(),
            paymentAppId: crate::config::PAYKIT_APP_ID.into(),
            paymentRequestId: context.request_id.into(),
            paymentReference: context.reference.into(),
            paymentEndpointIdentifier: USDT_ENDPOINT.into(),
            periodStartsAt: String::new(),
            periodEndsAt: String::new(),
            conversionQuoteId: String::new(),
        },
    }
    .eip712_signing_hash(
        &eip712_domain! { name: "Paykit ERC20 Payment", version: "1", chain_id: 42161, },
    );
    let signature =
        alloy_primitives::hex::decode(canonical_hex(&proof.signature, 65)?).map_err(|_| invalid)?;
    let recovery = match signature[64] {
        27 => 0,
        28 => 1,
        _ => return Err(invalid),
    };
    let signature = RecoverableSignature::from_compact(
        &signature[..64],
        RecoveryId::from_i32(recovery).map_err(|_| invalid)?,
    )
    .map_err(|_| invalid)?;
    let standard = signature.to_standard();
    let mut normalized = standard;
    normalized.normalize_s();
    if standard != normalized {
        return Err(invalid);
    }
    let public = Secp256k1::verification_only()
        .recover_ecdsa(&Message::from_digest(digest.0), &signature)
        .map_err(|_| invalid)?;
    let sender = Address::from_slice(
        &alloy_primitives::keccak256(&public.serialize_uncompressed()[1..])[12..],
    );
    Ok((proof, hash, index_usize, sender))
}

fn transfer_amount(
    log: &Value,
    sender: Address,
    recipient: &UsdtAddress,
    hash: B256,
    block_hash: &Value,
) -> Result<u64, VerificationError> {
    let invalid = VerificationError::InvalidProof;
    let topics = log["topics"]
        .as_array()
        .filter(|topics| topics.len() == 3)
        .ok_or(invalid)?;
    if log["removed"] == true
        || log["transactionHash"] != format!("{hash:#x}")
        || log["blockHash"] != *block_hash
        || Address::from_str(log["address"].as_str().ok_or(invalid)?).map_err(|_| invalid)?
            != Address::from_str(USDT_TOKEN).map_err(|_| invalid)?
        || parse_hash(&topics[0])?
            != alloy_primitives::keccak256("Transfer(address,address,uint256)")
        || parse_hash(&topics[1])? != sender.into_word()
        || parse_hash(&topics[2])?
            != Address::from_str(recipient.as_str())
                .map_err(|_| invalid)?
                .into_word()
    {
        return Err(invalid);
    }
    let data = log["data"].as_str().ok_or(invalid)?;
    let amount = U256::from_be_bytes(
        B256::from_str(canonical_hex(data, 32)?)
            .map_err(|_| invalid)?
            .0,
    );
    let amount = u64::try_from(amount).map_err(|_| invalid)?;
    if amount == 0 {
        return Err(invalid);
    }
    Ok(amount)
}

fn canonical_hex(value: &str, bytes: usize) -> Result<&str, VerificationError> {
    if value.len() != 2 + bytes * 2
        || !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(VerificationError::InvalidProof);
    }
    Ok(value)
}

fn parse_hash(value: &Value) -> Result<B256, VerificationError> {
    value
        .as_str()
        .and_then(|v| B256::from_str(v).ok())
        .ok_or(VerificationError::Unavailable)
}

fn quantity(value: &Value) -> Result<u64, VerificationError> {
    value
        .as_str()
        .and_then(|v| v.strip_prefix("0x"))
        .and_then(|v| u64::from_str_radix(v, 16).ok())
        .ok_or(VerificationError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recoverable_proof() -> PaymentProofRecord {
        let signature = Secp256k1::new().sign_ecdsa_recoverable(
            &Message::from_digest([1; 32]),
            &secp256k1::SecretKey::from_slice(&[1; 32]).unwrap(),
        );
        let (recovery, compact) = signature.serialize_compact();
        let mut signature = compact.to_vec();
        signature.push(27 + recovery.to_i32() as u8);
        serde_json::from_value(json!({
            "event_id": "00000000-0000-4000-8000-000000000001", "stream_item_id": 1,
            "payment_reference": "payment", "payment_app_id": "paykit-server",
            "payment_endpoint_identifier": USDT_ENDPOINT,
            "recorded_at": "2026-10-07T00:00:00Z",
            "proof": {
                "type": "erc20-transfer-eip712", "chain_id": USDT_CHAIN_ID,
                "transaction_hash": format!("0x{}", "11".repeat(32)),
                "receipt_log_index": "0",
                "signature": format!("0x{}", alloy_primitives::hex::encode(signature)),
            }
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn scan_capacity_preserves_active_retry_delays() {
        let verifier = ArbitrumVerifier::new("http://127.0.0.1:1".parse().unwrap()).unwrap();
        let recipient =
            UsdtAddress::try_from("0x2222222222222222222222222222222222222222".to_owned()).unwrap();
        let context = PaymentContext {
            payer: "payer",
            payee: "payee",
            request_id: "0",
            reference: "payment",
            recipient: &recipient,
        };
        let proofs = [recoverable_proof()];
        let mut admitted = Vec::new();
        for _ in 0..2 {
            let mut candidates = 0;
            for index in 0..=MAX_SCAN_REQUESTS {
                let request_id = index.to_string();
                let scan = verifier
                    .payment_scan(
                        &PaymentContext {
                            request_id: &request_id,
                            ..context
                        },
                        &proofs,
                    )
                    .await
                    .unwrap();
                candidates += scan.candidates.len();
                verifier.finish_payment_scan(&scan, false).await;
            }
            admitted.push(candidates);
        }
        assert_eq!(admitted, [MAX_SCAN_REQUESTS, 0]);
        assert_eq!(
            verifier.scans.lock().await.requests.len(),
            MAX_SCAN_REQUESTS
        );

        // A retained request keeps its slot even when it is the only eligible victim.
        let retained = verifier.payment_scan(&context, &proofs).await.unwrap();
        verifier
            .scans
            .lock()
            .await
            .requests
            .get_mut(&retained.key)
            .unwrap()
            .retry_at = Instant::now();
        let mut corrected = proofs.clone();
        corrected[0]
            .proof
            .insert("receipt_log_index".into(), json!("1"));
        let corrected_scan = verifier.payment_scan(&context, &corrected).await.unwrap();
        assert_eq!(corrected_scan.candidates.len(), 1);
        verifier.finish_payment_scan(&corrected_scan, true).await;

        // A completed scan releases its slot without evicting any active cooldown.
        let pending_id = MAX_SCAN_REQUESTS.to_string();
        let pending = PaymentContext {
            request_id: &pending_id,
            ..context
        };
        let scan = verifier.payment_scan(&pending, &proofs).await.unwrap();
        assert_eq!(scan.candidates.len(), 1);
        assert_eq!(
            verifier.scans.lock().await.requests.len(),
            MAX_SCAN_REQUESTS
        );
        assert!(
            verifier
                .payment_scan(&pending, &proofs)
                .await
                .unwrap()
                .candidates
                .is_empty()
        );

        // Once its delay expires, an unchanged request can retry normally.
        verifier
            .scans
            .lock()
            .await
            .requests
            .get_mut(&scan.key)
            .unwrap()
            .retry_at = Instant::now();
        assert_eq!(
            verifier
                .payment_scan(&pending, &proofs)
                .await
                .unwrap()
                .candidates
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn deferred_requests_progress_in_stable_reconciliation_order() {
        let verifier = ArbitrumVerifier::new("http://127.0.0.1:1".parse().unwrap()).unwrap();
        let recipient =
            UsdtAddress::try_from("0x2222222222222222222222222222222222222222".to_owned()).unwrap();
        let proof = recoverable_proof();
        let proofs: Vec<_> = (0..MAX_SCAN_CANDIDATES + 1)
            .map(|index| {
                let mut proof = proof.clone();
                proof
                    .proof
                    .insert("receipt_log_index".into(), json!(index.to_string()));
                proof
            })
            .collect();
        let mut seen = vec![BTreeSet::new(); MAX_SCAN_REQUESTS + 3];
        let mut now = Instant::now();
        for _ in 0..16 {
            now += UNMATCHED_RETRY_DELAY + Duration::from_secs(1);
            let mut admitted = 0;
            for (index, candidates) in seen.iter_mut().enumerate() {
                let request_id = index.to_string();
                let context = PaymentContext {
                    payer: "payer",
                    payee: "payee",
                    request_id: &request_id,
                    reference: "payment",
                    recipient: &recipient,
                };
                let scan = verifier
                    .payment_scan_at(&context, &proofs, now + Duration::from_nanos(index as u64))
                    .await
                    .unwrap();
                if !scan.candidates.is_empty() {
                    candidates.extend(scan.candidates.iter().map(|candidate| candidate.index));
                    admitted += 1;
                }
                verifier.finish_payment_scan(&scan, false).await;
            }
            assert!(admitted <= MAX_SCAN_REQUESTS);
            assert!(verifier.scans.lock().await.requests.len() <= MAX_SCAN_REQUESTS);
            if seen
                .iter()
                .all(|candidates| candidates.len() == proofs.len())
            {
                break;
            }
        }
        for (index, candidates) in seen.iter().enumerate() {
            assert_eq!(candidates.len(), proofs.len(), "request {index}");
        }
    }

    #[tokio::test]
    async fn inactive_partial_scans_release_capacity() {
        let verifier = ArbitrumVerifier::new("http://127.0.0.1:1".parse().unwrap()).unwrap();
        let recipient =
            UsdtAddress::try_from("0x2222222222222222222222222222222222222222".to_owned()).unwrap();
        let context = PaymentContext {
            payer: "payer",
            payee: "payee",
            request_id: "pending",
            reference: "payment",
            recipient: &recipient,
        };
        let proofs = vec![recoverable_proof(); MAX_SCAN_CANDIDATES + 1];
        let now = Instant::now();
        for index in 0..MAX_SCAN_REQUESTS {
            verifier.scans.lock().await.requests.insert(
                blake3::hash(&index.to_le_bytes()),
                ScanState {
                    fingerprint: proof_fingerprint(&proofs),
                    cursor: Some(MAX_SCAN_CANDIDATES),
                    sweep_complete: false,
                    retry_at: now,
                    last_used: now,
                },
            );
        }
        assert!(
            verifier
                .payment_scan_at(&context, &proofs, now)
                .await
                .unwrap()
                .candidates
                .is_empty()
        );
        let scan = verifier
            .payment_scan_at(&context, &proofs, now + SCAN_IDLE_TTL)
            .await
            .unwrap();
        assert_eq!(scan.candidates.len(), 1);
        assert_eq!(
            verifier.scans.lock().await.requests.len(),
            MAX_SCAN_REQUESTS
        );
    }
}
