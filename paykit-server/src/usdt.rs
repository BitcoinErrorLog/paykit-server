//! Direct Arbitrum USDT0 receipts and Paykit ERC-20 account attestations.

use std::{
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
}

const CHAIN_TIP_TTL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
struct ChainTip {
    head: u64,
    finalized: Option<u64>,
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
        })
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
        let (proof, hash, index, sender) = parse_proof(context, record)?;
        let mut tip = self.chain_tip(0).await?;
        let receipt = self
            .call("eth_getTransactionReceipt", json!([proof.transaction_hash]))
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
        let amount = transfer_amount(log, sender, context.recipient, hash, &receipt["blockHash"])?;
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
        }))
    }
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
