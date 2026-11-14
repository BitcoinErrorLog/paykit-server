//! Reads the Receipts the seller's wallet issued for Marketplace requests.
//!
//! The seller's wallet shares the Creator's identity-wide SDK state, sees the
//! server's Marketplace Payment Requests as payee, and issues a Receipt when it
//! receives the money. The server never issues Receipts. It accepts one only
//! when its Payment Request ID is the request's, its counterparty is the
//! request's reader, and another App on the identity issued it, and decrypts
//! only those: the seller's other Receipts are listed but never opened.
//!
//! Every SDK storage transaction takes the identity's shared-state write lock,
//! which the seller's wallet also needs, so reads are spaced out per Creator
//! and made only while the Creator has a request waiting for its Receipt.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex as StdMutex,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use paykit_sdk::{PaykitSdkError, PubkyPublicKey};
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use super::{PaykitAdapter, allowances::reader_of, sdk_error_label};
use crate::{
    application::marketplace_receipt::{SellerReceipt, SellerReceiptAmount},
    crypto::LookupHash,
    domain::locks::ReaderPubky,
    persistence::{MarketplacePreparationStore, OpenSellerReceiptRequest, SellerReceiptStored},
};

/// Least time between two reads of one Creator's issued Receipts.
pub const SELLER_RECEIPT_READ_INTERVAL: Duration = Duration::from_secs(30);

/// A Creator whose read took `d` is read again no sooner than `d` times this
/// after that read began.
const SELLER_RECEIPT_SPACING_FACTOR: u32 = 10;

/// How long a started read counts as taking until it reports back, so a read
/// that never does, as after a panic, is spaced out by ten times this.
const SELLER_RECEIPT_UNFINISHED_READ: Duration = Duration::from_secs(60);

/// Receipts one read decrypts. Each is its own SDK call under the shared-state
/// lock; matches left over are read on the next pass.
const MAX_SELLER_RECEIPTS_PER_READ: usize = 4;

/// Decides when a Creator's issued Receipts are read: no sooner than the
/// interval, or ten times the last read's duration, after the last read began.
#[derive(Debug)]
pub struct SellerReceiptReads {
    interval: Duration,
    creators: StdMutex<HashMap<Uuid, ReadSpacing>>,
}

#[derive(Debug, Clone, Copy)]
struct ReadSpacing {
    last_started: Instant,
    last_took: Duration,
}

impl SellerReceiptReads {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            creators: StdMutex::new(HashMap::new()),
        }
    }

    /// Whether `creator` may be read at `now`.
    pub fn is_due(&self, creator: Uuid, now: Instant) -> bool {
        self.creators
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&creator)
            .is_none_or(|spacing| {
                now.saturating_duration_since(spacing.last_started)
                    >= self
                        .interval
                        .max(spacing.last_took * SELLER_RECEIPT_SPACING_FACTOR)
            })
    }

    /// Starts a due read; it counts against the spacing at once.
    fn begin(&self, creator: Uuid, now: Instant) -> bool {
        if !self.is_due(creator, now) {
            return false;
        }
        self.creators
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                creator,
                ReadSpacing {
                    last_started: now,
                    last_took: SELLER_RECEIPT_UNFINISHED_READ,
                },
            );
        true
    }

    fn finish(&self, creator: Uuid, took: Duration) {
        if let Some(spacing) = self
            .creators
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_mut(&creator)
        {
            spacing.last_took = took;
        }
    }
}

/// One local Receipt issuance record, as the SDK lists it without decrypting.
#[derive(Clone, Debug)]
struct IssuedReceipt {
    counterparty: PubkyPublicKey,
    app_id: String,
    receipt_id: String,
    payment_request_id: Option<String>,
    issued_at: OffsetDateTime,
}

/// The two SDK reads: the identity's issued Receipts, and one decrypted.
#[async_trait]
trait IssuedReceipts: Send + Sync {
    async fn issued(&self) -> paykit_sdk::Result<Vec<IssuedReceipt>>;

    async fn decrypt(
        &self,
        counterparty: &PubkyPublicKey,
        receipt_id: &str,
    ) -> paykit_sdk::Result<paykit_lib::Receipt>;
}

#[async_trait]
impl IssuedReceipts for PaykitAdapter {
    async fn issued(&self) -> paykit_sdk::Result<Vec<IssuedReceipt>> {
        Ok(self
            .sdk
            .issued_receipts()
            .await?
            .into_iter()
            // Only a Receipt the wallet has stored at its Receipt Location,
            // which the buyer can fetch too, is the wallet's attestation.
            .filter(|view| view.stored_at.is_some())
            .filter_map(|view| {
                let issued_at = OffsetDateTime::from_unix_timestamp_nanos(i128::from(
                    view.created_at.timestamp_nanos_opt()?,
                ))
                .ok()?;
                Some(IssuedReceipt {
                    counterparty: view.counterparty,
                    app_id: view.app_id.as_str().to_owned(),
                    receipt_id: view.receipt_id,
                    payment_request_id: view.payment_request_id,
                    issued_at,
                })
            })
            .collect())
    }

    async fn decrypt(
        &self,
        counterparty: &PubkyPublicKey,
        receipt_id: &str,
    ) -> paykit_sdk::Result<paykit_lib::Receipt> {
        self.sdk.issued_receipt(counterparty, receipt_id).await
    }
}

impl PaykitAdapter {
    /// Reads this Creator's issued Receipts once, when it has an open
    /// Marketplace request without a stored seller Receipt and its spacing
    /// allows, and stores each Receipt that matches such a request. Returns
    /// how many it stored.
    pub async fn read_seller_receipts(
        &self,
        reads: &SellerReceiptReads,
        store: &MarketplacePreparationStore,
    ) -> paykit_sdk::Result<usize> {
        let open = store
            .open_seller_receipt_requests(self.creator_id)
            .await
            .map_err(|_| PaykitSdkError::Storage {
                context: "open Marketplace requests unavailable".into(),
                source: None,
            })?;
        if open.is_empty() || !reads.begin(self.creator_id, Instant::now()) {
            return Ok(0);
        }
        let started = Instant::now();
        let matched = {
            let _guard = self.mutation_lock.lock().await;
            read_matching(self, self.app_id.as_str(), &open, &|reader| {
                store.reader_lookup_hash(reader)
            })
            .await
        };
        reads.finish(self.creator_id, started.elapsed());
        let mut stored = 0;
        for (invoice_id, receipt) in matched? {
            match store
                .store_seller_receipt(self.creator_id, invoice_id, &receipt)
                .await
            {
                Ok(SellerReceiptStored::Stored) => stored += 1,
                Ok(SellerReceiptStored::Unchanged) => {}
                Ok(SellerReceiptStored::KeptFirst) => warn!(
                    stage = "seller_receipts",
                    step = "store",
                    category = "kept_first_receipt",
                    "Another seller Receipt is already stored for the request"
                ),
                Err(error) => warn!(
                    stage = "seller_receipts",
                    step = "store",
                    category = error.diagnostic_label(),
                    "Seller Receipt not stored"
                ),
            }
        }
        Ok(stored)
    }
}

/// The issued Receipts that answer an open request, oldest first, at most one
/// per request: same Payment Request ID, issued to the request's reader, by an
/// App other than this server.
fn matching<'a>(
    issued: &'a [IssuedReceipt],
    open: &'a [OpenSellerReceiptRequest],
    own_app_id: &str,
    reader_hash: &dyn Fn(&ReaderPubky) -> LookupHash,
) -> Vec<(&'a OpenSellerReceiptRequest, &'a IssuedReceipt)> {
    let mut oldest_first = issued.iter().collect::<Vec<_>>();
    oldest_first.sort_by_key(|receipt| receipt.issued_at);
    let mut answered = HashSet::new();
    oldest_first
        .into_iter()
        .filter(|receipt| receipt.app_id != own_app_id)
        .filter_map(|receipt| {
            let request_id = receipt.payment_request_id.as_deref()?;
            let request = open
                .iter()
                .find(|request| request.payment_request_id == request_id)?;
            let reader = reader_of(&receipt.counterparty)?;
            (reader_hash(&reader) == request.reader_lookup_hash
                && answered.insert(request.invoice_id))
            .then_some((request, receipt))
        })
        .collect()
}

/// Lists the issued Receipts once and decrypts only those [`matching`] an
/// open request, at most [`MAX_SELLER_RECEIPTS_PER_READ`] of them. A Receipt
/// whose decrypted content disagrees with its record is skipped.
async fn read_matching<S: IssuedReceipts + ?Sized>(
    source: &S,
    own_app_id: &str,
    open: &[OpenSellerReceiptRequest],
    reader_hash: &(dyn Fn(&ReaderPubky) -> LookupHash + Sync),
) -> paykit_sdk::Result<Vec<(Uuid, SellerReceipt)>> {
    let issued = source.issued().await?;
    let mut accepted = Vec::new();
    for (request, record) in matching(&issued, open, own_app_id, reader_hash)
        .into_iter()
        .take(MAX_SELLER_RECEIPTS_PER_READ)
    {
        let receipt = match source
            .decrypt(&record.counterparty, &record.receipt_id)
            .await
        {
            Ok(receipt) => receipt,
            // Gone, or the buyer is now blocked: nothing to accept.
            Err(PaykitSdkError::NotFound { .. } | PaykitSdkError::Policy { .. }) => continue,
            // The wallet holds the lock; the rest wait for the next read.
            Err(
                PaykitSdkError::SharedStateBusy { .. } | PaykitSdkError::ConcurrentUpdate { .. },
            ) => break,
            Err(error) => {
                warn!(
                    stage = "seller_receipts",
                    step = "issued_receipt",
                    category = sdk_error_label(&error),
                    "Seller Receipt read failed"
                );
                break;
            }
        };
        let recipient = record.counterparty.to_public_key().ok();
        if receipt.receipt_id.as_str() != record.receipt_id
            || receipt.payment_request_id.as_ref().map(|id| id.as_str())
                != Some(request.payment_request_id.as_str())
            || recipient.as_ref() != Some(&receipt.recipient_public_key)
        {
            warn!(
                stage = "seller_receipts",
                step = "issued_receipt",
                category = "receipt_mismatch",
                "Seller Receipt does not match its issuance record"
            );
            continue;
        }
        accepted.push((
            request.invoice_id,
            SellerReceipt {
                receipt_id: record.receipt_id.clone(),
                app_id: record.app_id.clone(),
                payment_request_id: request.payment_request_id.clone(),
                payment_reference: receipt.payment_reference.as_str().to_owned(),
                payment_endpoint_identifier: receipt
                    .payment_endpoint_identifier
                    .as_ref()
                    .map(|id| id.as_str().to_owned()),
                amount: receipt.amount.as_ref().map(|amount| SellerReceiptAmount {
                    value: amount.value().to_owned(),
                    currency: amount.asset().to_owned(),
                }),
                metadata: receipt.metadata,
                issued_at: record.issued_at,
            },
        ));
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::crypto::Crypto;

    const BUYER: &str = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";
    const OTHER: &str = "5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo";
    const REQUEST_ID: &str = "4c6e66c7-8a8b-4d54-b97b-340cedb3e1d0";
    /// Receipt IDs are UUID v4 strings.
    const MARKET_ORDER: &str = "9b2f3c1e-4d5a-4b6c-8d7e-1f2a3b4c5d6e";

    fn key(raw: &str) -> PubkyPublicKey {
        PubkyPublicKey::from_raw_or_app_key(raw).unwrap()
    }

    fn crypto() -> Crypto {
        Crypto::from_master_key(&[7; 32]).unwrap()
    }

    fn reader_hash(reader: &ReaderPubky) -> LookupHash {
        crypto().lookup_hash(reader.to_string().as_bytes())
    }

    fn open_request() -> OpenSellerReceiptRequest {
        OpenSellerReceiptRequest {
            invoice_id: Uuid::from_u128(1),
            payment_request_id: REQUEST_ID.into(),
            reader_lookup_hash: reader_hash(&reader_of(&key(BUYER)).unwrap()),
        }
    }

    fn issued(
        receipt_id: &str,
        counterparty: &str,
        app_id: &str,
        request_id: Option<&str>,
    ) -> IssuedReceipt {
        IssuedReceipt {
            counterparty: key(counterparty),
            app_id: app_id.into(),
            receipt_id: receipt_id.into(),
            payment_request_id: request_id.map(str::to_owned),
            issued_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn bitkit(receipt_id: &str) -> IssuedReceipt {
        issued(receipt_id, BUYER, "bitkit", Some(REQUEST_ID))
    }

    fn matched_ids(issued: &[IssuedReceipt]) -> Vec<String> {
        matching(issued, &[open_request()], "paykit-server", &reader_hash)
            .into_iter()
            .map(|(_, receipt)| receipt.receipt_id.clone())
            .collect()
    }

    #[test]
    fn a_receipt_another_app_issued_to_the_reader_for_the_request_matches() {
        assert_eq!(matched_ids(&[bitkit("r-1")]), ["r-1"]);
    }

    #[test]
    fn a_receipt_for_another_payment_request_does_not_match() {
        let other_request = issued(
            "r-1",
            BUYER,
            "bitkit",
            Some("0e2f8c0e-7c43-4a4b-8f1e-35c1d1f0c1a2"),
        );
        let no_request = issued("r-2", BUYER, "bitkit", None);
        assert!(matched_ids(&[other_request, no_request]).is_empty());
    }

    #[test]
    fn a_receipt_issued_to_someone_other_than_the_reader_does_not_match() {
        assert!(matched_ids(&[issued("r-1", OTHER, "bitkit", Some(REQUEST_ID))]).is_empty());
    }

    #[test]
    fn a_receipt_this_server_issued_does_not_match() {
        assert!(matched_ids(&[issued("r-1", BUYER, "paykit-server", Some(REQUEST_ID))]).is_empty());
    }

    #[test]
    fn the_oldest_matching_receipt_answers_a_request() {
        let mut newer = bitkit("r-new");
        newer.issued_at = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(5);
        assert_eq!(matched_ids(&[newer, bitkit("r-old")]), ["r-old"]);
    }

    struct FakeWallet {
        issued: Vec<IssuedReceipt>,
        decrypted: Mutex<Vec<String>>,
        decrypt_error: Option<fn() -> PaykitSdkError>,
        wrong_request_id: bool,
    }

    impl FakeWallet {
        fn new(issued: Vec<IssuedReceipt>) -> Self {
            Self {
                issued,
                decrypted: Mutex::new(Vec::new()),
                decrypt_error: None,
                wrong_request_id: false,
            }
        }
    }

    #[async_trait]
    impl IssuedReceipts for FakeWallet {
        async fn issued(&self) -> paykit_sdk::Result<Vec<IssuedReceipt>> {
            Ok(self.issued.clone())
        }

        async fn decrypt(
            &self,
            counterparty: &PubkyPublicKey,
            receipt_id: &str,
        ) -> paykit_sdk::Result<paykit_lib::Receipt> {
            self.decrypted.lock().unwrap().push(receipt_id.to_owned());
            if let Some(error) = self.decrypt_error {
                return Err(error());
            }
            let mut metadata = serde_json::Map::new();
            metadata.insert("txid".into(), "ab".repeat(32).into());
            let request_id = if self.wrong_request_id {
                "0e2f8c0e-7c43-4a4b-8f1e-35c1d1f0c1a2"
            } else {
                REQUEST_ID
            };
            Ok(paykit_lib::Receipt {
                receipt_id: paykit_lib::ReceiptId::new(receipt_id).unwrap(),
                payment_reference: paykit_lib::PaymentReference::new("order-7").unwrap(),
                payment_request_id: Some(paykit_lib::PaymentRequestId::new(request_id).unwrap()),
                billing_period: None,
                recipient_public_key: counterparty.to_public_key().unwrap(),
                payment_endpoint_identifier: None,
                amount: Some(paykit_lib::PaymentAmount::new("1500", "SAT").unwrap()),
                metadata,
            })
        }
    }

    async fn read(wallet: &FakeWallet) -> paykit_sdk::Result<Vec<(Uuid, SellerReceipt)>> {
        read_matching(wallet, "paykit-server", &[open_request()], &reader_hash).await
    }

    #[tokio::test]
    async fn only_the_matching_receipt_is_decrypted_and_reported_as_issued() {
        let wallet = FakeWallet::new(vec![
            issued("unrelated-sale", OTHER, "bitkit", None),
            issued("server-own", BUYER, "paykit-server", Some(REQUEST_ID)),
            issued("other-buyer", OTHER, "bitkit", Some(REQUEST_ID)),
            bitkit(MARKET_ORDER),
        ]);
        let accepted = read(&wallet).await.unwrap();
        assert_eq!(*wallet.decrypted.lock().unwrap(), [MARKET_ORDER]);
        let [(invoice_id, receipt)] = accepted.as_slice() else {
            panic!("one Receipt is accepted");
        };
        assert_eq!(*invoice_id, Uuid::from_u128(1));
        assert_eq!(receipt.receipt_id, MARKET_ORDER);
        assert_eq!(receipt.app_id, "bitkit");
        assert_eq!(receipt.payment_request_id, REQUEST_ID);
        assert_eq!(receipt.payment_reference, "order-7");
        assert_eq!(
            receipt.amount,
            Some(SellerReceiptAmount {
                value: "1500".into(),
                currency: "SAT".into(),
            })
        );
        assert_eq!(receipt.metadata["txid"], "ab".repeat(32));
    }

    #[tokio::test]
    async fn nothing_is_decrypted_without_a_match() {
        let wallet = FakeWallet::new(vec![issued("unrelated-sale", OTHER, "bitkit", None)]);
        assert!(read(&wallet).await.unwrap().is_empty());
        assert!(wallet.decrypted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_receipt_whose_content_disagrees_with_its_record_is_skipped() {
        let mut wallet = FakeWallet::new(vec![bitkit(MARKET_ORDER)]);
        wallet.wrong_request_id = true;
        assert!(read(&wallet).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_missing_or_blocked_receipt_is_skipped_and_a_busy_state_stops_the_read() {
        for error in [
            (|| PaykitSdkError::NotFound {
                context: "gone".into(),
                source: None,
            }) as fn() -> PaykitSdkError,
            || PaykitSdkError::Policy {
                context: "blocked".into(),
                source: None,
            },
            || PaykitSdkError::SharedStateBusy {
                context: "held".into(),
                source: None,
            },
        ] {
            let mut wallet = FakeWallet::new(vec![bitkit(MARKET_ORDER)]);
            wallet.decrypt_error = Some(error);
            assert!(read(&wallet).await.unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn one_read_decrypts_at_most_its_limit() {
        let open = (0..6_u128)
            .map(|index| OpenSellerReceiptRequest {
                invoice_id: Uuid::from_u128(index),
                payment_request_id: Uuid::from_u128(index).hyphenated().to_string(),
                reader_lookup_hash: open_request().reader_lookup_hash,
            })
            .collect::<Vec<_>>();
        let wallet = FakeWallet::new(
            open.iter()
                .map(|request| {
                    issued(
                        &Uuid::new_v4().to_string(),
                        BUYER,
                        "bitkit",
                        Some(&request.payment_request_id),
                    )
                })
                .collect(),
        );
        read_matching(&wallet, "paykit-server", &open, &reader_hash)
            .await
            .unwrap();
        assert_eq!(
            wallet.decrypted.lock().unwrap().len(),
            MAX_SELLER_RECEIPTS_PER_READ
        );
    }

    #[test]
    fn a_creator_is_read_at_most_once_per_interval() {
        let reads = SellerReceiptReads::new(Duration::from_secs(30));
        let creator = Uuid::from_u128(9);
        let other = Uuid::from_u128(10);
        let start = Instant::now();
        assert!(reads.begin(creator, start));
        reads.finish(creator, Duration::from_millis(100));
        assert!(!reads.is_due(creator, start + Duration::from_secs(29)));
        assert!(
            reads.is_due(other, start),
            "Creators are spaced independently"
        );
        assert!(reads.begin(creator, start + Duration::from_secs(30)));
    }

    #[test]
    fn a_slow_or_unfinished_read_spaces_the_next_one_out() {
        let reads = SellerReceiptReads::new(Duration::from_secs(30));
        let creator = Uuid::from_u128(9);
        let start = Instant::now();
        assert!(reads.begin(creator, start));
        // Not reported back: counts as a minute-long read.
        assert!(!reads.is_due(creator, start + Duration::from_secs(599)));
        assert!(reads.is_due(creator, start + Duration::from_secs(600)));
        reads.finish(creator, Duration::from_secs(5));
        assert!(!reads.is_due(creator, start + Duration::from_secs(49)));
        assert!(reads.is_due(creator, start + Duration::from_secs(50)));
    }
}
