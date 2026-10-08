use paykit_sdk::{
    ContactRecord, ContactUpdate, LinkedPeerState, PaykitProfile, PaykitSdkError, PubkyPublicKey,
    PublicationStatus, StorageAdapter, StorageTransaction,
};

use super::PaykitAdapter;
use crate::persistence::{InvoiceStore, PendingBuyerContact, PersistenceError};

impl PaykitAdapter {
    /// Saves a verified buyer privately, preferring their Paykit profile to Pubky.app.
    /// Missing profiles, existing contacts and blocked peers are terminal no-ops.
    pub async fn save_buyer_contact(
        &self,
        invoices: &InvoiceStore,
        pending: &PendingBuyerContact,
    ) -> paykit_sdk::Result<()> {
        if pending.creator_id != self.creator_id {
            return Err(PaykitSdkError::Identity {
                context: "buyer contact attempt does not match Creator".into(),
                source: None,
            });
        }
        let buyer = PubkyPublicKey::from_raw_or_app_key(pending.reader.to_string())?;
        let owner = PubkyPublicKey::from_raw_or_app_key(self.creator.to_string())?;
        let contact = self.resolve_buyer_contact(&owner, buyer).await?;
        let _guard = self.mutation_lock.lock().await;
        // The shared-state lock fences all workers, including claims whose retry
        // delay elapsed during profile resolution. Record completion before
        // releasing it, so a later attempt cannot recreate a deleted contact.
        self.storage
            .with_operation(async {
                if !invoices
                    .buyer_contact_is_pending(pending)
                    .await
                    .map_err(contact_store_error)?
                {
                    return Ok(());
                }
                if let Some(contact) = contact {
                    self.storage
                        .transaction(move |tx| insert_buyer_contact(tx, &owner, contact))
                        .await?;
                }
                invoices
                    .complete_buyer_contact(pending)
                    .await
                    .map_err(contact_store_error)
            })
            .await
    }

    async fn resolve_buyer_contact(
        &self,
        owner: &PubkyPublicKey,
        buyer: PubkyPublicKey,
    ) -> paykit_sdk::Result<Option<ContactRecord>> {
        if &buyer == owner {
            return Ok(None);
        }
        let Some(resolved) = self.sdk.resolve_profile(buyer.clone(), true).await? else {
            return Ok(None);
        };
        let profile = resolved.paykit_profile.unwrap_or(PaykitProfile {
            display_name: resolved.display_name,
            image_uri: resolved.image_uri,
            extra: None,
        });
        profile.validate()?;
        let update = ContactUpdate {
            public_key: buyer,
            label: profile
                .display_name
                .as_deref()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned),
        };
        update.validate()?;
        let now = std::time::SystemTime::now().into();
        Ok(Some(ContactRecord {
            public_key: update.public_key,
            label: update.label,
            profile: Some(profile),
            profile_fetched_at: Some(now),
            created_at: now,
            updated_at: now,
            public_contact_marker_status: PublicationStatus::NotPublished,
            public_contact_published_at: None,
            public_contact_removed_at: None,
            public_contact_last_error: None,
        }))
    }
}

fn contact_store_error(_error: PersistenceError) -> PaykitSdkError {
    PaykitSdkError::Storage {
        context: "buyer contact work unavailable".into(),
        source: None,
    }
}

fn insert_buyer_contact(
    tx: &mut dyn StorageTransaction,
    owner: &PubkyPublicKey,
    contact: ContactRecord,
) -> paykit_sdk::Result<()> {
    if tx
        .load_identity_state()
        .and_then(|identity| identity.public_key)
        .as_ref()
        != Some(owner)
    {
        return Err(PaykitSdkError::Identity {
            context: "buyer contact identity does not match Creator".into(),
            source: None,
        });
    }
    if &contact.public_key == owner
        || tx.contact_record(&contact.public_key).is_some()
        || tx
            .linked_peer(&contact.public_key)
            .is_some_and(|peer| peer.state == LinkedPeerState::Blocked)
    {
        return Ok(());
    }
    tx.save_contact_record(contact);
    Ok(())
}
