//! Encrypted full Paykit SDK state snapshots.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use paykit_sdk::{
    PaykitSdkError,
    storage::{
        StorageAdapter, StorageState, StorageTransactionCallback, run_storage_state_transaction,
    },
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    domain::locks::CreatorPubky,
    persistence::{PersistenceError, creators::CreatorRow},
};

/// Encrypted SDK-state repository with one locked state row per mutation.
#[derive(Clone, Debug)]
pub struct SdkStateStore {
    pool: PgPool,
    crypto: Arc<Crypto>,
}

/// Creator-scoped public Paykit SDK storage adapter backed by one encrypted
/// PostgreSQL `StorageState` row.
#[derive(Clone)]
pub struct PostgresStorageAdapter {
    pool: PgPool,
    crypto: Arc<Crypto>,
    creator_id: Uuid,
    invocation_token: Arc<Mutex<Option<Uuid>>>,
}

impl std::fmt::Debug for PostgresStorageAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PostgresStorageAdapter { <redacted> }")
    }
}

impl PostgresStorageAdapter {
    pub fn new(pool: &PgPool, crypto: Arc<Crypto>, creator_id: Uuid) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
            creator_id,
            invocation_token: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) fn creator_id(&self) -> Uuid {
        self.creator_id
    }

    /// Binds exactly one fenced handoff invocation to the next SDK-created
    /// outbound record(s). `PaykitAdapter` serializes creator mutations and
    /// clears this scope immediately after the handoff returns.
    pub(crate) fn set_invocation_token(&self, token: Uuid) -> paykit_sdk::Result<()> {
        let mut slot = self
            .invocation_token
            .lock()
            .map_err(|_| storage_context("invocation token scope is unavailable"))?;
        if slot.is_some() {
            return Err(storage_context("invocation token scope is already active"));
        }
        *slot = Some(token);
        Ok(())
    }

    pub(crate) fn clear_invocation_token(&self) {
        if let Ok(mut slot) = self.invocation_token.lock() {
            *slot = None;
        }
    }

    #[cfg(feature = "test-utils")]
    pub fn set_invocation_token_for_test(&self, token: Uuid) -> paykit_sdk::Result<()> {
        self.set_invocation_token(token)
    }

    #[cfg(feature = "test-utils")]
    pub fn clear_invocation_token_for_test(&self) {
        self.clear_invocation_token();
    }
}

#[async_trait]
impl StorageAdapter for PostgresStorageAdapter {
    async fn transaction_erased<'a>(
        &self,
        callback: StorageTransactionCallback<'a>,
    ) -> paykit_sdk::Result<Box<dyn std::any::Any + Send>> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        let (creator_id, lookup_hash): (Uuid, Vec<u8>) =
            sqlx::query_as("SELECT id, creator_lookup_hash FROM creators WHERE id = $1")
                .bind(self.creator_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_error)?
                .ok_or_else(|| storage_context("creator SDK state is unavailable"))?;
        let envelope: Vec<u8> = sqlx::query_scalar(
            "SELECT state_envelope FROM sdk_states WHERE creator_id = $1 FOR UPDATE",
        )
        .bind(self.creator_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| storage_context("creator SDK state is unavailable"))?;
        let hash_bytes: [u8; 32] = lookup_hash
            .try_into()
            .map_err(|_| storage_context("creator lookup hash is invalid"))?;
        let hash = LookupHash::from_bytes(hash_bytes);
        let state =
            decrypt_state(&self.crypto, hash, creator_id, &envelope).map_err(persistence_error)?;
        let before_outbound_ids = state
            .outbound_private_messages
            .iter()
            .map(|record| record.outbound_message_id)
            .collect::<Vec<_>>();
        let (updated, result) = run_storage_state_transaction(state, callback)?;
        let after_outbound_ids = updated
            .outbound_private_messages
            .iter()
            .map(|record| record.outbound_message_id)
            .collect::<Vec<_>>();
        if !after_outbound_ids.starts_with(&before_outbound_ids) {
            return Err(storage_context(
                "SDK changed existing outbound record identities",
            ));
        }
        let new_outbound_ids = &after_outbound_ids[before_outbound_ids.len()..];
        if new_outbound_ids.len() > 1 {
            return Err(storage_context(
                "SDK callback appended multiple outbound records",
            ));
        }
        let encrypted =
            encrypt_state(&self.crypto, hash, creator_id, &updated).map_err(persistence_error)?;
        let changed = sqlx::query(
            "UPDATE sdk_states SET state_envelope = $1, updated_at = NOW() WHERE creator_id = $2",
        )
        .bind(encrypted.as_bytes())
        .bind(self.creator_id)
        .execute(&mut *tx)
        .await
        .map_err(storage_error)?;
        if changed.rows_affected() != 1 {
            return Err(storage_context("creator SDK state update was lost"));
        }
        let invocation_token = *self
            .invocation_token
            .lock()
            .map_err(|_| storage_context("invocation token scope is unavailable"))?;
        if let (Some(token), Some(outbound_id)) = (invocation_token, new_outbound_ids.first()) {
            sqlx::query(
                "INSERT INTO sdk_outbound_invocations \
                 (creator_id, sdk_outbound_message_id, invocation_token) VALUES ($1, $2, $3)",
            )
            .bind(self.creator_id)
            .bind(outbound_id.to_string())
            .bind(token)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        }
        tx.commit().await.map_err(storage_error)?;
        Ok(result)
    }
}

fn storage_context(context: &str) -> PaykitSdkError {
    PaykitSdkError::Storage {
        context: context.into(),
        source: None,
    }
}

fn storage_error(_error: sqlx::Error) -> PaykitSdkError {
    PaykitSdkError::Storage {
        context: "PostgreSQL SDK state transaction failed".into(),
        source: None,
    }
}

fn persistence_error(_error: PersistenceError) -> PaykitSdkError {
    storage_context("encrypted creator SDK state is invalid")
}

impl SdkStateStore {
    /// Creates an SDK state repository using a deployment-scoped crypto context.
    pub fn new(pool: &PgPool, crypto: Arc<Crypto>) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
        }
    }

    /// Loads the complete SDK state for one creator.
    pub async fn load(&self, creator: &CreatorPubky) -> Result<StorageState, PersistenceError> {
        let row = creator_row(&self.pool, &self.crypto, creator).await?;
        load_state_by_row(&self.pool, &self.crypto, &row).await
    }

    /// Atomically decrypts, synchronously mutates, and replaces one full SDK state snapshot.
    pub async fn update<F>(&self, creator: &CreatorPubky, mutate: F) -> Result<(), PersistenceError>
    where
        F: FnOnce(&mut StorageState) + Send,
    {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let row = sqlx::query_as::<_, CreatorRow>("SELECT id, creator_lookup_hash, credential_envelope FROM creators WHERE creator_lookup_hash = $1")
            .bind(hash.as_bytes().as_slice()).fetch_optional(&mut *tx).await.map_err(|_| PersistenceError::Unavailable)?.ok_or(PersistenceError::CorruptOrMissing)?;
        let state_envelope: Vec<u8> = sqlx::query_scalar(
            "SELECT state_envelope FROM sdk_states WHERE creator_id = $1 FOR UPDATE",
        )
        .bind(row.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        let mut state = decrypt_state(&self.crypto, row.lookup_hash()?, row.id, &state_envelope)?;
        mutate(&mut state);
        let envelope = encrypt_state(&self.crypto, row.lookup_hash()?, row.id, &state)?;
        sqlx::query(
            "UPDATE sdk_states SET state_envelope = $1, updated_at = NOW() WHERE creator_id = $2",
        )
        .bind(envelope.as_bytes())
        .bind(row.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit().await.map_err(|_| PersistenceError::Unavailable)
    }
}

#[derive(Serialize)]
struct SdkStateV1Ref<'a> {
    version: u8,
    state: &'a StorageState,
}

#[derive(Deserialize)]
struct SdkStateV1 {
    version: u8,
    state: StorageState,
}

pub(crate) fn encrypt_state(
    crypto: &Crypto,
    hash: LookupHash,
    id: Uuid,
    state: &StorageState,
) -> Result<EncryptedEnvelope, PersistenceError> {
    let bytes = Zeroizing::new(
        postcard::to_allocvec(&SdkStateV1Ref { version: 1, state })
            .map_err(|_| PersistenceError::CorruptOrMissing)?,
    );
    crypto
        .encrypt(&EnvelopeContext::sdk_state(hash, id), &bytes)
        .map_err(|_| PersistenceError::CorruptOrMissing)
}

pub(crate) async fn load_state_by_row(
    pool: &PgPool,
    crypto: &Crypto,
    row: &CreatorRow,
) -> Result<StorageState, PersistenceError> {
    let envelope: Vec<u8> =
        sqlx::query_scalar("SELECT state_envelope FROM sdk_states WHERE creator_id = $1")
            .bind(row.id)
            .fetch_optional(pool)
            .await
            .map_err(|_| PersistenceError::Unavailable)?
            .ok_or(PersistenceError::CorruptOrMissing)?;
    decrypt_state(crypto, row.lookup_hash()?, row.id, &envelope)
}

pub(crate) fn decrypt_state(
    crypto: &Crypto,
    hash: LookupHash,
    id: Uuid,
    envelope: &[u8],
) -> Result<StorageState, PersistenceError> {
    let bytes = Zeroizing::new(
        crypto
            .decrypt(
                &EnvelopeContext::sdk_state(hash, id),
                &EncryptedEnvelope::from_bytes(envelope.to_vec()),
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?,
    );
    let wire: SdkStateV1 =
        postcard::from_bytes(&bytes).map_err(|_| PersistenceError::CorruptOrMissing)?;
    if wire.version != 1 {
        return Err(PersistenceError::CorruptOrMissing);
    }
    Ok(wire.state)
}

async fn creator_row(
    pool: &PgPool,
    crypto: &Crypto,
    creator: &CreatorPubky,
) -> Result<CreatorRow, PersistenceError> {
    let hash = crypto.lookup_hash(creator.to_string().as_bytes());
    sqlx::query_as("SELECT id, creator_lookup_hash, credential_envelope FROM creators WHERE creator_lookup_hash = $1")
        .bind(hash.as_bytes().as_slice()).fetch_optional(pool).await.map_err(|_| PersistenceError::Unavailable)?.ok_or(PersistenceError::CorruptOrMissing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    async fn postgres_storage_adapter_debug_redacts_creator_identity() {
        let creator_id = Uuid::new_v4();
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/paykit_debug_test")
            .unwrap();
        let adapter = PostgresStorageAdapter::new(
            &pool,
            Arc::new(Crypto::from_master_key(&[9; 32]).unwrap()),
            creator_id,
        );

        let debug = format!("{adapter:?}");
        assert!(!debug.contains(&creator_id.to_string()));
        assert_eq!(debug, "PostgresStorageAdapter { <redacted> }");
    }

    #[tokio::test]
    async fn invocation_scope_refuses_replacement_and_database_errors_are_static() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/paykit_debug_test")
            .unwrap();
        let adapter = PostgresStorageAdapter::new(
            &pool,
            Arc::new(Crypto::from_master_key(&[10; 32]).unwrap()),
            Uuid::new_v4(),
        );
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        adapter.set_invocation_token(first).unwrap();
        assert!(adapter.set_invocation_token(second).is_err());
        assert_eq!(*adapter.invocation_token.lock().unwrap(), Some(first));
        adapter.clear_invocation_token();

        let sensitive = Uuid::new_v4().to_string();
        let rendered = format!(
            "{:?}",
            storage_error(sqlx::Error::Protocol(sensitive.clone()))
        );
        assert!(!rendered.contains(&sensitive));
        assert!(rendered.contains("PostgreSQL SDK state transaction failed"));
    }
}
