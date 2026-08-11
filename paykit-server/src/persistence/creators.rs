//! Encrypted creator authority persistence.

use std::fmt;

use paykit_sdk::{ReceiverNoiseSecretKey, storage::StorageState};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    crypto::{Crypto, EncryptedEnvelope, EnvelopeContext, LookupHash},
    domain::locks::{CreatorPubky, parse_creator},
    persistence::PersistenceError,
};

/// Secret-bearing creator authority accepted by the persistence boundary.
pub struct CreatorCredentials {
    creator: CreatorPubky,
    session_secret: Zeroizing<String>,
    receiver_noise_secret: ReceiverNoiseSecretKey,
    xpub: Zeroizing<String>,
    account_index: u32,
}

impl fmt::Debug for CreatorCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CreatorCredentials(<redacted>)")
    }
}

impl CreatorCredentials {
    /// Constructs creator authority from canonical identity and SDK secret wrappers.
    pub fn new(
        creator: CreatorPubky,
        session_secret: String,
        receiver_noise_secret: ReceiverNoiseSecretKey,
        xpub: String,
        account_index: u32,
    ) -> Self {
        Self::from_secret_parts(
            creator,
            Zeroizing::new(session_secret),
            receiver_noise_secret,
            Zeroizing::new(xpub),
            account_index,
        )
    }

    fn from_secret_parts(
        creator: CreatorPubky,
        session_secret: Zeroizing<String>,
        receiver_noise_secret: ReceiverNoiseSecretKey,
        xpub: Zeroizing<String>,
        account_index: u32,
    ) -> Self {
        Self {
            creator,
            session_secret,
            receiver_noise_secret,
            xpub,
            account_index,
        }
    }

    /// Returns the canonical creator identity.
    pub fn creator(&self) -> &CreatorPubky {
        &self.creator
    }
    /// Borrows the current Pubky session bearer secret.
    pub fn session_secret(&self) -> &str {
        self.session_secret.as_str()
    }
    /// Borrows the receiver-scoped Noise secret.
    pub fn receiver_noise_secret(&self) -> &ReceiverNoiseSecretKey {
        &self.receiver_noise_secret
    }
    /// Borrows the exact persisted account xpub.
    pub fn xpub(&self) -> &str {
        self.xpub.as_str()
    }
    /// Returns the immutable account index.
    pub fn account_index(&self) -> u32 {
        self.account_index
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, PersistenceError> {
        let creator = self.creator.to_string();
        let wire = CreatorCredentialsV1Ref {
            version: 1,
            creator: &creator,
            session_secret: self.session_secret.as_str(),
            receiver_noise_secret: self.receiver_noise_secret.as_bytes(),
            xpub: self.xpub.as_str(),
            account_index: self.account_index,
        };
        postcard::to_allocvec(&wire)
            .map(Zeroizing::new)
            .map_err(|_| PersistenceError::CorruptOrMissing)
    }

    fn decode(bytes: &[u8]) -> Result<Self, PersistenceError> {
        let wire: CreatorCredentialsV1 =
            postcard::from_bytes(bytes).map_err(|_| PersistenceError::CorruptOrMissing)?;
        if wire.version != 1 {
            return Err(PersistenceError::CorruptOrMissing);
        }
        let creator =
            parse_creator(&wire.creator).map_err(|_| PersistenceError::CorruptOrMissing)?;
        Ok(Self::from_secret_parts(
            creator,
            wire.session_secret,
            ReceiverNoiseSecretKey::new(*wire.receiver_noise_secret),
            wire.xpub,
            wire.account_index,
        ))
    }
}

#[derive(Serialize)]
struct CreatorCredentialsV1Ref<'a> {
    version: u8,
    creator: &'a str,
    session_secret: &'a str,
    receiver_noise_secret: &'a [u8; 32],
    xpub: &'a str,
    account_index: u32,
}

#[derive(Deserialize)]
struct CreatorCredentialsV1 {
    version: u8,
    creator: String,
    session_secret: Zeroizing<String>,
    receiver_noise_secret: Zeroizing<[u8; 32]>,
    xpub: Zeroizing<String>,
    account_index: u32,
}

/// Immutable identity assigned to a persisted creator row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedCreator {
    id: Uuid,
    lookup_hash: LookupHash,
}
impl PersistedCreator {
    /// Returns the internal row UUID used in envelope AAD.
    pub fn id(&self) -> Uuid {
        self.id
    }
}

/// Encrypted creator and initial SDK-state repository.
#[derive(Clone, Debug)]
pub struct CreatorStore {
    pool: PgPool,
    crypto: std::sync::Arc<Crypto>,
}

/// A creator-scoped PostgreSQL session advisory lock used to serialize setup
/// publication and persistence across all server processes sharing the database.
/// Its dedicated connection is detached from the pool, so cancellation drops
/// the connection and releases PostgreSQL's session lock instead of returning a
/// locked session to the pool.
pub struct CreatorSetupLock {
    connection: PgConnection,
    key: i64,
}

impl CreatorSetupLock {
    /// Releases the advisory lock before closing its dedicated connection.
    pub async fn release(mut self) -> Result<(), PersistenceError> {
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(self.key)
            .execute(&mut self.connection)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(())
    }
}

impl CreatorStore {
    /// Creates a creator repository using a deployment-scoped crypto context.
    pub fn new(pool: &PgPool, crypto: std::sync::Arc<Crypto>) -> Self {
        Self {
            pool: pool.clone(),
            crypto,
        }
    }

    /// Serializes the full setup critical section for one creator. Callers must
    /// hold this lock before loading credentials, publishing a marker, and
    /// committing credentials, then call [`CreatorSetupLock::release`].
    pub async fn acquire_setup_lock(
        &self,
        creator: &CreatorPubky,
    ) -> Result<CreatorSetupLock, PersistenceError> {
        let lookup_hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let key = i64::from_be_bytes(
            lookup_hash.as_bytes()[..8]
                .try_into()
                .expect("lookup hashes are 32 bytes"),
        );
        // A session advisory lock survives returning a connection to the pool.
        // Detach before acquiring it so cancellation closes the connection and
        // PostgreSQL releases the lock.
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| PersistenceError::Unavailable)?
            .detach();
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(key)
            .execute(&mut connection)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(CreatorSetupLock { connection, key })
    }

    /// Inserts a creator and its initial full SDK state atomically.
    pub async fn create(
        &self,
        credentials: &CreatorCredentials,
        state: &StorageState,
    ) -> Result<PersistedCreator, PersistenceError> {
        let lookup_hash = self
            .crypto
            .lookup_hash(credentials.creator().to_string().as_bytes());
        let id = Uuid::new_v4();
        let credentials_bytes = credentials.encode()?;
        let credential_envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::creator_credentials(lookup_hash, id),
                &credentials_bytes,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        let state_envelope =
            crate::persistence::sdk_state::encrypt_state(&self.crypto, lookup_hash, id, state)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query("INSERT INTO creators (id, creator_lookup_hash, credential_envelope) VALUES ($1, $2, $3)")
            .bind(id).bind(lookup_hash.as_bytes().as_slice()).bind(credential_envelope.as_bytes()).execute(&mut *tx).await.map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query("INSERT INTO sdk_states (creator_id, state_envelope) VALUES ($1, $2)")
            .bind(id)
            .bind(state_envelope.as_bytes())
            .execute(&mut *tx)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(PersistedCreator { id, lookup_hash })
    }

    /// Loads and authenticates a creator credential envelope by canonical creator identity.
    pub async fn load(
        &self,
        creator: &CreatorPubky,
    ) -> Result<CreatorCredentials, PersistenceError> {
        let row = self.lookup_row(creator).await?;
        self.decrypt_credentials(&row)
    }

    /// Loads authenticated Creator authority together with its opaque internal
    /// row identity for production SDK adapter composition.
    pub(crate) async fn load_with_id(
        &self,
        creator: &CreatorPubky,
    ) -> Result<(Uuid, CreatorCredentials), PersistenceError> {
        let row = self.lookup_row(creator).await?;
        let id = row.id;
        self.decrypt_credentials(&row)
            .map(|credentials| (id, credentials))
    }

    /// Loads and authenticates one exact internal Creator row for worker composition.
    pub async fn load_by_id(
        &self,
        creator_id: Uuid,
    ) -> Result<CreatorCredentials, PersistenceError> {
        let row = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash, credential_envelope FROM creators WHERE id = $1",
        )
        .bind(creator_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?
        .ok_or(PersistenceError::CorruptOrMissing)?;
        self.decrypt_credentials(&row)
    }

    /// Loads an existing creator when present. A present but unauthenticatable
    /// row is an error rather than an invitation to overwrite it during setup.
    pub async fn load_optional(
        &self,
        creator: &CreatorPubky,
    ) -> Result<Option<CreatorCredentials>, PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        let row = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash, credential_envelope FROM creators WHERE creator_lookup_hash = $1",
        )
        .bind(hash.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        row.map(|row| self.decrypt_credentials(&row)).transpose()
    }

    /// Replaces only the Pubky session secret after proving immutable account identity matches.
    pub async fn reauthenticate(
        &self,
        replacement: &CreatorCredentials,
    ) -> Result<(), PersistenceError> {
        let hash = self
            .crypto
            .lookup_hash(replacement.creator().to_string().as_bytes());
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        let row = sqlx::query_as::<_, CreatorRow>("SELECT id, creator_lookup_hash, credential_envelope FROM creators WHERE creator_lookup_hash = $1 FOR UPDATE")
            .bind(hash.as_bytes().as_slice()).fetch_optional(&mut *tx).await.map_err(|_| PersistenceError::Unavailable)?.ok_or(PersistenceError::CorruptOrMissing)?;
        let existing = self.decrypt_credentials(&row)?;
        if existing.xpub != replacement.xpub || existing.account_index != replacement.account_index
        {
            return Err(PersistenceError::ReauthenticationMismatch);
        }
        let updated = CreatorCredentials::from_secret_parts(
            existing.creator,
            replacement.session_secret.clone(),
            existing.receiver_noise_secret,
            existing.xpub,
            existing.account_index,
        );
        let bytes = updated.encode()?;
        let envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::creator_credentials(row.lookup_hash()?, row.id),
                &bytes,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        sqlx::query(
            "UPDATE creators SET credential_envelope = $1, updated_at = NOW() WHERE id = $2",
        )
        .bind(envelope.as_bytes())
        .bind(row.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit().await.map_err(|_| PersistenceError::Unavailable)
    }

    /// Authenticates every creator authority and SDK-state envelope required at boot.
    pub async fn scan_integrity(&self) -> Result<(), PersistenceError> {
        let rows = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash, credential_envelope FROM creators ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for row in rows {
            self.decrypt_credentials(&row)?;
            crate::persistence::sdk_state::load_state_by_row(&self.pool, &self.crypto, &row)
                .await?;
        }
        Ok(())
    }

    async fn lookup_row(&self, creator: &CreatorPubky) -> Result<CreatorRow, PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        sqlx::query_as("SELECT id, creator_lookup_hash, credential_envelope FROM creators WHERE creator_lookup_hash = $1")
            .bind(hash.as_bytes().as_slice()).fetch_optional(&self.pool).await.map_err(|_| PersistenceError::Unavailable)?.ok_or(PersistenceError::CorruptOrMissing)
    }

    fn decrypt_credentials(
        &self,
        row: &CreatorRow,
    ) -> Result<CreatorCredentials, PersistenceError> {
        let hash = row.lookup_hash()?;
        let plaintext = Zeroizing::new(
            self.crypto
                .decrypt(
                    &EnvelopeContext::creator_credentials(hash, row.id),
                    &EncryptedEnvelope::from_bytes(row.credential_envelope.clone()),
                )
                .map_err(|_| PersistenceError::CorruptOrMissing)?,
        );
        let credentials = CreatorCredentials::decode(&plaintext)?;
        if self
            .crypto
            .lookup_hash(credentials.creator().to_string().as_bytes())
            != hash
        {
            return Err(PersistenceError::CorruptOrMissing);
        }
        Ok(credentials)
    }
}

#[derive(sqlx::FromRow)]
pub(crate) struct CreatorRow {
    pub(crate) id: Uuid,
    pub(crate) creator_lookup_hash: Vec<u8>,
    pub(crate) credential_envelope: Vec<u8>,
}
impl CreatorRow {
    pub(crate) fn lookup_hash(&self) -> Result<LookupHash, PersistenceError> {
        self.creator_lookup_hash
            .as_slice()
            .try_into()
            .map(LookupHash::from_bytes)
            .map_err(|_| PersistenceError::CorruptOrMissing)
    }
}
