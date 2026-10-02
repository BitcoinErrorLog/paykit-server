//! Encrypted creator authority persistence.

use std::fmt;

use paykit_sdk::PaykitIdentitySecretKey;
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
    paykit_identity_secret: PaykitIdentitySecretKey,
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
        paykit_identity_secret: PaykitIdentitySecretKey,
        xpub: String,
        account_index: u32,
    ) -> Self {
        Self::from_secret_parts(
            creator,
            Zeroizing::new(session_secret),
            paykit_identity_secret,
            Zeroizing::new(xpub),
            account_index,
        )
    }

    fn from_secret_parts(
        creator: CreatorPubky,
        session_secret: Zeroizing<String>,
        paykit_identity_secret: PaykitIdentitySecretKey,
        xpub: Zeroizing<String>,
        account_index: u32,
    ) -> Self {
        Self {
            creator,
            session_secret,
            paykit_identity_secret,
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
    /// Borrows the delegated identity-wide Paykit secret.
    pub fn paykit_identity_secret(&self) -> &PaykitIdentitySecretKey {
        &self.paykit_identity_secret
    }
    /// Borrows the exact persisted account xpub.
    pub fn xpub(&self) -> &str {
        self.xpub.as_str()
    }
    /// Returns the immutable account index.
    pub fn account_index(&self) -> u32 {
        self.account_index
    }

    /// Rejects account changes, key rollback, and key substitution within a generation.
    pub fn validate_reauthentication(&self, replacement: &Self) -> Result<(), PersistenceError> {
        let current = &self.paykit_identity_secret;
        let next = &replacement.paykit_identity_secret;
        if self.creator != replacement.creator
            || self.xpub != replacement.xpub
            || self.account_index != replacement.account_index
            || next.key_generation() < current.key_generation()
            || (next.key_generation() == current.key_generation() && next != current)
        {
            return Err(PersistenceError::ReauthenticationMismatch);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, PersistenceError> {
        let creator = self.creator.to_string();
        let wire = CreatorCredentialsV1Ref {
            version: 1,
            creator: &creator,
            session_secret: self.session_secret.as_str(),
            paykit_identity_secret: self.paykit_identity_secret.as_bytes(),
            key_generation: self.paykit_identity_secret.key_generation(),
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
            PaykitIdentitySecretKey::new(*wire.paykit_identity_secret, wire.key_generation)
                .map_err(|_| PersistenceError::CorruptOrMissing)?,
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
    paykit_identity_secret: &'a [u8; 32],
    key_generation: u64,
    xpub: &'a str,
    account_index: u32,
}

#[derive(Deserialize)]
struct CreatorCredentialsV1 {
    version: u8,
    creator: String,
    session_secret: Zeroizing<String>,
    paykit_identity_secret: Zeroizing<[u8; 32]>,
    key_generation: u64,
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

/// Encrypted creator authority repository.
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
    /// hold this lock before loading credentials, publishing the Paykit App, and
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

    /// Inserts encrypted creator credentials before app publication.
    pub async fn create(
        &self,
        credentials: &CreatorCredentials,
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
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        sqlx::query("INSERT INTO creators (id, creator_lookup_hash, credential_envelope) VALUES ($1, $2, $3)")
            .bind(id).bind(lookup_hash.as_bytes().as_slice()).bind(credential_envelope.as_bytes()).execute(&mut *tx).await.map_err(|_| PersistenceError::Unavailable)?;
        tx.commit()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(PersistedCreator { id, lookup_hash })
    }

    /// Lists configured creators for durable SDK transport maintenance after restart.
    pub async fn ready_ids(&self) -> Result<Vec<Uuid>, PersistenceError> {
        sqlx::query_scalar("SELECT id FROM creators WHERE setup_complete ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .map_err(|_| PersistenceError::Unavailable)
    }

    /// Marks setup ready only after credentials and shared app publication succeed.
    pub async fn mark_setup_complete(
        &self,
        creator: &CreatorPubky,
    ) -> Result<(), PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        sqlx::query("UPDATE creators SET setup_complete = TRUE WHERE creator_lookup_hash = $1")
            .bind(hash.as_bytes().as_slice())
            .execute(&self.pool)
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(())
    }

    /// Reports whether setup finished app publication.
    pub async fn setup_complete(&self, creator: &CreatorPubky) -> Result<bool, PersistenceError> {
        let hash = self.crypto.lookup_hash(creator.to_string().as_bytes());
        sqlx::query_scalar("SELECT setup_complete FROM creators WHERE creator_lookup_hash = $1")
            .bind(hash.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| PersistenceError::Unavailable)
            .map(|value| value.unwrap_or(false))
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

    /// Replaces credentials after validating immutable account identity and key monotonicity.
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
        existing.validate_reauthentication(replacement)?;
        let bytes = replacement.encode()?;
        let envelope = self
            .crypto
            .encrypt(
                &EnvelopeContext::creator_credentials(row.lookup_hash()?, row.id),
                &bytes,
            )
            .map_err(|_| PersistenceError::CorruptOrMissing)?;
        sqlx::query(
            "UPDATE creators SET credential_envelope = $1, setup_complete = FALSE, updated_at = NOW() WHERE id = $2",
        )
        .bind(envelope.as_bytes())
        .bind(row.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        tx.commit().await.map_err(|_| PersistenceError::Unavailable)
    }

    /// Authenticates every creator authority envelope required at boot.
    pub async fn scan_integrity(&self) -> Result<(), PersistenceError> {
        let rows = sqlx::query_as::<_, CreatorRow>(
            "SELECT id, creator_lookup_hash, credential_envelope FROM creators ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| PersistenceError::Unavailable)?;
        for row in rows {
            self.decrypt_credentials(&row)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials(secret: u8, generation: u64) -> CreatorCredentials {
        CreatorCredentials::new(
            parse_creator("pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy").unwrap(),
            "session".into(),
            PaykitIdentitySecretKey::new([secret; 32], generation).unwrap(),
            "account".into(),
            7,
        )
    }

    #[test]
    fn encrypted_credentials_plaintext_round_trips_key_and_generation() {
        let expected = credentials(9, 3);
        let decoded = CreatorCredentials::decode(&expected.encode().unwrap()).unwrap();
        assert_eq!(
            decoded.paykit_identity_secret(),
            expected.paykit_identity_secret()
        );
        assert_eq!(decoded.account_index(), 7);
        assert_eq!(decoded.xpub(), "account");
        assert_eq!(format!("{decoded:?}"), "CreatorCredentials(<redacted>)");
    }

    #[test]
    fn reauthentication_preserves_account_and_rejects_key_rollback_or_substitution() {
        let current = credentials(9, 3);
        assert!(
            current
                .validate_reauthentication(&credentials(9, 3))
                .is_ok()
        );
        assert!(
            current
                .validate_reauthentication(&credentials(8, 5))
                .is_ok()
        );
        for replacement in [credentials(9, 2), credentials(8, 3)] {
            assert_eq!(
                current.validate_reauthentication(&replacement),
                Err(PersistenceError::ReauthenticationMismatch)
            );
        }
        let mut replacement = credentials(8, 4);
        replacement.account_index = 8;
        assert!(current.validate_reauthentication(&replacement).is_err());
        replacement.account_index = 7;
        replacement.xpub = Zeroizing::new("different".into());
        assert!(current.validate_reauthentication(&replacement).is_err());
    }
}
