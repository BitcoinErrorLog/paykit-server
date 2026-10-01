use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

const ENVELOPE_VERSION: u8 = 1;
const PLAINTEXT_VERSION: u8 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const DOMAIN: &[u8] = b"paykit-reader-state-v1";
const MIN_ENVELOPE_LEN: usize = 1 + SALT_LEN + NONCE_LEN + TAG_LEN;
const MAX_STATE_LEN: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StateInvariants {
    pub(super) app_id: String,
    pub(super) server_pubky: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaintextState {
    version: u8,
    app_id: String,
    server_pubky: String,
}

pub(super) struct EncryptedReaderStateStore {
    path: PathBuf,
    reader_secret: Zeroizing<[u8; 32]>,
}

pub(super) struct StateLock {
    _file: File,
}

#[derive(Debug)]
pub(super) enum StateLockError {
    Busy,
    Invalid,
}

impl EncryptedReaderStateStore {
    pub(super) fn new(path: PathBuf, reader_secret: [u8; 32]) -> Self {
        Self {
            path,
            reader_secret: Zeroizing::new(reader_secret),
        }
    }

    pub(super) fn try_lock(&self) -> Result<StateLock, StateLockError> {
        let lock_path = self.path.with_extension("lock");
        let parent = lock_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|_| StateLockError::Invalid)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(lock_path)
            .map_err(|_| StateLockError::Invalid)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| StateLockError::Invalid)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(StateLockError::Busy),
            Err(TryLockError::Error(_)) => return Err(StateLockError::Invalid),
        }
        Ok(StateLock { _file: file })
    }

    pub(super) fn load_optional(&self) -> Result<Option<StateInvariants>, ()> {
        match fs::read(&self.path) {
            Ok(bytes) if bytes.len() <= MAX_STATE_LEN => self.decode(&bytes).map(Some),
            Ok(_) => Err(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(()),
        }
    }

    pub(super) fn save(&self, state: &StateInvariants) -> Result<(), ()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|_| ())?;

        let mut salt = [0_u8; SALT_LEN];
        let mut nonce = [0_u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut salt);
        rand::rng().fill_bytes(&mut nonce);
        let key = derive_key(&self.reader_secret, &salt)?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&PlaintextState {
                version: PLAINTEXT_VERSION,
                app_id: state.app_id.clone(),
                server_pubky: state.server_pubky.clone(),
            })
            .map_err(|_| ())?,
        );
        let ciphertext = XChaCha20Poly1305::new_from_slice(&*key)
            .map_err(|_| ())?
            .encrypt(
                &XNonce::try_from(nonce.as_slice()).map_err(|_| ())?,
                Payload {
                    msg: &plaintext,
                    aad: DOMAIN,
                },
            )
            .map_err(|_| ())?;

        let mut encoded = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ciphertext.len());
        encoded.push(ENVELOPE_VERSION);
        encoded.extend_from_slice(&salt);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        if encoded.len() > MAX_STATE_LEN {
            return Err(());
        }

        let temporary = parent.join(format!(
            ".{}.{}.tmp",
            self.path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("state.v1"),
            uuid::Uuid::new_v4()
        ));
        let result = (|| -> Result<(), ()> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|_| ())?;
            file.write_all(&encoded).map_err(|_| ())?;
            file.sync_all().map_err(|_| ())?;
            drop(file);
            fs::rename(&temporary, &self.path).map_err(|_| ())?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| ())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn decode(&self, encoded: &[u8]) -> Result<StateInvariants, ()> {
        if encoded.len() < MIN_ENVELOPE_LEN || encoded[0] != ENVELOPE_VERSION {
            return Err(());
        }
        let salt = &encoded[1..1 + SALT_LEN];
        let nonce = &encoded[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN];
        let ciphertext = &encoded[1 + SALT_LEN + NONCE_LEN..];
        let key = derive_key(&self.reader_secret, salt)?;
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(&*key)
                .map_err(|_| ())?
                .decrypt(
                    &XNonce::try_from(nonce).map_err(|_| ())?,
                    Payload {
                        msg: ciphertext,
                        aad: DOMAIN,
                    },
                )
                .map_err(|_| ())?,
        );
        let state: PlaintextState = serde_json::from_slice(&plaintext).map_err(|_| ())?;
        if state.version != PLAINTEXT_VERSION {
            return Err(());
        }
        Ok(StateInvariants {
            app_id: state.app_id,
            server_pubky: state.server_pubky,
        })
    }
}

fn derive_key(reader_secret: &[u8; 32], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, ()> {
    let mut key = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), reader_secret)
        .expand(DOMAIN, &mut *key)
        .map_err(|_| ())?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;

    fn path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("paykit-reader-{name}-{}", uuid::Uuid::new_v4()))
    }

    fn state() -> StateInvariants {
        StateInvariants {
            app_id: "reader-demo".into(),
            server_pubky: "pubky-server".into(),
        }
    }

    #[test]
    fn encrypted_json_state_round_trips_with_exact_envelope_and_fresh_salt_nonce() {
        let path = path("round-trip");
        let store = EncryptedReaderStateStore::new(path.clone(), [7; 32]);
        store.save(&state()).unwrap();
        let first = fs::read(&path).unwrap();
        let loaded = store.load_optional().unwrap().unwrap();
        assert_eq!(loaded, state());
        assert_eq!(first[0], 1);
        assert_eq!(first[1..33].len(), SALT_LEN);
        assert_eq!(first[33..57].len(), NONCE_LEN);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        store.save(&state()).unwrap();
        let second = fs::read(&path).unwrap();
        assert_ne!(&first[1..33], &second[1..33], "salt must be fresh");
        assert_ne!(&first[33..57], &second[33..57], "nonce must be fresh");
        let prefix = format!(".{}.", path.file_name().unwrap().to_string_lossy());
        assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|entry| {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            name.starts_with(&prefix) && name.ends_with(".tmp")
        }));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn encrypted_state_fails_closed_for_wrong_key_corruption_and_versions() {
        let path = path("fail-closed");
        EncryptedReaderStateStore::new(path.clone(), [7; 32])
            .save(&state())
            .unwrap();
        assert!(
            EncryptedReaderStateStore::new(path.clone(), [8; 32])
                .load_optional()
                .is_err()
        );
        let original = fs::read(&path).unwrap();
        let mut corrupt = original.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(&path, corrupt).unwrap();
        assert!(
            EncryptedReaderStateStore::new(path.clone(), [7; 32])
                .load_optional()
                .is_err()
        );
        let mut wrong_version = original;
        wrong_version[0] = 2;
        fs::write(&path, wrong_version).unwrap();
        assert!(
            EncryptedReaderStateStore::new(path.clone(), [7; 32])
                .load_optional()
                .is_err()
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn state_lock_excludes_a_second_store_for_the_complete_operation() {
        let path = path("exclusive-lock");
        let first = EncryptedReaderStateStore::new(path.clone(), [7; 32]);
        let second = EncryptedReaderStateStore::new(path.clone(), [7; 32]);

        let first_lock = first.try_lock().unwrap();
        assert!(second.try_lock().is_err());
        drop(first_lock);
        assert!(second.try_lock().is_ok());

        fs::remove_file(path.with_extension("lock")).unwrap();
    }
}
