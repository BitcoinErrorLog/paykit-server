//! Canonical watch-only key identity: the key tail every claim-time gate keys
//! on, the display fingerprint the claim response returns, and the deny-list
//! of known-public test-vector keys.
//!
//! All identity is derived from the canonical 78-byte BIP32 serialization, so
//! the xpub and zpub encodings of one key collapse to one identity:
//! `Xpub::decode`/`encode` normalizes the version bytes, and the 65-byte tail
//! (bytes 13..78: 32-byte chain code + 33-byte public key) never carries them.
//!
//! The deny-list covers accounts 0..=99 of `m/84'/0'/n'` and `m/84'/1'/n'` of
//! the BIP39 `abandon … about` (x11 + about) mnemonic — the key material every
//! tutorial and every published BIP84 test vector hands out — plus each
//! account's derived first address (belt-and-braces). Nothing here is
//! hand-copied: the table is derived from the mnemonic once per process, and
//! the module tests re-derive every entry from the mnemonic through an
//! independent path and anchor account 0 to the published BIP84 vectors.

use std::{collections::HashSet, sync::LazyLock};

use bitcoin::{
    Network,
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::Secp256k1,
};
use sha2::{Digest, Sha256};

use crate::config::BitcoinNetwork;

/// The BIP39 mnemonic behind every published BIP84 test vector. Public
/// knowledge by definition; it appears here so the deny-list is derived from
/// it rather than hand-copied.
const DENY_LIST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// BIP84 coin types covered by the deny-list: 0 (mainnet) and 1 (testnet).
const DENY_LIST_COIN_TYPES: [u32; 2] = [0, 1];

/// Highest account index the deny-list enumerates, per coin type. The bound
/// is exactly the claimable account range, so every claimable index of the
/// public mnemonic is covered.
pub const DENY_LIST_MAX_ACCOUNT_INDEX: u32 = 99;

/// Highest claimable account index (design B.6 r4): claims accept
/// `0 <= account_index <= 99` under every stack role, and the bound is what
/// keeps the deny-list enumerable at accounts 0–99 of every known-public
/// mnemonic.
pub const MAX_CLAIMABLE_ACCOUNT_INDEX: u32 = DENY_LIST_MAX_ACCOUNT_INDEX;

/// Offset of the chain code inside the 78-byte BIP32 serialization (the
/// 13-byte prefix is version, depth, parent fingerprint, and child number);
/// the 65 bytes from here to the end are the chain code and public key.
const KEY_TAIL_OFFSET: usize = 13;

/// The canonical 65-byte key tail: 32-byte chain code + 33-byte public key,
/// free of version bytes, so every encoding of one key shares it.
pub fn canonical_key_tail(serialized_xpub: &[u8; 78]) -> [u8; 65] {
    serialized_xpub[KEY_TAIL_OFFSET..]
        .try_into()
        .expect("78 - 13 is 65")
}

/// The display fingerprint returned in the claim response: hex of the first 8
/// bytes of SHA-256 over the canonical 78-byte serialization. The client
/// recomputes it locally and refuses to enable Bitcoin on mismatch.
pub fn key_fingerprint(serialized_xpub: &[u8; 78]) -> String {
    let digest = Sha256::digest(serialized_xpub);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether the canonical key material is a known-public test-vector key. The
/// derived first address is checked as belt-and-braces beside the tail.
pub fn is_deny_listed(key_tail: &[u8; 65], first_address: &str) -> bool {
    denied_key_tails().contains(key_tail) || denied_first_addresses().contains(first_address)
}

/// Every deny-listed canonical 65-byte key tail: accounts 0..=99 of
/// `m/84'/0'/n'` and `m/84'/1'/n'` of the public mnemonic.
pub fn denied_key_tails() -> &'static HashSet<[u8; 65]> {
    &deny_list().key_tails
}

/// Every deny-listed first address (`0/0`), derived on the network matching
/// the account's coin type.
pub fn denied_first_addresses() -> &'static HashSet<String> {
    &deny_list().first_addresses
}

struct DenyList {
    key_tails: HashSet<[u8; 65]>,
    first_addresses: HashSet<String>,
}

fn deny_list() -> &'static DenyList {
    static DENY_LIST: LazyLock<DenyList> = LazyLock::new(|| {
        let mut key_tails = HashSet::new();
        let mut first_addresses = HashSet::new();
        for coin_type in DENY_LIST_COIN_TYPES {
            for account_index in 0..=DENY_LIST_MAX_ACCOUNT_INDEX {
                let xpub = deny_list_account_xpub(coin_type, account_index);
                key_tails.insert(canonical_key_tail(&xpub.encode()));
                first_addresses.insert(first_address(&xpub, coin_type, account_index));
            }
        }
        DenyList {
            key_tails,
            first_addresses,
        }
    });
    &DENY_LIST
}

/// Derives one deny-list account xpub: `m/84'/{coin_type}'/{account_index}'`
/// of the public BIP39 `abandon … about` mnemonic. The master key's network
/// only sets the serialization's version bytes (derivation is identical), so
/// coin type 0 derives under a mainnet master and coin type 1 under a testnet
/// master, matching each coin type's conventional encoding. `#[doc(hidden)]`
/// for the integration tests that must present a deny-listed key to the claim
/// path; the mnemonic is public by definition, so this exposes no secret.
#[doc(hidden)]
pub fn deny_list_account_xpub(coin_type: u32, account_index: u32) -> Xpub {
    let secp = Secp256k1::new();
    let master_network = match coin_type {
        0 => Network::Bitcoin,
        _ => Network::Testnet,
    };
    let master = Xpriv::new_master(master_network, &bip39_seed(DENY_LIST_MNEMONIC))
        .expect("a 64-byte BIP39 seed is a valid master key");
    let account = master
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(84).expect("84 is a valid hardened index"),
                ChildNumber::from_hardened_idx(coin_type)
                    .expect("deny-list coin types are valid hardened indices"),
                ChildNumber::from_hardened_idx(account_index)
                    .expect("deny-list account indices are valid hardened indices"),
            ],
        )
        .expect("deny-list derivation paths are valid");
    Xpub::from_priv(&secp, &account)
}

/// The account's first receiving address (`0/0`), encoded on the network the
/// coin type conventionally maps to (0 → mainnet, 1 → testnet).
fn first_address(xpub: &Xpub, coin_type: u32, account_index: u32) -> String {
    let network = match coin_type {
        0 => BitcoinNetwork::Mainnet,
        _ => BitcoinNetwork::Testnet,
    };
    crate::application::create_invoice::derive_bip84_p2wpkh_address(
        &xpub.to_string(),
        account_index,
        &network,
        0,
    )
    .expect("deny-list accounts are depth-3 BIP84 keys")
}

/// BIP39 seed derivation: PBKDF2-HMAC-SHA512 over the mnemonic with salt
/// `"mnemonic"` (empty passphrase), 2048 rounds, one 64-byte output block.
fn bip39_seed(mnemonic: &str) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    type HmacSha512 = Hmac<sha2::Sha512>;
    let mut block = {
        let mut mac =
            HmacSha512::new_from_slice(mnemonic.as_bytes()).expect("HMAC accepts any key length");
        mac.update(b"mnemonic");
        mac.update(&1u32.to_be_bytes());
        mac.finalize().into_bytes()
    };
    let mut previous = block;
    for _ in 1..2048 {
        let mut mac =
            HmacSha512::new_from_slice(mnemonic.as_bytes()).expect("HMAC accepts any key length");
        mac.update(&previous);
        previous = mac.finalize().into_bytes();
        for (accumulated, round) in block.iter_mut().zip(previous.iter()) {
            *accumulated ^= *round;
        }
    }
    block.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::DerivationPath;
    use std::str::FromStr;

    /// Published BIP84 test vectors for the `abandon … about` mnemonic,
    /// account 0 (`m/84'/0'/0'`).
    const BIP84_ACCOUNT_ZERO_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
    const BIP84_ACCOUNT_ZERO_FIRST_ADDRESS: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

    /// The SLIP-132 version-byte rewrite the client performs: zpub → xpub.
    fn zpub_to_xpub_bytes(zpub: &str) -> [u8; 78] {
        let mut bytes: [u8; 78] = bitcoin::base58::decode_check(zpub)
            .expect("published vector is valid base58check")
            .try_into()
            .expect("an extended key serializes to 78 bytes");
        bytes[..4].copy_from_slice(&0x0488B21Eu32.to_be_bytes());
        bytes
    }

    #[test]
    fn bip39_seed_matches_the_reference_pbkdf2_vector() {
        // Reference: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048, 64).
        let expected: [u8; 64] = [
            0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55,
            0x56, 0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6,
            0xf6, 0xda, 0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86,
            0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
            0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4,
        ];
        assert_eq!(bip39_seed(DENY_LIST_MNEMONIC), expected);
    }

    #[test]
    fn every_entry_re_derives_from_the_mnemonic_through_an_independent_path() {
        let seed = bip39_seed(DENY_LIST_MNEMONIC);
        let secp = Secp256k1::new();
        let mut expected_tails = HashSet::new();
        let mut expected_addresses = HashSet::new();
        for coin_type in DENY_LIST_COIN_TYPES {
            let master_network = match coin_type {
                0 => Network::Bitcoin,
                _ => Network::Testnet,
            };
            let master = Xpriv::new_master(master_network, &seed).unwrap();
            for account_index in 0..=DENY_LIST_MAX_ACCOUNT_INDEX {
                let path =
                    DerivationPath::from_str(&format!("m/84'/{coin_type}'/{account_index}'"))
                        .unwrap();
                let account = master.derive_priv(&secp, &path).unwrap();
                let xpub = Xpub::from_priv(&secp, &account);
                expected_tails.insert(canonical_key_tail(&xpub.encode()));
                expected_addresses.insert(first_address(&xpub, coin_type, account_index));
            }
        }
        assert_eq!(expected_tails.len(), 200);
        assert_eq!(expected_addresses.len(), 200);
        assert_eq!(denied_key_tails(), &expected_tails);
        assert_eq!(denied_first_addresses(), &expected_addresses);
    }

    #[test]
    fn account_zero_anchors_to_the_published_bip84_vectors() {
        // The zpub and xpub encodings of the account-0 key are one key: the
        // version-byte rewrite the client performs yields identical 78 bytes,
        // one tail, and one fingerprint.
        let rewritten = zpub_to_xpub_bytes(BIP84_ACCOUNT_ZERO_ZPUB);
        let derived = deny_list_account_xpub(0, 0).encode();
        assert_eq!(rewritten, derived);
        assert!(denied_key_tails().contains(&canonical_key_tail(&rewritten)));
        assert!(
            denied_first_addresses().contains(BIP84_ACCOUNT_ZERO_FIRST_ADDRESS),
            "the published BIP84 first receiving address is deny-listed"
        );
        assert_eq!(
            key_fingerprint(&rewritten),
            key_fingerprint(&derived),
            "xpub and zpub forms of one key share one fingerprint"
        );
    }

    #[test]
    fn the_tail_is_version_byte_independent() {
        let zpub = zpub_to_xpub_bytes(BIP84_ACCOUNT_ZERO_ZPUB);
        let xpub = deny_list_account_xpub(0, 0).encode();
        assert_eq!(canonical_key_tail(&zpub), canonical_key_tail(&xpub));
    }

    #[test]
    fn an_unrelated_key_is_not_deny_listed() {
        let secp = Secp256k1::new();
        let account = Xpriv::new_master(Network::Bitcoin, &[7; 32])
            .unwrap()
            .derive_priv(
                &secp,
                &[
                    ChildNumber::from_hardened_idx(84).unwrap(),
                    ChildNumber::from_hardened_idx(0).unwrap(),
                    ChildNumber::from_hardened_idx(0).unwrap(),
                ],
            )
            .unwrap();
        let xpub = Xpub::from_priv(&secp, &account);
        assert!(!is_deny_listed(
            &canonical_key_tail(&xpub.encode()),
            "bc1qunrelated"
        ));
    }
}
