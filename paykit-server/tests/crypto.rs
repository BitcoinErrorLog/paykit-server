use paykit_server::{
    crypto::{Crypto, CryptoError, EncryptedEnvelope, EnvelopeContext},
    domain::locks::{CreatorPubky, parse_creator},
};
use uuid::Uuid;

const CREATOR: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

fn creator() -> CreatorPubky {
    parse_creator(CREATOR).expect("valid canonical creator fixture")
}

fn another_creator() -> CreatorPubky {
    for replacement in "ybndrfg8ejkmcpqxot1uwisza345h769".chars() {
        let mut candidate = CREATOR.to_owned();
        candidate.replace_range(5..6, &replacement.to_string());
        if let Ok(creator) = parse_creator(&candidate)
            && creator.to_string() != CREATOR
        {
            return creator;
        }
    }

    panic!("the canonical identifier provider did not yield a second valid fixture");
}

fn master_key() -> &'static [u8; 32] {
    b"MASTER_KEY_SENTINEL_012345678901"
}

#[test]
fn payment_drain_cleanup_tokens_are_stable_distinct_and_redacted() {
    let crypto = Crypto::from_master_key(master_key()).expect("valid master key");
    let drain = Uuid::new_v4();
    let first = crypto.payment_drain_cleanup_token(drain);
    let replay = crypto.payment_drain_cleanup_token(drain);
    let another = crypto.payment_drain_cleanup_token(Uuid::new_v4());

    assert_eq!(first, replay);
    assert_ne!(first, another);
    assert_ne!(first, crypto.lookup_hash(drain.as_bytes()));
    assert_eq!(format!("{first:?}"), "LookupHash(<redacted>)");
}

#[test]
fn creator_envelope_round_trips_with_the_persistent_binary_layout() {
    let crypto = Crypto::from_master_key(master_key()).expect("valid master key");
    let context = EnvelopeContext::creator_credentials(
        crypto.lookup_hash(creator().to_string().as_bytes()),
        Uuid::new_v4(),
    );
    let plaintext = b"credential-sentinel xpub-sentinel address-sentinel";

    let envelope = crypto.encrypt(&context, plaintext).expect("encrypts");
    let stored = envelope.as_bytes();

    assert_eq!(stored[0], 1);
    assert_eq!(stored.len(), 1 + 24 + plaintext.len() + 16);
    assert_eq!(
        crypto.decrypt(&context, &envelope).expect("decrypts"),
        plaintext
    );
}

#[test]
fn decrypt_rejects_context_swaps_wrong_key_and_malformed_envelopes() {
    let crypto = Crypto::from_master_key(master_key()).expect("valid master key");
    let creator = creator();
    let row = Uuid::new_v4();
    let lookup_hash = crypto.lookup_hash(creator.to_string().as_bytes());
    let context = EnvelopeContext::creator_credentials(lookup_hash, row);
    let envelope = crypto
        .encrypt(&context, b"credential-sentinel")
        .expect("encrypts");

    let swapped_row = EnvelopeContext::creator_credentials(lookup_hash, Uuid::new_v4());
    let swapped_type = EnvelopeContext::sdk_state(lookup_hash, row);
    let swapped_lookup_hash = EnvelopeContext::creator_credentials(
        crypto.lookup_hash(another_creator().to_string().as_bytes()),
        row,
    );
    let wrong_crypto = Crypto::from_master_key(b"ANOTHER_MASTER_KEY_SENTINEL_0123")
        .expect("valid other master key");

    for rejected in [
        crypto.decrypt(&swapped_row, &envelope),
        crypto.decrypt(&swapped_type, &envelope),
        crypto.decrypt(&swapped_lookup_hash, &envelope),
        wrong_crypto.decrypt(&context, &envelope),
    ] {
        assert!(matches!(rejected, Err(CryptoError::AuthenticationFailed)));
    }

    for malformed in [vec![], vec![1], vec![2; 1 + 24 + 16 - 1]] {
        let envelope = EncryptedEnvelope::from_bytes(malformed);
        assert!(matches!(
            crypto.decrypt(&context, &envelope),
            Err(CryptoError::InvalidEnvelope)
        ));
    }

    let wrong_version = EncryptedEnvelope::from_bytes(vec![2; 1 + 24 + 16]);
    assert!(matches!(
        crypto.decrypt(&context, &wrong_version),
        Err(CryptoError::InvalidEnvelope)
    ));
}

#[test]
fn bitcoin_observation_envelope_is_bound_to_its_invoice() {
    let crypto = Crypto::from_master_key(master_key()).expect("valid master key");
    let creator_hash = crypto.lookup_hash(creator().to_string().as_bytes());
    let observation_id = Uuid::new_v4();
    let first_invoice_id = Uuid::new_v4();
    let context = EnvelopeContext::bitcoin_observation_for_invoice(
        creator_hash,
        observation_id,
        first_invoice_id,
    );
    let envelope = crypto.encrypt(&context, b"observation").unwrap();

    assert_eq!(crypto.decrypt(&context, &envelope).unwrap(), b"observation");
    assert_eq!(
        crypto.decrypt(
            &EnvelopeContext::bitcoin_observation_for_invoice(
                creator_hash,
                observation_id,
                Uuid::new_v4(),
            ),
            &envelope,
        ),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn encryption_uses_fresh_nonces_for_identical_values_and_contexts() {
    let crypto = Crypto::from_master_key(master_key()).expect("valid master key");
    let context = EnvelopeContext::creator_credentials(
        crypto.lookup_hash(creator().to_string().as_bytes()),
        Uuid::new_v4(),
    );
    let plaintext = b"credential-sentinel";

    let first = crypto
        .encrypt(&context, plaintext)
        .expect("first encryption");
    let second = crypto
        .encrypt(&context, plaintext)
        .expect("second encryption");

    assert_ne!(first.as_bytes(), second.as_bytes());
    assert_ne!(&first.as_bytes()[1..25], &second.as_bytes()[1..25]);
    assert_eq!(
        crypto.decrypt(&context, &first).expect("first decrypts"),
        plaintext
    );
    assert_eq!(
        crypto.decrypt(&context, &second).expect("second decrypts"),
        plaintext
    );
}

#[test]
fn supported_persistence_envelopes_bind_distinct_typed_contexts() {
    let crypto = Crypto::from_master_key(master_key()).expect("valid master key");
    let hash = crypto.lookup_hash(creator().to_string().as_bytes());
    let row = Uuid::new_v4();
    let contexts = [
        EnvelopeContext::reader_assignment(hash, row),
        EnvelopeContext::invoice(hash, row),
        EnvelopeContext::outbox_semantic_intent(hash, row),
    ];
    for (index, context) in contexts.iter().enumerate() {
        let envelope = crypto.encrypt(context, b"task-seven-sentinel").unwrap();
        assert_eq!(
            crypto.decrypt(context, &envelope).unwrap(),
            b"task-seven-sentinel"
        );
        assert!(matches!(
            crypto.decrypt(&contexts[(index + 1) % contexts.len()], &envelope),
            Err(CryptoError::AuthenticationFailed)
        ));
        assert!(!format!("{context:?} {envelope:?}").contains("task-seven-sentinel"));
    }
}

#[test]
fn keyed_lookup_hashes_are_deterministic_keyed_and_exactly_32_bytes() {
    let crypto = Crypto::from_master_key(master_key()).expect("valid master key");
    let different_crypto = Crypto::from_master_key(b"ANOTHER_MASTER_KEY_SENTINEL_0123")
        .expect("valid other master key");

    let first = crypto.lookup_hash(b"lookup-sentinel");
    let same = crypto.lookup_hash(b"lookup-sentinel");
    let different_input = crypto.lookup_hash(b"another-lookup-sentinel");
    let different_key = different_crypto.lookup_hash(b"lookup-sentinel");

    assert_eq!(first.as_bytes().len(), 32);
    assert_eq!(first.as_bytes(), same.as_bytes());
    assert_ne!(first.as_bytes(), different_input.as_bytes());
    assert_ne!(first.as_bytes(), different_key.as_bytes());
}

#[test]
fn bitcoin_lookup_hashes_are_domain_separated() {
    let crypto = Crypto::from_master_key(master_key()).expect("valid master key");
    let value = b"same-sensitive-value";

    let generic = crypto.lookup_hash(value);
    let address = crypto.bitcoin_address_lookup_hash(value);
    let outpoint = crypto.bitcoin_outpoint_lookup_hash(value);
    let first_creator = crypto.lookup_hash(b"creator-one");
    let second_creator = crypto.lookup_hash(b"creator-two");
    let index = crypto.bitcoin_derivation_index_lookup_hash(first_creator, 7);
    let other_crypto = Crypto::from_master_key(&[9; 32]).expect("valid second master key");
    let other_creator = other_crypto.lookup_hash(b"creator-one");

    assert_ne!(generic, address);
    assert_ne!(generic, outpoint);
    assert_ne!(address, outpoint);
    assert_ne!(index, address);
    assert_ne!(index, outpoint);
    assert_ne!(
        index,
        crypto.bitcoin_derivation_index_lookup_hash(first_creator, 8)
    );
    assert_ne!(
        index,
        crypto.bitcoin_derivation_index_lookup_hash(second_creator, 7)
    );
    assert_ne!(address, other_crypto.bitcoin_address_lookup_hash(value));
    assert_ne!(outpoint, other_crypto.bitcoin_outpoint_lookup_hash(value));
    assert_ne!(
        index,
        other_crypto.bitcoin_derivation_index_lookup_hash(other_creator, 7)
    );
    assert_eq!(address, crypto.bitcoin_address_lookup_hash(value));
    assert_eq!(outpoint, crypto.bitcoin_outpoint_lookup_hash(value));
    assert_eq!(
        index,
        crypto.bitcoin_derivation_index_lookup_hash(first_creator, 7)
    );
}

#[test]
fn crypto_values_and_errors_redact_sensitive_material() {
    let crypto = Crypto::from_master_key(master_key()).expect("valid master key");
    let context = EnvelopeContext::creator_credentials(
        crypto.lookup_hash(creator().to_string().as_bytes()),
        Uuid::new_v4(),
    );
    let envelope = crypto
        .encrypt(
            &context,
            b"credential-sentinel xpub-sentinel address-sentinel",
        )
        .expect("encrypts");
    let lookup = crypto.lookup_hash(b"lookup-sentinel");
    let error = crypto
        .decrypt(&context, &EncryptedEnvelope::from_bytes(vec![]))
        .expect_err("empty envelope is invalid");

    let rendered = format!("{crypto:?} {context:?} {envelope:?} {lookup:?} {error:?} {error}");
    for secret in [
        "credential-sentinel",
        "xpub-sentinel",
        "address-sentinel",
        CREATOR,
        "MASTER_KEY_SENTINEL_012345678901",
        "lookup-sentinel",
    ] {
        assert!(
            !rendered.contains(secret),
            "rendered sensitive value: {secret}"
        );
    }
}
