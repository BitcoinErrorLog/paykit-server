//! Closed, versioned semantic inputs used to replay a durable Paykit handoff.
//!
//! These values are the complete inputs to public Paykit SDK enqueue/proposal
//! methods. They deliberately do not contain SDK-generated event, request, wire,
//! or outbound-message identifiers.

use std::fmt;

use paykit_lib::{
    PaykitReceiverMarker, PaykitReceiverPath, PaymentAmount, PaymentEndpointIdentifier,
    PaymentEndpointPayload, PaymentReference, PaymentRequestTerms,
    serialize_paykit_receiver_marker,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Server-owned delivery intent stored inside the Creator-bound outbox AEAD envelope.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveryIntentV1 {
    version: u8,
    reader_pubky: String,
    selected_reader_path: String,
    marker_fingerprint: [u8; 32],
    local_receiver_path: String,
    operation: DeliveryOperationV1,
}

/// Exactly one supported public-SDK operation and all of its caller inputs.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum DeliveryOperationV1 {
    EndpointPublication {
        receiving_details: Vec<ReceivingDetailV1>,
    },
    PaymentRequestProposal {
        terms: PaymentTermsV1,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceivingDetailV1 {
    pub identifier: String,
    pub payload: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PaymentTermsV1 {
    pub amount: String,
    pub asset: String,
    pub payment_reference: String,
    pub proposal_expires_at: Option<String>,
    pub accepted_endpoint_identifiers: Vec<String>,
    #[serde(with = "json_map_as_string")]
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

mod json_map_as_string {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_json::{Map, Value};

    pub fn serialize<S>(value: &Map<String, Value>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_json::to_string(value)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Map<String, Value>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        serde_json::from_str(&encoded).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DeliveryIntentError {
    #[error("could not canonicalize receiver marker")]
    Marker,
    #[error("stored delivery intent contains an invalid canonical value")]
    Invalid,
}

impl DeliveryIntentV1 {
    pub fn fingerprint(marker: &PaykitReceiverMarker) -> Result<[u8; 32], DeliveryIntentError> {
        let canonical =
            serialize_paykit_receiver_marker(marker).map_err(|_| DeliveryIntentError::Marker)?;
        Ok(*blake3::hash(canonical.as_bytes()).as_bytes())
    }

    pub fn endpoint(
        reader_pubky: String,
        marker: &PaykitReceiverMarker,
        local_receiver_path: PaykitReceiverPath,
        receiving_details: Vec<(PaymentEndpointIdentifier, PaymentEndpointPayload)>,
    ) -> Result<Self, DeliveryIntentError> {
        if receiving_details.is_empty()
            || receiving_details
                .iter()
                .any(|(_, payload)| payload.as_str().is_empty())
        {
            return Err(DeliveryIntentError::Invalid);
        }
        let intent = Self {
            version: 2,
            reader_pubky,
            selected_reader_path: marker.receiver_path.as_str().into(),
            marker_fingerprint: Self::fingerprint(marker)?,
            local_receiver_path: local_receiver_path.as_str().into(),
            operation: DeliveryOperationV1::EndpointPublication {
                receiving_details: receiving_details
                    .into_iter()
                    .map(|(identifier, payload)| ReceivingDetailV1 {
                        identifier: identifier.to_string(),
                        payload: payload.into_inner(),
                    })
                    .collect(),
            },
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn payment_request(
        reader_pubky: String,
        marker: &PaykitReceiverMarker,
        local_receiver_path: PaykitReceiverPath,
        terms: &PaymentRequestTerms,
    ) -> Result<Self, DeliveryIntentError> {
        if terms.recurrence.is_some() {
            return Err(DeliveryIntentError::Invalid);
        }
        let intent = Self {
            version: 2,
            reader_pubky,
            selected_reader_path: marker.receiver_path.as_str().into(),
            marker_fingerprint: Self::fingerprint(marker)?,
            local_receiver_path: local_receiver_path.as_str().into(),
            operation: DeliveryOperationV1::PaymentRequestProposal {
                terms: PaymentTermsV1 {
                    amount: terms.amount.value.clone(),
                    asset: terms.amount.asset.clone(),
                    payment_reference: terms.payment_reference.to_string(),
                    proposal_expires_at: terms.proposal_expires_at.clone(),
                    accepted_endpoint_identifiers: terms
                        .accepted_payment_endpoint_identifiers
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                    metadata: terms.metadata.clone(),
                },
            },
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    /// Decodes and revalidates the one supported persisted representation.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeliveryIntentError> {
        let intent: Self = postcard::from_bytes(bytes).map_err(|_| DeliveryIntentError::Invalid)?;
        intent.validate()?;
        Ok(intent)
    }

    /// Revalidates every canonical value after authenticated deserialization.
    pub fn validate(&self) -> Result<(), DeliveryIntentError> {
        if self.version != 2
            || crate::domain::locks::parse_reader(&self.reader_pubky).is_err()
            || PaykitReceiverPath::new(self.selected_reader_path.clone()).is_err()
            || PaykitReceiverPath::new(self.local_receiver_path.clone()).is_err()
        {
            return Err(DeliveryIntentError::Invalid);
        }
        match &self.operation {
            DeliveryOperationV1::EndpointPublication { receiving_details } => {
                if receiving_details.is_empty()
                    || receiving_details.iter().any(|detail| {
                        detail.payload.is_empty()
                            || PaymentEndpointIdentifier::new(detail.identifier.clone()).is_err()
                    })
                {
                    return Err(DeliveryIntentError::Invalid);
                }
            }
            DeliveryOperationV1::PaymentRequestProposal { terms } => {
                if PaymentReference::new(terms.payment_reference.clone()).is_err()
                    || PaymentAmount::new(terms.amount.clone(), terms.asset.clone()).is_err()
                    || terms.accepted_endpoint_identifiers.is_empty()
                    || terms
                        .accepted_endpoint_identifiers
                        .iter()
                        .any(|identifier| {
                            PaymentEndpointIdentifier::new(identifier.clone()).is_err()
                        })
                {
                    return Err(DeliveryIntentError::Invalid);
                }
                let reference = uuid::Uuid::parse_str(&terms.payment_reference)
                    .map_err(|_| DeliveryIntentError::Invalid)?;
                if reference.get_version_num() != 4
                    || reference.get_variant() != uuid::Variant::RFC4122
                    || terms.payment_reference != reference.hyphenated().to_string()
                {
                    return Err(DeliveryIntentError::Invalid);
                }
                // §B.9: the proposal expiry is carried so the buyer's wallet
                // enforces it; when present it must be a well-formed RFC3339
                // timestamp (freshness is a creation-time check, not a
                // decode-time one — a replayed intent must still validate
                // after the moment has passed).
                if let Some(expires_at) = &terms.proposal_expires_at {
                    time::OffsetDateTime::parse(
                        expires_at,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .map_err(|_| DeliveryIntentError::Invalid)?;
                }
            }
        }
        Ok(())
    }

    pub fn reader_pubky(&self) -> &str {
        &self.reader_pubky
    }

    pub fn selected_reader_path(&self) -> Result<PaykitReceiverPath, DeliveryIntentError> {
        PaykitReceiverPath::new(self.selected_reader_path.clone())
            .map_err(|_| DeliveryIntentError::Invalid)
    }

    pub fn marker_fingerprint(&self) -> [u8; 32] {
        self.marker_fingerprint
    }

    pub fn local_receiver_path(&self) -> Result<PaykitReceiverPath, DeliveryIntentError> {
        PaykitReceiverPath::new(self.local_receiver_path.clone())
            .map_err(|_| DeliveryIntentError::Invalid)
    }

    pub fn operation(&self) -> &DeliveryOperationV1 {
        &self.operation
    }
}

impl fmt::Debug for DeliveryIntentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryIntentV1")
            .field("version", &self.version)
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DeliveryOperationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EndpointPublication { .. } => "EndpointPublication { .. }",
            Self::PaymentRequestProposal { .. } => "PaymentRequestProposal { .. }",
        })
    }
}

impl fmt::Debug for ReceivingDetailV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReceivingDetailV1 { .. }")
    }
}

impl fmt::Debug for PaymentTermsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PaymentTermsV1 { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_but_invalid_stored_paths_fail_without_panicking() {
        let intent = DeliveryIntentV1 {
            version: 2,
            reader_pubky: "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy".into(),
            selected_reader_path: "../invalid".into(),
            marker_fingerprint: [0; 32],
            local_receiver_path: "paykit/server".into(),
            operation: DeliveryOperationV1::EndpointPublication {
                receiving_details: vec![ReceivingDetailV1 {
                    identifier: "btc-bitcoin-p2wpkh".into(),
                    payload: "address-secret".into(),
                }],
            },
        };

        assert_eq!(intent.validate(), Err(DeliveryIntentError::Invalid));
        assert_eq!(
            intent.selected_reader_path(),
            Err(DeliveryIntentError::Invalid)
        );
    }

    #[test]
    fn debug_formatting_redacts_encrypted_business_values() {
        let intent = DeliveryIntentV1 {
            version: 2,
            reader_pubky: "reader-secret".into(),
            selected_reader_path: "bitkit/wallet".into(),
            marker_fingerprint: [0; 32],
            local_receiver_path: "paykit/server".into(),
            operation: DeliveryOperationV1::EndpointPublication {
                receiving_details: vec![ReceivingDetailV1 {
                    identifier: "btc-bitcoin-p2wpkh".into(),
                    payload: "address-secret".into(),
                }],
            },
        };
        let rendered = format!("{intent:?}");

        assert!(!rendered.contains("reader-secret"));
        assert!(!rendered.contains("address-secret"));
        assert!(!rendered.contains("bitkit/wallet"));
    }

    #[test]
    fn payment_request_metadata_round_trips_through_postcard() {
        let metadata = serde_json::Map::from_iter([
            ("bundle_id".into(), serde_json::json!("bundle-secret")),
            (
                "nested".into(),
                serde_json::json!({"reader": "reader-secret"}),
            ),
        ]);
        let intent = DeliveryIntentV1 {
            version: 2,
            reader_pubky: "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy".into(),
            selected_reader_path: "bitkit/wallet".into(),
            marker_fingerprint: [9; 32],
            local_receiver_path: "paykit/server".into(),
            operation: DeliveryOperationV1::PaymentRequestProposal {
                terms: PaymentTermsV1 {
                    amount: "0.00000100".into(),
                    asset: "BTC".into(),
                    payment_reference: "550e8400-e29b-41d4-a716-446655440000".into(),
                    proposal_expires_at: None,
                    accepted_endpoint_identifiers: vec!["btc-bitcoin-p2wpkh".into()],
                    metadata: metadata.clone(),
                },
            },
        };

        let decoded = DeliveryIntentV1::decode(&postcard::to_allocvec(&intent).unwrap()).unwrap();
        assert_eq!(decoded, intent);
    }

    #[test]
    fn unsupported_persisted_intent_version_is_rejected() {
        let intent = DeliveryIntentV1 {
            version: 1,
            reader_pubky: "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy".into(),
            selected_reader_path: "bitkit/wallet".into(),
            marker_fingerprint: [3; 32],
            local_receiver_path: "paykit/server".into(),
            operation: DeliveryOperationV1::EndpointPublication {
                receiving_details: vec![ReceivingDetailV1 {
                    identifier: "btc-bitcoin-p2wpkh".into(),
                    payload: "address-secret".into(),
                }],
            },
        };

        assert_eq!(
            DeliveryIntentV1::decode(&postcard::to_allocvec(&intent).unwrap()),
            Err(DeliveryIntentError::Invalid)
        );
    }
}
