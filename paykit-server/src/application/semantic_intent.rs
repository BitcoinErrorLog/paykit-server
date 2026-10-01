//! Closed, versioned semantic inputs used to replay a durable Paykit handoff.
//!
//! These values are the complete inputs to public Paykit SDK enqueue/proposal
//! methods. They deliberately do not contain SDK-generated event, request, wire,
//! or outbound-message identifiers.

use std::{collections::BTreeMap, fmt};

use paykit_lib::{
    PaykitAppId, PaymentAmount, PaymentEndpointIdentifier, PaymentReference, PaymentRequestTerms,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Server-owned delivery intent stored inside the Creator-bound outbox AEAD envelope.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveryIntentV1 {
    version: u8,
    reader_pubky: String,
    app_id: String,
    terms: PaymentTermsV1,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PaymentTermsV1 {
    pub amount: String,
    pub asset: String,
    pub payment_reference: String,
    pub proposal_expires_at: Option<String>,
    pub accepted_endpoint_identifiers: Vec<String>,
    pub payment_endpoints: BTreeMap<String, String>,
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
    #[error("stored delivery intent contains an invalid canonical value")]
    Invalid,
}

impl DeliveryIntentV1 {
    pub fn payment_request(
        reader_pubky: String,
        app_id: PaykitAppId,
        terms: &PaymentRequestTerms,
    ) -> Result<Self, DeliveryIntentError> {
        if terms.recurrence().is_some()
            || terms.conversion().is_some()
            || terms.payment_deadline().is_some()
            || terms.required_app_id() != Some(&app_id)
        {
            return Err(DeliveryIntentError::Invalid);
        }
        let intent = Self {
            version: 1,
            reader_pubky,
            app_id: app_id.as_str().into(),
            terms: PaymentTermsV1 {
                amount: terms.amount().value().to_owned(),
                asset: terms.amount().asset().to_owned(),
                payment_reference: terms.payment_reference().to_string(),
                proposal_expires_at: terms.proposal_expires_at().clone(),
                accepted_endpoint_identifiers: terms
                    .accepted_payment_endpoint_identifiers()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                payment_endpoints: terms
                    .payment_endpoints()
                    .ok_or(DeliveryIntentError::Invalid)?
                    .iter()
                    .map(|(identifier, payload)| {
                        (identifier.to_string(), payload.as_str().to_owned())
                    })
                    .collect(),
                metadata: terms.metadata().clone(),
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
        if self.version != 1
            || crate::domain::locks::parse_reader(&self.reader_pubky).is_err()
            || self.app_id != crate::config::PAYKIT_APP_ID
        {
            return Err(DeliveryIntentError::Invalid);
        }
        let terms = &self.terms;
        if PaymentReference::new(terms.payment_reference.clone()).is_err()
            || PaymentAmount::new(terms.amount.clone(), terms.asset.clone()).is_err()
            || terms.accepted_endpoint_identifiers.is_empty()
            || terms.payment_endpoints.is_empty()
            || terms.payment_endpoints.iter().any(|(identifier, payload)| {
                payload.is_empty()
                    || !terms.accepted_endpoint_identifiers.contains(identifier)
                    || PaymentEndpointIdentifier::new(identifier.clone()).is_err()
            })
            || terms
                .accepted_endpoint_identifiers
                .iter()
                .any(|identifier| PaymentEndpointIdentifier::new(identifier.clone()).is_err())
        {
            return Err(DeliveryIntentError::Invalid);
        }
        let reference = uuid::Uuid::parse_str(&terms.payment_reference)
            .map_err(|_| DeliveryIntentError::Invalid)?;
        if reference.get_version_num() != 4
            || reference.get_variant() != uuid::Variant::RFC4122
            || terms.payment_reference != reference.hyphenated().to_string()
            || terms.proposal_expires_at.is_some()
        {
            return Err(DeliveryIntentError::Invalid);
        }
        Ok(())
    }

    pub fn reader_pubky(&self) -> &str {
        &self.reader_pubky
    }

    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    pub fn terms(&self) -> &PaymentTermsV1 {
        &self.terms
    }
}

impl fmt::Debug for DeliveryIntentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryIntentV1")
            .field("version", &self.version)
            .field("terms", &self.terms)
            .finish_non_exhaustive()
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
    use paykit_lib::PaymentEndpointPayload;
    use std::collections::HashMap;
    const READER: &str = "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy";

    #[test]
    fn bound_payment_request_round_trips_without_exposing_private_terms() {
        let app_id = PaykitAppId::new(crate::config::PAYKIT_APP_ID).unwrap();
        let terms = PaymentRequestTerms::builder(
            PaymentAmount::new("0.00000100", "btc").unwrap(),
            PaymentReference::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            vec![PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap()],
        )
        .required_app_id(Some(app_id.clone()))
        .payment_endpoints(Some(HashMap::from([(
            PaymentEndpointIdentifier::new("btc-bitcoin-p2wpkh").unwrap(),
            PaymentEndpointPayload::new("private-address"),
        )])))
        .metadata(serde_json::Map::from_iter([
            ("bundle_id".into(), serde_json::json!("bundle-secret")),
            (
                "nested".into(),
                serde_json::json!({"reader": "reader-secret"}),
            ),
        ]))
        .build()
        .unwrap();
        let intent = DeliveryIntentV1::payment_request(READER.into(), app_id, &terms).unwrap();
        assert_eq!(
            DeliveryIntentV1::decode(&postcard::to_allocvec(&intent).unwrap()).unwrap(),
            intent
        );
        assert!(!format!("{intent:?}").contains("private-address"));
        let mut wrong_app = intent.clone();
        wrong_app.app_id = "bitkit".into();
        assert_eq!(wrong_app.validate(), Err(DeliveryIntentError::Invalid));
        let mut wrong_version = intent;
        wrong_version.version = 2;
        assert_eq!(wrong_version.validate(), Err(DeliveryIntentError::Invalid));
    }
}
