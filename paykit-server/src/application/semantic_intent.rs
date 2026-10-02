//! Closed, versioned semantic inputs used to replay a durable Paykit handoff.
//!
//! These values are the complete inputs to public Paykit SDK enqueue/proposal
//! methods. They deliberately do not contain SDK-generated event, request, wire,
//! or outbound-message identifiers.

use std::{collections::BTreeMap, fmt};

use paykit_lib::{
    PaykitAppId, PaymentAmount, PaymentEndpointIdentifier, PaymentReference, PaymentRequestId,
    PaymentRequestTerms,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// Server-owned delivery intent stored inside the Creator-bound outbox AEAD envelope.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveryIntentV1 {
    version: u8,
    reader_pubky: String,
    app_id: String,
    operation: DeliveryOperationV1,
}

/// Exactly one supported public-SDK operation and all of its caller inputs.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum DeliveryOperationV1 {
    PaymentRequestProposal { terms: PaymentTermsV1 },
    PaymentRequestCancellation { payment_request_id: String },
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct PaymentTermsV1 {
    pub amount: String,
    pub asset: String,
    pub payment_reference: String,
    pub proposal_expires_at: Option<String>,
    pub payment_deadline: Option<String>,
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
            || terms.required_app_id() != Some(&app_id)
        {
            return Err(DeliveryIntentError::Invalid);
        }
        let intent = Self {
            version: 2,
            reader_pubky,
            app_id: app_id.as_str().into(),
            operation: DeliveryOperationV1::PaymentRequestProposal {
                terms: PaymentTermsV1 {
                    amount: terms.amount().value().to_owned(),
                    asset: terms.amount().asset().to_owned(),
                    payment_reference: terms.payment_reference().to_string(),
                    proposal_expires_at: terms.proposal_expires_at().clone(),
                    payment_deadline: terms
                        .payment_deadline()
                        .map(|deadline| deadline.at(None))
                        .transpose()
                        .map_err(|_| DeliveryIntentError::Invalid)?,
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
            },
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn payment_request_cancellation(
        proposal: &Self,
        payment_request_id: String,
    ) -> Result<Self, DeliveryIntentError> {
        if !matches!(
            proposal.operation,
            DeliveryOperationV1::PaymentRequestProposal { .. }
        ) || PaymentRequestId::new(payment_request_id.clone()).is_err()
        {
            return Err(DeliveryIntentError::Invalid);
        }
        let intent = Self {
            version: 2,
            reader_pubky: proposal.reader_pubky.clone(),
            app_id: proposal.app_id.clone(),
            operation: DeliveryOperationV1::PaymentRequestCancellation { payment_request_id },
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn proposal_payment_reference(&self) -> Result<&str, DeliveryIntentError> {
        match &self.operation {
            DeliveryOperationV1::PaymentRequestProposal { terms } => {
                PaymentReference::new(terms.payment_reference.clone())
                    .map_err(|_| DeliveryIntentError::Invalid)?;
                Ok(&terms.payment_reference)
            }
            DeliveryOperationV1::PaymentRequestCancellation { .. } => {
                Err(DeliveryIntentError::Invalid)
            }
        }
    }

    pub fn set_deadlines(
        &mut self,
        proposal_expires_at: String,
        payment_deadline: String,
    ) -> Result<(), DeliveryIntentError> {
        let proposal = OffsetDateTime::parse(&proposal_expires_at, &Rfc3339)
            .map_err(|_| DeliveryIntentError::Invalid)?;
        let payment = OffsetDateTime::parse(&payment_deadline, &Rfc3339)
            .map_err(|_| DeliveryIntentError::Invalid)?;
        if proposal >= payment {
            return Err(DeliveryIntentError::Invalid);
        }
        match &mut self.operation {
            DeliveryOperationV1::PaymentRequestProposal { terms } => {
                terms.proposal_expires_at = Some(proposal_expires_at);
                terms.payment_deadline = Some(payment_deadline);
                self.validate()
            }
            DeliveryOperationV1::PaymentRequestCancellation { .. } => {
                Err(DeliveryIntentError::Invalid)
            }
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DeliveryIntentError> {
        let intent: Self = postcard::from_bytes(bytes).map_err(|_| DeliveryIntentError::Invalid)?;
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), DeliveryIntentError> {
        if self.version != 2
            || crate::domain::locks::parse_reader(&self.reader_pubky).is_err()
            || self.app_id != crate::config::PAYKIT_APP_ID
        {
            return Err(DeliveryIntentError::Invalid);
        }
        match &self.operation {
            DeliveryOperationV1::PaymentRequestProposal { terms } => validate_terms(terms),
            DeliveryOperationV1::PaymentRequestCancellation { payment_request_id } => {
                PaymentRequestId::new(payment_request_id.clone())
                    .map_err(|_| DeliveryIntentError::Invalid)?;
                Ok(())
            }
        }
    }

    pub fn reader_pubky(&self) -> &str {
        &self.reader_pubky
    }

    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    pub fn operation(&self) -> &DeliveryOperationV1 {
        &self.operation
    }

    pub fn terms(&self) -> Result<&PaymentTermsV1, DeliveryIntentError> {
        match &self.operation {
            DeliveryOperationV1::PaymentRequestProposal { terms } => Ok(terms),
            DeliveryOperationV1::PaymentRequestCancellation { .. } => {
                Err(DeliveryIntentError::Invalid)
            }
        }
    }

    pub fn matches_proposal(
        &self,
        reader_pubky: &str,
        proposal_app_id: &str,
        expected_terms: &PaymentTermsV1,
    ) -> bool {
        self.reader_pubky == reader_pubky
            && self.app_id == proposal_app_id
            && matches!(
                &self.operation,
                DeliveryOperationV1::PaymentRequestProposal { terms }
                    if terms.payment_reference == expected_terms.payment_reference
                        && terms == expected_terms
            )
    }
}

fn validate_terms(terms: &PaymentTermsV1) -> Result<(), DeliveryIntentError> {
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
        || terms
            .proposal_expires_at
            .as_ref()
            .is_some_and(|value| OffsetDateTime::parse(value, &Rfc3339).is_err())
        || terms
            .payment_deadline
            .as_ref()
            .is_some_and(|value| OffsetDateTime::parse(value, &Rfc3339).is_err())
    {
        return Err(DeliveryIntentError::Invalid);
    }
    match (&terms.proposal_expires_at, &terms.payment_deadline) {
        (None, None) => Ok(()),
        (Some(proposal), Some(payment))
            if OffsetDateTime::parse(proposal, &Rfc3339).ok()
                < OffsetDateTime::parse(payment, &Rfc3339).ok() =>
        {
            Ok(())
        }
        _ => Err(DeliveryIntentError::Invalid),
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
            Self::PaymentRequestProposal { .. } => "PaymentRequestProposal { .. }",
            Self::PaymentRequestCancellation { .. } => "PaymentRequestCancellation { .. }",
        })
    }
}

impl fmt::Debug for PaymentTermsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PaymentTermsV1 { .. }")
    }
}
