use std::str::FromStr;

use bitcoin::{Address, AddressType, Amount, Denomination, Network};
use paykit_sdk::{
    PaymentAdapter, PaymentRequestLifecycleState, PaymentRequestLocalRole, PaymentRequestRecord,
    PaymentTarget, PrivateContactPaymentResolution, PrivatePaymentEndpointCandidate,
    PrivatePaymentEndpointSelectionRequest, PrivatePaymentResolutionStatus, PubkyPublicKey,
};
use serde::Deserialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{Failure, PAYKIT_APP_ID, ReceiveOutput};

pub(super) const BITCOIN_ENDPOINT: &str = "btc-regtest-p2wpkh";
const MAX_BITCOIN_SATS: u64 = 2_100_000_000_000_000;

pub(super) struct DemoPaymentAdapter;

#[async_trait::async_trait]
impl PaymentAdapter for DemoPaymentAdapter {
    async fn select_private_payment_endpoints(
        &self,
        request: &PrivatePaymentEndpointSelectionRequest,
    ) -> paykit_sdk::Result<Vec<PrivatePaymentEndpointCandidate>> {
        Ok(request
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.app_id.as_str() == PAYKIT_APP_ID
                    && candidate.identifier == BITCOIN_ENDPOINT
            })
            .cloned()
            .collect())
    }

    async fn build_private_payment_target(
        &self,
        endpoint: &PrivatePaymentEndpointCandidate,
    ) -> paykit_sdk::Result<PaymentTarget> {
        Ok(PaymentTarget {
            payload: endpoint.payload.clone(),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BitcoinEndpointPayload {
    value: String,
}

pub(super) fn select_actionable_request(
    requests: &[PaymentRequestRecord],
) -> Result<Option<&PaymentRequestRecord>, Failure> {
    let mut actionable = None;
    for request in requests {
        let app_id = request
            .proposal_app_id
            .as_ref()
            .ok_or(Failure::ProtocolFailed)?;
        if app_id.as_str() != PAYKIT_APP_ID {
            continue;
        }
        match request.state {
            PaymentRequestLifecycleState::Proposed => {
                if request.local_role != Some(PaymentRequestLocalRole::Payer) {
                    return Err(Failure::ProtocolFailed);
                }
                actionable.get_or_insert(request);
            }
            PaymentRequestLifecycleState::ProposalExpired
            | PaymentRequestLifecycleState::Accepted
            | PaymentRequestLifecycleState::Rejected
            | PaymentRequestLifecycleState::Canceled
            | PaymentRequestLifecycleState::ProofSubmitted => {}
            PaymentRequestLifecycleState::ActiveRecurring
            | PaymentRequestLifecycleState::RecoveryRequired
            | PaymentRequestLifecycleState::InvalidConflict => {
                return Err(Failure::ProtocolFailed);
            }
            _ => return Err(Failure::ProtocolFailed),
        }
    }
    Ok(actionable)
}

pub(super) fn payment_instructions(
    request: &PaymentRequestRecord,
    resolution: &PrivateContactPaymentResolution,
    reader_pubky: &PubkyPublicKey,
) -> Result<ReceiveOutput, Failure> {
    payment_instructions_at(request, resolution, reader_pubky, OffsetDateTime::now_utc())
}

fn payment_instructions_at(
    request: &PaymentRequestRecord,
    resolution: &PrivateContactPaymentResolution,
    reader_pubky: &PubkyPublicKey,
    now: OffsetDateTime,
) -> Result<ReceiveOutput, Failure> {
    if request
        .proposal_app_id
        .as_ref()
        .map(|app_id| app_id.as_str())
        != Some(PAYKIT_APP_ID)
        || request.local_role != Some(PaymentRequestLocalRole::Payer)
        || request.state != PaymentRequestLifecycleState::Proposed
    {
        return Err(Failure::ProtocolFailed);
    }
    let terms = request.terms.as_ref().ok_or(Failure::ProtocolFailed)?;
    if terms.amount.asset != "btc"
        || terms.required_app_id.as_ref().map(|id| id.as_str()) != Some(PAYKIT_APP_ID)
        || terms.recurrence.is_some()
        || terms.conversion.is_some()
        || terms.accepted_payment_endpoint_identifiers != [BITCOIN_ENDPOINT.to_owned()]
        || terms
            .metadata
            .get("reader")
            .and_then(|value| value.as_str())
            != Some(reader_pubky.to_app_key().as_str())
    {
        return Err(Failure::ProtocolFailed);
    }
    if let Some(proposal_expires_at) = &terms.proposal_expires_at {
        let proposal_expires_at = OffsetDateTime::parse(proposal_expires_at, &Rfc3339)
            .map_err(|_| Failure::ProtocolFailed)?;
        if proposal_expires_at <= now {
            return Err(Failure::ProtocolFailed);
        }
    }
    let amount = Amount::from_str_in(&terms.amount.value, Denomination::Bitcoin)
        .map_err(|_| Failure::ProtocolFailed)?;
    let amount_sats = amount.to_sat();
    if amount_sats == 0 || amount_sats > MAX_BITCOIN_SATS {
        return Err(Failure::ProtocolFailed);
    }
    let endpoints = terms
        .payment_endpoints
        .as_ref()
        .ok_or(Failure::ProtocolFailed)?;
    if endpoints.len() != 1
        || resolution.status != PrivatePaymentResolutionStatus::Payable
        || resolution.private_payment_list_version.is_some()
        || resolution.payable_endpoints.len() != 1
    {
        return Err(Failure::ProtocolFailed);
    }
    let raw_payload = endpoints
        .get(BITCOIN_ENDPOINT)
        .ok_or(Failure::ProtocolFailed)?;
    let resolved = &resolution.payable_endpoints[0];
    if resolved.endpoint.counterparty != request.counterparty
        || resolved.endpoint.app_id.as_str() != PAYKIT_APP_ID
        || resolved.endpoint.identifier != BITCOIN_ENDPOINT
        || &resolved.endpoint.payload != raw_payload
        || &resolved.target.payload != raw_payload
    {
        return Err(Failure::ProtocolFailed);
    }
    let raw_address = serde_json::from_str::<BitcoinEndpointPayload>(raw_payload)
        .map_err(|_| Failure::ProtocolFailed)?
        .value;
    let address = Address::from_str(&raw_address)
        .map_err(|_| Failure::ProtocolFailed)?
        .require_network(Network::Regtest)
        .map_err(|_| Failure::ProtocolFailed)?;
    if address.address_type() != Some(AddressType::P2wpkh) || address.to_string() != raw_address {
        return Err(Failure::ProtocolFailed);
    }
    let address = address.to_string();
    let bitcoin_amount = format!(
        "{}.{:08}",
        amount_sats / 100_000_000,
        amount_sats % 100_000_000
    );
    Ok(ReceiveOutput {
        version: 1,
        status: "received",
        payment_request_id: request.payment_request_id.clone(),
        address: address.clone(),
        asset: "btc",
        amount_sats: amount_sats.to_string(),
        payment_command: format!(
            "docker compose exec -T bitcoin sh -ec 'bitcoin-cli -conf=\"$BITCOIN_DATA/bitcoin.conf\" -regtest -rpcwallet=miner sendtoaddress \"{address}\" \"{bitcoin_amount}\"'"
        ),
        optional_mining_command: "docker compose exec -T bitcoin sh -ec 'bitcoin-cli -conf=\"$BITCOIN_DATA/bitcoin.conf\" -regtest -rpcwallet=miner generatetoaddress 6 \"$(bitcoin-cli -conf=\"$BITCOIN_DATA/bitcoin.conf\" -regtest -rpcwallet=miner getnewaddress)\"'".into(),
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use bitcoin::{Address, Network};
    use paykit_sdk::{
        AmountRecord, PaykitAppId, PaymentRequestLifecycleState, PaymentRequestLocalRole,
        PaymentRequestRecord, PaymentRequestTermsRecord, PaymentTarget,
        PrivateContactPaymentResolution, PrivatePaymentEndpointCandidate,
        PrivatePaymentResolutionState, PrivatePaymentResolutionStatus, PubkyPublicKey,
        ResolvedPrivatePaymentEndpoint,
    };
    use serde_json::{Map, json, to_value};
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};

    use super::{
        BITCOIN_ENDPOINT, payment_instructions, payment_instructions_at, select_actionable_request,
    };

    fn reader() -> PubkyPublicKey {
        PubkyPublicKey::from_raw_or_app_key(
            "pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo",
        )
        .unwrap()
    }

    fn request() -> PaymentRequestRecord {
        let reader = reader();
        PaymentRequestRecord {
            counterparty: PubkyPublicKey::from_raw_or_app_key(
                "pubkytkrq8zmwb8a3m9k15csu3q17qmfgqnp9dskbrg9uq1rydpyxp7qy",
            )
            .unwrap(),
            proposal_app_id: Some(PaykitAppId::new("paykit-server").unwrap()),
            payer_app_id: None,
            execution_claim_app_id: None,
            conversion_quotes: Vec::new(),
            payment_request_id: "b7f9c2a1-6d43-4b0e-a8d4-0fe2c712ab33".into(),
            local_role: Some(PaymentRequestLocalRole::Payer),
            state: PaymentRequestLifecycleState::Proposed,
            proposal_stream_item_id: Some(1),
            proposal_outbound_message_id: None,
            proposal_outbound_status: None,
            proposal_event_id: Some("8a0d8b4c-913f-4e31-9f2c-2a6f5bb4d101".into()),
            terms: Some(PaymentRequestTermsRecord {
                amount: AmountRecord {
                    asset: "btc".into(),
                    value: "0.00050000".into(),
                },
                payment_reference: "reference-1".into(),
                proposal_expires_at: None,
                recurrence: None,
                required_app_id: Some(PaykitAppId::new("paykit-server").unwrap()),
                conversion: None,
                payment_deadline: None,
                accepted_payment_endpoint_identifiers: vec![BITCOIN_ENDPOINT.into()],
                payment_endpoints: Some(HashMap::from([(
                    BITCOIN_ENDPOINT.into(),
                    json!({"value": regtest_p2wpkh()}).to_string(),
                )])),
                metadata: Map::from_iter([("reader".into(), json!(reader.to_app_key()))]),
            }),
            accepted_event_id: None,
            accepted_outbound_status: None,
            rejected_event_id: None,
            rejected_outbound_status: None,
            canceled_event_id: None,
            canceled_outbound_status: None,
            payment_proofs: Vec::new(),
            last_stream_item_id: Some(1),
            last_outbound_message_id: None,
            last_outbound_status: None,
            last_event_at: None,
            invalid_reason: None,
        }
    }

    fn resolution(address: &str) -> PrivateContactPaymentResolution {
        let payload = json!({"value": address}).to_string();
        PrivateContactPaymentResolution {
            status: PrivatePaymentResolutionStatus::Payable,
            state: PrivatePaymentResolutionState::Available,
            private_payment_list_version: None,
            payable_endpoints: vec![ResolvedPrivatePaymentEndpoint {
                endpoint: PrivatePaymentEndpointCandidate {
                    counterparty: request().counterparty,
                    app_id: PaykitAppId::new("paykit-server").unwrap(),
                    identifier: BITCOIN_ENDPOINT.into(),
                    payload: payload.clone(),
                },
                target: PaymentTarget { payload },
            }],
        }
    }

    fn public_key() -> bitcoin::CompressedPublicKey {
        bitcoin::CompressedPublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
    }

    fn regtest_p2wpkh() -> String {
        Address::p2wpkh(&public_key(), Network::Regtest).to_string()
    }

    #[test]
    fn projects_exact_valid_request_and_manual_commands() {
        let output =
            payment_instructions(&request(), &resolution(&regtest_p2wpkh()), &reader()).unwrap();
        assert_eq!(output.payment_request_id, request().payment_request_id);
        assert_eq!(output.amount_sats, "50000");
        assert_eq!(
            output.payment_command,
            format!(
                "docker compose exec -T bitcoin sh -ec 'bitcoin-cli -conf=\"$BITCOIN_DATA/bitcoin.conf\" -regtest -rpcwallet=miner sendtoaddress \"{}\" \"0.00050000\"'",
                regtest_p2wpkh()
            )
        );
        assert_eq!(
            output.optional_mining_command,
            "docker compose exec -T bitcoin sh -ec 'bitcoin-cli -conf=\"$BITCOIN_DATA/bitcoin.conf\" -regtest -rpcwallet=miner generatetoaddress 6 \"$(bitcoin-cli -conf=\"$BITCOIN_DATA/bitcoin.conf\" -regtest -rpcwallet=miner getnewaddress)\"'"
        );
        assert_eq!(
            to_value(&output).unwrap(),
            json!({
                "version": 1,
                "status": "received",
                "payment_request_id": request().payment_request_id,
                "address": regtest_p2wpkh(),
                "asset": "btc",
                "amount_sats": "50000",
                "payment_command": format!(
                    "docker compose exec -T bitcoin sh -ec 'bitcoin-cli -conf=\"$BITCOIN_DATA/bitcoin.conf\" -regtest -rpcwallet=miner sendtoaddress \"{}\" \"0.00050000\"'",
                    regtest_p2wpkh()
                ),
                "optional_mining_command": "docker compose exec -T bitcoin sh -ec 'bitcoin-cli -conf=\"$BITCOIN_DATA/bitcoin.conf\" -regtest -rpcwallet=miner generatetoaddress 6 \"$(bitcoin-cli -conf=\"$BITCOIN_DATA/bitcoin.conf\" -regtest -rpcwallet=miner getnewaddress)\"'"
            })
        );
    }

    #[test]
    fn accepts_server_request_before_proposal_deadline() {
        let now = OffsetDateTime::parse("2027-01-15T07:59:59Z", &Rfc3339).unwrap();
        let mut request = request();
        let terms = request.terms.as_mut().unwrap();
        terms.proposal_expires_at = Some("2027-01-15T08:00:00Z".into());
        terms.payment_deadline = Some(paykit_lib::PaymentDeadline::At {
            timestamp: "2027-01-16T08:00:00Z".into(),
        });

        assert!(
            payment_instructions_at(&request, &resolution(&regtest_p2wpkh()), &reader(), now,)
                .is_ok()
        );
    }

    #[test]
    fn rejects_server_request_at_or_after_proposal_deadline() {
        let deadline = "2027-01-15T08:00:00Z";
        let mut request = request();
        request.terms.as_mut().unwrap().proposal_expires_at = Some(deadline.into());

        for now in [
            OffsetDateTime::parse(deadline, &Rfc3339).unwrap(),
            OffsetDateTime::parse("2027-01-15T08:00:01Z", &Rfc3339).unwrap(),
        ] {
            assert!(
                payment_instructions_at(&request, &resolution(&regtest_p2wpkh()), &reader(), now,)
                    .is_err()
            );
        }
    }

    #[test]
    fn rejects_malformed_proposal_deadline() {
        let now = OffsetDateTime::parse("2027-01-15T07:59:59Z", &Rfc3339).unwrap();
        let mut request = request();
        request.terms.as_mut().unwrap().proposal_expires_at = Some("not-rfc3339".into());

        assert!(
            payment_instructions_at(&request, &resolution(&regtest_p2wpkh()), &reader(), now,)
                .is_err()
        );
    }

    #[test]
    fn rejects_unsupported_conversion_terms() {
        let mut request = request();
        request.terms.as_mut().unwrap().conversion =
            Some(paykit_lib::PaymentConversion::Fixed { rates: Vec::new() });

        assert!(payment_instructions(&request, &resolution(&regtest_p2wpkh()), &reader()).is_err());
    }

    #[test]
    fn payment_command_canonicalizes_equivalent_paykit_amount_spellings() {
        for value in [".0005", "000.00050000"] {
            let mut request = request();
            request.terms.as_mut().unwrap().amount.value = value.into();
            let output =
                payment_instructions(&request, &resolution(&regtest_p2wpkh()), &reader()).unwrap();
            assert!(output.payment_command.ends_with("\"0.00050000\"'"));
        }
    }

    #[test]
    fn rejects_wrong_recipient_conflict_and_unsupported_terms() {
        let list = resolution(&regtest_p2wpkh());
        let mut wrong_reader = request();
        wrong_reader.terms.as_mut().unwrap().metadata.insert(
            "reader".into(),
            json!("pubky7ir1ttte48bcp4zjychjyscicrwi1j34mtt91ptsafdbjmr8g9eo"),
        );
        assert!(payment_instructions(&wrong_reader, &list, &request().counterparty).is_err());
        let mut conflict = request();
        conflict.state = PaymentRequestLifecycleState::InvalidConflict;
        assert!(payment_instructions(&conflict, &list, &reader()).is_err());
        let mut fractional_sat = request();
        fractional_sat.terms.as_mut().unwrap().amount.value = "0.000000001".into();
        assert!(payment_instructions(&fractional_sat, &list, &reader()).is_err());
    }

    #[test]
    fn selects_newest_current_proposal_without_treating_history_as_ambiguous() {
        let current = request();
        let mut expired = request();
        expired.payment_request_id = "6fce1f5c-736a-43df-a1e9-a105889a19da".into();
        expired.state = PaymentRequestLifecycleState::ProposalExpired;
        let requests = vec![current.clone(), expired];
        assert_eq!(
            select_actionable_request(&requests)
                .unwrap()
                .unwrap()
                .payment_request_id,
            current.payment_request_id
        );

        let mut newest = request();
        newest.payment_request_id = "71e4c53e-4455-4307-89ab-f6676d9ea225".into();
        newest.proposal_stream_item_id = Some(3);
        newest.last_stream_item_id = Some(3);
        let mut older = request();
        older.payment_request_id = "8cd29d33-f948-4f00-8d8f-e72cb15b7fac".into();
        older.proposal_stream_item_id = Some(2);
        older.last_stream_item_id = Some(2);
        assert_eq!(
            select_actionable_request(&[newest.clone(), older])
                .unwrap()
                .unwrap()
                .payment_request_id,
            newest.payment_request_id
        );
        let mut conflict = request();
        conflict.state = PaymentRequestLifecycleState::InvalidConflict;
        assert!(select_actionable_request(&[current, conflict]).is_err());
    }

    #[test]
    fn selects_server_request_among_other_app_requests_in_either_order() {
        let server = request();
        for state in [
            PaymentRequestLifecycleState::Proposed,
            PaymentRequestLifecycleState::ActiveRecurring,
            PaymentRequestLifecycleState::RecoveryRequired,
            PaymentRequestLifecycleState::InvalidConflict,
        ] {
            let mut other = request();
            other.payment_request_id = "71e4c53e-4455-4307-89ab-f6676d9ea225".into();
            other.proposal_app_id = Some(PaykitAppId::new("bitkit").unwrap());
            other.terms.as_mut().unwrap().required_app_id = other.proposal_app_id.clone();
            other.state = state;
            for requests in [
                [other.clone(), server.clone()],
                [server.clone(), other.clone()],
            ] {
                let selected = select_actionable_request(&requests).unwrap().unwrap();
                assert_eq!(selected.payment_request_id, server.payment_request_id);
                assert!(
                    payment_instructions(selected, &resolution(&regtest_p2wpkh()), &reader())
                        .is_ok()
                );
            }
            assert!(select_actionable_request(&[other]).unwrap().is_none());
        }
    }

    #[test]
    fn selection_keeps_unknown_ownership_and_server_failures_terminal() {
        let server = request();
        let mut unknown = request();
        unknown.proposal_app_id = None;
        assert!(select_actionable_request(&[server.clone(), unknown]).is_err());

        for state in [
            PaymentRequestLifecycleState::ActiveRecurring,
            PaymentRequestLifecycleState::RecoveryRequired,
            PaymentRequestLifecycleState::InvalidConflict,
        ] {
            let mut invalid = request();
            invalid.state = state;
            assert!(select_actionable_request(&[server.clone(), invalid]).is_err());
        }
    }

    #[test]
    fn payment_instructions_require_server_proposal_ownership() {
        for app_id in [None, Some(PaykitAppId::new("bitkit").unwrap())] {
            let mut request = request();
            request.proposal_app_id = app_id;
            assert!(
                payment_instructions(&request, &resolution(&regtest_p2wpkh()), &reader()).is_err()
            );
        }
    }

    #[test]
    fn rejects_malformed_wrong_network_and_non_p2wpkh_endpoints() {
        assert!(
            payment_instructions(&request(), &resolution("not-an-address"), &reader()).is_err()
        );
        let mainnet = Address::p2wpkh(&public_key(), Network::Bitcoin).to_string();
        assert!(payment_instructions(&request(), &resolution(&mainnet), &reader()).is_err());
        let p2tr = Address::p2tr(
            &bitcoin::secp256k1::Secp256k1::verification_only(),
            bitcoin::secp256k1::XOnlyPublicKey::from_str(
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            )
            .unwrap(),
            None,
            Network::Regtest,
        )
        .to_string();
        assert!(payment_instructions(&request(), &resolution(&p2tr), &reader()).is_err());

        let mut extra = resolution(&regtest_p2wpkh());
        extra
            .payable_endpoints
            .push(extra.payable_endpoints[0].clone());
        assert!(payment_instructions(&request(), &extra, &reader()).is_err());
    }

    #[test]
    fn rejects_unbound_requests_and_list_based_resolution() {
        let mut unbound = request();
        unbound.terms.as_mut().unwrap().payment_endpoints = None;
        assert!(payment_instructions(&unbound, &resolution(&regtest_p2wpkh()), &reader()).is_err());
        let mut list_based = resolution(&regtest_p2wpkh());
        list_based.private_payment_list_version = Some(1);
        assert!(payment_instructions(&request(), &list_based, &reader()).is_err());
    }
}
