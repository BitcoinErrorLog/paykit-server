use std::str::FromStr;

use bitcoin::{Address, AddressType, Amount, Denomination, Network};
use paykit_sdk::{
    PaymentRequestLifecycleState, PaymentRequestLocalRole, PaymentRequestRecord,
    PrivatePaymentListView, PubkyPublicKey,
};

use super::{Failure, ReceiveOutput};

/// The demo validates regtest instructions, so it expects the
/// network-correct endpoint identifier the patched server advertises.
pub(super) const BITCOIN_ENDPOINT: &str = "btc-regtest-p2wpkh";
const MAX_BITCOIN_SATS: u64 = 2_100_000_000_000_000;

pub(super) fn select_actionable_request(
    requests: &[PaymentRequestRecord],
) -> Result<Option<&PaymentRequestRecord>, Failure> {
    let mut actionable = None;
    for request in requests {
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
    private_list: &PrivatePaymentListView,
    reader_pubky: &PubkyPublicKey,
) -> Result<ReceiveOutput, Failure> {
    if request.local_role != Some(PaymentRequestLocalRole::Payer)
        || request.state != PaymentRequestLifecycleState::Proposed
    {
        return Err(Failure::ProtocolFailed);
    }
    let terms = request.terms.as_ref().ok_or(Failure::ProtocolFailed)?;
    // Spec-lowercase asset string, matching the endpoint identifier's asset
    // segment (what real wallets enforce and the server now emits).
    if terms.amount.asset != "btc"
        || terms.recurrence.is_some()
        || terms.proposal_expires_at.is_some()
        || terms.accepted_payment_endpoint_identifiers != [BITCOIN_ENDPOINT.to_owned()]
        || terms
            .metadata
            .get("reader")
            .and_then(|value| value.as_str())
            != Some(reader_pubky.to_app_key().as_str())
    {
        return Err(Failure::ProtocolFailed);
    }
    let amount = Amount::from_str_in(&terms.amount.value, Denomination::Bitcoin)
        .map_err(|_| Failure::ProtocolFailed)?;
    let amount_sats = amount.to_sat();
    if amount_sats == 0 || amount_sats > MAX_BITCOIN_SATS {
        return Err(Failure::ProtocolFailed);
    }
    if private_list.payment_endpoints.len() != 1 {
        return Err(Failure::ProtocolFailed);
    }
    let raw_payload = private_list
        .payment_endpoints
        .get(BITCOIN_ENDPOINT)
        .ok_or(Failure::ProtocolFailed)?;
    // Payment-endpoint-identifier spec section 7: the interoperable payload
    // is a JSON object carrying the receiving handle under "value".
    let payload: serde_json::Value =
        serde_json::from_str(raw_payload).map_err(|_| Failure::ProtocolFailed)?;
    let raw_address = payload
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or(Failure::ProtocolFailed)?;
    let address = Address::from_str(raw_address)
        .map_err(|_| Failure::ProtocolFailed)?
        .require_network(Network::Regtest)
        .map_err(|_| Failure::ProtocolFailed)?;
    if address.address_type() != Some(AddressType::P2wpkh) || address.to_string() != *raw_address {
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
        asset: "BTC",
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
        AmountRecord, PaykitReceiverPath, PaymentRequestLifecycleState, PaymentRequestLocalRole,
        PaymentRequestRecord, PaymentRequestTermsRecord, PrivatePaymentListView, PubkyPublicKey,
    };
    use serde_json::{Map, json, to_value};

    use super::{BITCOIN_ENDPOINT, payment_instructions, select_actionable_request};

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
            counterparty_receiver_path: PaykitReceiverPath::new("paykit/server").unwrap(),
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
                accepted_payment_endpoint_identifiers: vec![BITCOIN_ENDPOINT.into()],
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

    fn private_list(address: &str) -> PrivatePaymentListView {
        PrivatePaymentListView {
            latest_stream_item_id: Some(2),
            payment_endpoints: HashMap::from([(
                BITCOIN_ENDPOINT.into(),
                json!({ "value": address }).to_string(),
            )]),
            last_refresh_at: None,
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
            payment_instructions(&request(), &private_list(&regtest_p2wpkh()), &reader()).unwrap();
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
                "asset": "BTC",
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
    fn payment_command_canonicalizes_equivalent_paykit_amount_spellings() {
        for value in [".0005", "000.00050000"] {
            let mut request = request();
            request.terms.as_mut().unwrap().amount.value = value.into();
            let output =
                payment_instructions(&request, &private_list(&regtest_p2wpkh()), &reader())
                    .unwrap();
            assert!(output.payment_command.ends_with("\"0.00050000\"'"));
        }
    }

    #[test]
    fn rejects_wrong_recipient_conflict_and_unsupported_terms() {
        let list = private_list(&regtest_p2wpkh());
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
    fn rejects_malformed_wrong_network_and_non_p2wpkh_endpoints() {
        assert!(
            payment_instructions(&request(), &private_list("not-an-address"), &reader()).is_err()
        );
        let mainnet = Address::p2wpkh(&public_key(), Network::Bitcoin).to_string();
        assert!(payment_instructions(&request(), &private_list(&mainnet), &reader()).is_err());
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
        assert!(payment_instructions(&request(), &private_list(&p2tr), &reader()).is_err());

        let mut extra = private_list(&regtest_p2wpkh());
        extra
            .payment_endpoints
            .insert("extra".into(), "payload".into());
        assert!(payment_instructions(&request(), &extra, &reader()).is_err());
    }
}
