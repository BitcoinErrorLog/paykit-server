-- One invoice has one proposal plus zero or more cancellation intents.
ALTER TABLE outbox DROP CONSTRAINT outbox_invoice_id_key;
