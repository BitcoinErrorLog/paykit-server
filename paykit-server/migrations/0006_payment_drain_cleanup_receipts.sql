ALTER TABLE lock_payment_generations
    ADD COLUMN last_cleanup_token BYTEA;

ALTER TABLE lock_payment_generations
    ADD CONSTRAINT lock_payment_generations_cleanup_token_length
    CHECK (last_cleanup_token IS NULL OR octet_length(last_cleanup_token) = 32);
