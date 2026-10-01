# Bitkit companion claim contract

Initial Paykit Server setup requests both Paykit access and a new watch-only BIP84 account.
Explicit reconnect requests only Paykit access and retains the server's account binding.
The SDK companion API signs and encrypts the application payload. The request
requires the exact `/pub/paykit/:rw` capability.

The `x-bitkit-claim` query parameter must occur exactly once. Its value is a
dot-separated list of independent permission identifiers: `paykit-access-v1`
and `watch-only-account-v1`. The supported permission selections are:

| Permission list (SDK `claim_type`) | Unsigned bytes | Contents |
| --- | ---: | --- |
| `watch-only-account-v1` | 84 | Version, account index, address kind, serialized xpub only |
| `paykit-access-v1` | 41 | Version, key generation, Paykit identity secret only |
| `paykit-access-v1.watch-only-account-v1` | 124 | 84 watch-only bytes, generation, secret |

Server builders compose the last list in Paykit-then-watch-only order:

```text
pubkyauth://signin_grant?...&x-bitkit-claim=paykit-access-v1.watch-only-account-v1
```

The reverse list `watch-only-account-v1.paykit-access-v1` requests the same two
permissions, but is a different signed string and relay channel. The SDK accepts
the dot within its protocol identifier grammar. Pass the exact received list
string, including order, as `claim_type`; never sort or reconstruct it for a reply.

Unknown, duplicate, or empty items, duplicate query parameters, and mismatched
responses fail closed. Bitkit displays each requested permission
independently and must not export a Paykit secret for watch-only approval, or
allocate/track an account for Paykit-only approval.

Initial server setup requires both permissions and rejects one-only requests and replies.
Reconnect requires only `paykit-access-v1` and rejects watch-only or combined replies.
The demo validates that both were
requested before deriving or exporting any key. `AuthRequest` retains the exact
validated list and AUTH secret; channel derivation and verification take that
request together so a caller cannot accidentally normalize the list at either
boundary.

## Fixed payload order

The payload layout does not follow list order. Watch-only uses version `0x01`,
the 4-byte big-endian account index, kind `0x00`, and 78-byte serialized xpub
(84 bytes). Paykit-only uses version `0x01`, the 8-byte big-endian generation,
and 32-byte identity secret (41 bytes). When both are requested, use the
84 watch-only bytes followed by generation and secret, with no second version
byte (124 bytes), even if Paykit access appears first in the request.

Offsets are zero-based and ranges below are half-open:

| Offset | Width | Value |
| --- | ---: | --- |
| `0` | 1 | Version `0x01` |
| `1..5` | 4 | Account index, unsigned big-endian, less than `2^31` |
| `5` | 1 | Address kind `0x00` (BIP84) |
| `6..84` | 78 | Serialized account xpub |
| `84..92` | 8 | Nonzero Paykit key generation, unsigned big-endian |
| `92..124` | 32 | Paykit identity secret |

The signature is Ed25519 over these concatenated bytes:

```text
UTF8("x-bitkit-claim|") || UTF8(received_claim_type) || UTF8("|")
|| SHA256(auth_secret)
|| unsigned_payload
```

Append the 64-byte signature to the 124-byte payload. Encrypt those 188 bytes
with the existing XSalsa20-Poly1305 companion transport keyed by the 32-byte AUTH
secret. The relay body is the 24-byte nonce followed by the 16-byte authenticator
and ciphertext (228 bytes total). The channel ID remains unpadded base64url of:

```text
BLAKE3(UTF8(received_claim_type) || UTF8("|") || auth_secret)
```

Verification uses the Creator established by normal Pubky AUTH, not a name or
query hint. It checks the exact length/schema, signature, xpub network/depth/index,
and delegated key against the wallet-published App Registry before durable writes.
Each setup attempt is consumed once. A prior claim cannot be rebound to a new
AUTH secret, query parameter, permission selection, or list order.

## Reconnection

The caller opens `GET /setup/reconnect` with `creator`, `return_to`, and `state`.
The canonical Creator must already exist before an AUTH request is created. It is
retained in the in-memory flow and must exactly match the identity authenticated
by Pubky AUTH; a different authorizer fails before credential writes or publication.
The URL requests only `x-bitkit-claim=paykit-access-v1`. Its 41 unsigned bytes
contain version, generation, and Paykit secret; with the signature and encryption
envelope the relay body is 145 bytes. No account bytes or native account picker
participate. Client IDs, display names, and relay URLs never select an account.

Under the Creator setup lock, reconnect loads the existing account index and xpub
and retains them exactly. A missing Creator cannot be created by reconnect. Initial
setup cannot overwrite an existing binding, including one awaiting publication retry.
The same Paykit generation must retain the same secret; lower
generations are rejected, and a higher generation must match the App Registry.
Unexpected account material and failed verification leave existing credentials and setup
readiness unchanged. An abandoned approval performs no durable writes. Bitkit
must retain existing account tracking/data on rejection or cancellation.

Successful reauthorization replaces only credentials before republishing the
server app, preserving invoices, reader assignments, pending delivery intents,
and the next address allocation index. Publication failure retains retryable
credentials with setup incomplete; it does not delete history or compensate by
rewriting shared registry state.

## Wire fixture

[`bitkit-combined-claim-v1.json`](../paykit-server/tests/fixtures/bitkit-combined-claim-v1.json)
is language-neutral and checked by the server encoder and decoder. Its
`claim_type` is `paykit-access-v1.watch-only-account-v1`. It uses index
`0x01020304`, 78 bytes of `09`, generation `0x0102030405060708`, and 32 bytes of
`0b`. The expected unsigned hex is fixed. The synthetic xpub field tests byte
layout only, not Bitcoin key validity. Use an exact unsigned 64-bit integer for
generation; do not round it through a floating-point JSON representation.

The local SDK relay test exercises both list orders through the generic
signing/encryption API and rejects a reordered response binding. Single-permission
payload tests check the 84/41-byte forms, initial setup rejection, and exact Paykit-only reconnect. The
PostgreSQL/Pubky setup composition covers valid BIP84 accounts,
rejected and cancelled reconnects, preserved pending invoices, and key rotation.
