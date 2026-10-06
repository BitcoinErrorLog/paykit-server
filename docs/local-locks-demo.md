# Local Locks demo image

`Dockerfile.local` packages Paykit Server for the Locks Compose stack. It is local/demo packaging, not a production image.

Invoices carry their immutable Bitcoin destination in the Payment Request terms.
`paykit-reader-demo` resolves the received request by ID through the SDK with no
Payment List version. It does not wait for an endpoint publication or use a later
Private Payment List as the invoice destination.

## Build from public release sources

From a fresh anonymous clone of this repository, build with the Paykit release
and exact Locks release selected in `Cargo.toml`:

```bash
docker buildx build --load \
  --build-context paykit-lib='https://github.com/pubky/paykit-rs.git#v0.1.0-rc64:paykit-lib' \
  --build-context paykit-sdk='https://github.com/pubky/paykit-rs.git#v0.1.0-rc64:paykit-sdk' \
  --build-context locks='https://github.com/pubky/locks.git#v0.1.0-rc8' \
  -f Dockerfile.local \
  -t paykit-server:local .
```

The Paykit tag resolves to `27fa6ed181d9fc428a6e2854f884c699a524dbc6`.
These contexts are anonymously reachable and reproducible. Update the URLs
together with the corresponding `Cargo.toml` pins; exact dependency-pin matches
make source drift fail closed.

## Build from local worktrees

For coordinated development, override the named contexts with local source
trees. This mode intentionally includes uncommitted source edits:

```bash
docker buildx build --load \
  --build-context paykit-lib=../paykit-rs/paykit-lib \
  --build-context paykit-sdk=../paykit-rs/paykit-sdk \
  --build-context locks=../../Pubky/locks \
  -f Dockerfile.local \
  -t paykit-server:local .
```

Crate-level `paykit-lib` and `paykit-sdk` contexts avoid transferring the Paykit
Rust workspace target directory and require no Docker-owned files in that
repository. The Locks context applies its existing source-tree exclusions.

Builder runs [`scripts/prepare-local-docker-sources.sh`](../scripts/prepare-local-docker-sources.sh) against copied manifests to resolve `paykit-lib`, `paykit-sdk`, and `locks-core` from named contexts. Committed Git dependency declarations and lockfile remain unchanged. No SSH agent or Cargo credentials are mounted. Exact dependency-pin matches make source drift fail closed.

## Runtime image

Final pinned Debian image:

- runs as unprivileged UID/GID `10001`;
- defaults to `/usr/local/bin/paykit-server` and exposes port `3001`;
- contains the existing `/usr/local/bin/paykit-reader-demo` binary for an
  explicit Compose command/entrypoint override;
- contains `/usr/local/bin/paykit-companion-auth`, built from the Paykit Cargo
  example `paykit-server/examples/paykit-companion-auth.rs` only by
  `Dockerfile.local`, for the Locks Creator demo to invoke;
- adds CA certificates, the server, the reader helper, and that local-only Cargo
  example to the pinned runtime base;
- contains no source tree, Cargo cache, runnable config, DB credentials, or application secrets.

Supply `PAYKIT_CONFIG`, `PAYKIT_DATABASE_URL`, and `PAYKIT_MASTER_KEY` at runtime. Mount generated ignored local config. The calling Compose definition owns mounts, environment values, infrastructure image pins, and helper command overrides.

## Generated local config contract

Locks must generate `.local/paykit-config/config.toml` only after the local Lock Server identity exists. The directory is Git-ignored. It must replace the deliberately invalid `<ACTUAL_CANONICAL_LOCK_SERVER_PUBKY>` token below with the exact canonical `pubky...` value exposed by Lock Server as `credentials.lock_server_public_key`. This block is not runnable config.

```toml
[http]
listen_addr = "0.0.0.0:3001"

[locks]
trusted_public_key = "<ACTUAL_CANONICAL_LOCK_SERVER_PUBKY>"

[setup]
allowed_origins = ["http://localhost:8080"]
# LOCAL DEMO ONLY. This logs the bearer-secret authorization URL once per flow.
# The operator owns access to and retention of the container logs.
log_authorization_url = true

[paykit]
client_id = "app.paykit.server"
app_id = "paykit-server"
network = "testnet"

[bitcoin]
network = "regtest"

[electrum]
endpoint = "tcp://fulcrum:50001"
poll_interval = "1s"

[outbox]
poll_interval = "500ms"
```

File contains no DB URL or master key. Compose supplies those only through `PAYKIT_DATABASE_URL` and `PAYKIT_MASTER_KEY`, then points `PAYKIT_CONFIG` at the mounted generated file. The parser rejects unknown keys, non-canonical trusted keys, and secrets placed in TOML. Only this local-demo config should enable `setup.log_authorization_url`.

## Local companion approval

Production setup is the Bitkit QR/deep-link flow. It has no helper handle,
helper endpoint or state, helper UI, or helper in the production package/runtime
surface. The companion executable
in this local image is only a demo substitute for Bitkit and is packaged only
from the Cargo example by `Dockerfile.local`.

### Prepare the Creator's Paykit identity

The Creator must already exist on the Pubky testnet. Companion approval does not
initialize Paykit: unless Bitkit has done so for that same identity and testnet,
run the existing authorizer `prepare` operation before server setup:

```bash
PAYKIT_READER_STATE_PATH=/operator-owned/paykit-authorizer.state \
PAYKIT_READER_PUBKY_TESTNET_HOST='<PUBKY_TESTNET_HOST>' \
PAYKIT_READER_APP_ID=paykit-authorizer-demo \
PAYKIT_READER_SERVER_PUBKY='<CANONICAL_CREATOR_PUBKY>' \
  /usr/local/bin/paykit-reader-demo < /operator-owned/authorizer-prepare.json
```

The private stdin file uses the **Creator's** root secret:
`{"version":1,"operation":"prepare","reader_secret":"<CREATOR_BASE64URL_32_BYTE_SECRET>"}`.

Use a separate authorizer app ID and state file, only for `prepare`. Keep the
input private and outside tracked source, then remove it; never send the root
secret to Paykit Server or put it in argv. `prepare` uses
`PAYKIT_AUTHORIZER_SESSION_CAPABILITIES` to publish the identity-signed Paykit Noise
Key Authorization before private app capabilities. Its additional
`/pub/paykit-authority/v0/current-key.json:rw` capability stays with the authorizer;
the exported Server grant remains `/pub/paykit/:rw`.
In the approval below, use generation `1` for a fresh identity or the existing
signed authorization's generation; never reset state. The independent Reader
must also run `prepare` for its own identity before exchanging private messages.

### Approve server setup

After starting a setup flow, retrieve the latest explicitly labeled
`paykit_setup_authorization_url` event from the Paykit Server container logs and
paste its `authorization_url` value into the Locks operator helper prompt. Each
flow emits exactly one such line when the generated local config enables
logging. The URL is a bearer secret: limit log access, do not publish or reuse
it, and delete or retain logs according to the local operator's policy.

The helper sends the Cargo example exactly one closed JSON object on stdin:

```json
{"version":1,"auth_url":"pubkyauth://...","creator_secret":"<base64url-32>","account_xpub":"tpub...","account_index":0,"key_generation":1}
```

Unknown or missing fields, extra argv, and invalid values are rejected. The
auth URL, Creator secret, and xpub never enter argv or `postMessage`, and the
example never echoes them to stdout or stderr. Its success output is only
`{"version":1,"status":"approved"}`; failures are coarse. There is no Paykit
Server URL input and no helper-to-server URL exchange: the example calls the
canonical `paykit-sdk` companion-approval operation directly.
`approved` confirms claim/grant delivery, not server setup completion; wait for
the setup flow's success response before creating invoices.

This local flow explicitly trusts the operator-supplied authorization URL's
provenance. Although the example validates client `app.paykit.server`, exact
capabilities
`/pub/paykit/:rw`, and
both independent permissions in `x-bitkit-claim=paykit-access-v1.watch-only-account-v1`
(either received order, retained exactly for SDK signing), it does not compare the URL's
requester key (`cpk`), relay, or encryption secret with server-held state. A
modified URL can therefore substitute any of those values. That risk is
accepted only for the controlled local demo and is not a production
authentication guarantee.
