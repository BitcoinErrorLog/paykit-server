# Local Locks demo image

`Dockerfile.local` packages Paykit Server for sibling Locks Compose stack. It is local/demo packaging, not production image.

## Build

Build from this repository with checked-out Paykit Rust and Locks source trees supplied as named BuildKit contexts:

```bash
docker buildx build --load \
  --build-context paykit-lib=../paykit-rs/paykit-lib \
  --build-context paykit-sdk=../paykit-rs/paykit-sdk \
  --build-context locks=../../Pubky/locks \
  -f Dockerfile.local \
  -t paykit-server:local .
```

Build uses exact local source-tree contents, including uncommitted source edits. Crate-level `paykit-lib` and `paykit-sdk` contexts avoid transferring Paykit Rust workspace target directory and require no Docker files in that repository. Locks context must exist and applies its existing source-tree exclusions.

Builder runs [`scripts/prepare-local-docker-sources.sh`](../scripts/prepare-local-docker-sources.sh) against copied manifests to resolve `paykit-lib`, `paykit-sdk`, and `locks-core` from named contexts. Committed Git dependency declarations and lockfile remain unchanged. No SSH agent or Cargo credentials are mounted. Exact dependency-pin matches make source drift fail closed.

## Runtime image

Final pinned Debian image:

- runs as unprivileged UID/GID `10001`;
- defaults to `/usr/local/bin/paykit-server` and exposes port `3001`;
- contains `/usr/local/bin/paykit-companion-auth` and `/usr/local/bin/paykit-reader-demo` for explicit Compose command/entrypoint overrides;
- adds CA certificates and three application binaries to pinned runtime base;
- contains no source tree, Cargo cache, runnable config, DB credentials, or application secrets.

Supply `PAYKIT_CONFIG`, `PAYKIT_DATABASE_URL`, and `PAYKIT_MASTER_KEY` at runtime. Mount generated ignored local config. Sibling Compose definition owns mounts, env values, infrastructure image pins, and helper command overrides.

## Generated local config contract

Sibling Locks orchestration generates `.local/paykit-server/config.toml` only after local Lock Server identity exists. Directory is Git-ignored. It must replace deliberately invalid `<ACTUAL_CANONICAL_LOCK_SERVER_PUBKY>` token below with exact canonical `pubky...` value exposed by Lock Server as `credentials.lock_server_public_key`. This block is not runnable config.

```toml
[http]
listen_addr = "0.0.0.0:3001"

[locks]
trusted_public_key = "<ACTUAL_CANONICAL_LOCK_SERVER_PUBKY>"

[setup]
allowed_origins = ["http://localhost:8080"]

[paykit]
receiver_path = "bitkit/server"
receiver_path_priority = ["bitkit"]
network = "testnet"

[bitcoin]
network = "regtest"

[deployment]
stack_role = "proof"

[electrum]
endpoint = "tcp://fulcrum:50001"
poll_interval = "1s"

[outbox]
poll_interval = "500ms"
```

File contains no DB URL or master key. Compose supplies those only through `PAYKIT_DATABASE_URL` and `PAYKIT_MASTER_KEY`, then points `PAYKIT_CONFIG` at mounted generated file. Parser rejects unknown top-level keys, unknown section keys, non-canonical trusted keys, and secrets placed in TOML. Production schema and defaults remain unchanged.
