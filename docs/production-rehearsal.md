# Paykit Server production-image rehearsal

This runbook is for the first creation-disabled rehearsal of the production
image. It does not create Railway resources, publish an image, or enable
Bitcoin creation.

## Image and startup contract

Build the checked-out commit with `Dockerfile.production` and a full
40-character `SOURCE_SHA`. The resulting image must be recorded by digest:

```text
ghcr.io/bitcoinerrorlog/paykit-server@sha256:<digest>
SOURCE_SHA=<40-hex-commit>
```

The publish workflow is dispatchable only from the protected canonical
`master` branch. Production consumes the pushed `image@sha256:<digest>`; the
convenience `sha-<SOURCE_SHA>` tag is not a deployment reference.

The binary logs one JSON startup event containing `source_sha`, package
`version`, `network`, `role`, and `stack_id`. It must not contain credentials,
database URLs, master keys, or private key material. Capture that event and
the image digest as the deployment evidence.

The listener is configured by the TOML file's `http.listen_addr`; this image
does not interpret Railway `$PORT`. Render the complete TOML configuration
before starting the binary. The production listener should be
`0.0.0.0:3001` unless the parent deployment configuration explicitly renders
another port.

## Named configuration inputs

The deployment system supplies these names only; values belong in the
deployment secret/config store and must not be committed:

```text
PAYKIT_CONFIG
PAYKIT_DATABASE_URL
PAYKIT_MASTER_KEY
```

The rendered TOML must set `bitcoin.creation_enabled = false` for the first
boot. Omit the field only when the fail-closed default is intended; omitted
configuration is also disabled. Creation-enabled environments must set this
field to `true` explicitly. Do not add a second creation switch.

## First boot sequence

1. Use one production image digest, one single-replica deployment, and a
   dedicated PostgreSQL database.
2. Confirm PostgreSQL PITR is enabled and a restore has been exercised before
   any creation-enabled cutover.
3. Start the binary with the rendered config. Startup applies migrations,
   validates deployment invariants, authenticates persisted state, and only
   then binds HTTP.
4. Verify `GET /health/live` and `GET /health/ready`. Record the exact image
   digest, `SOURCE_SHA`, and `stack_id` from the deployment and startup
   evidence.
5. Verify the public Electrum endpoint is exactly
   `ssl://bitkit.to:9999`; do not place credentials in this runbook.
6. Complete the W1.10 cutover checklist and signed `prepare`, `activate`,
   `void`, and `resolve` gates while creation remains disabled.
7. After parent approval, run one exclusive seller canary. Do not add a
   second seller or enable general creation as part of this rehearsal.

## Health interpretation

`/health/live` proves only that the process is serving. `/health/ready` must
be checked after migrations and dependency probes; a non-200 response blocks
the rehearsal and the canary.

The image intentionally has no Docker `HEALTHCHECK`; Railway (or the selected
deployment platform) must configure `/health/ready` as the service health
probe, and the final rehearsal must prove that probe succeeds.
