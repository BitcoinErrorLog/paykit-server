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
PAYKIT_MIGRATOR_DATABASE_URL
PAYKIT_MASTER_KEY
```

The current production database is in a two-step runtime-login transition.
For the image containing migration 0024, both `PAYKIT_DATABASE_URL` and
`PAYKIT_MIGRATOR_DATABASE_URL` continue to authenticate as `postgres`.
Migration 0024 idempotently creates the stable `paykit` group role as
`NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
NOBYPASSRLS` when it is absent, then installs the fenced-path grants. If that
role already exists, the migration does not alter its credentials or
attributes.

This image does **not** perform the runtime credential cutover. A later,
separately approved operation must create a LOGIN role, grant membership in
the `paykit` group, and change only `PAYKIT_DATABASE_URL` to that LOGIN
principal. Do not create credentials or change either production URL during
the 0024 migration deployment. Missing or malformed URLs still fail
configuration before any database connection or HTTP bind.

The rendered TOML must set `bitcoin.creation_enabled = false` for the first
boot. Omit the field only when the fail-closed default is intended; omitted
configuration is also disabled. Creation-enabled environments must set this
field to `true` explicitly. Do not add a second creation switch.

## First boot sequence

1. Use one production image digest, one single-replica deployment, and a
   dedicated PostgreSQL database.
2. Confirm PostgreSQL PITR is enabled and a restore has been exercised before
   any creation-enabled cutover.
3. Start the binary with the rendered config. Startup connects through
   `PAYKIT_MIGRATOR_DATABASE_URL`, applies the image's release-pinned
   migrations under the migration advisory lock, and closes that privileged
   pool. A migration connection or application failure aborts startup.
4. Startup then reconnects through `PAYKIT_DATABASE_URL`, verifies the exact
   migration set read-only, validates deployment invariants, authenticates
   persisted state, and only then binds HTTP. Only this runtime pool is passed
   to the server and workers. In this transitional image that URL still uses
   `postgres`; after the separately approved LOGIN-member cutover it is the
   restricted runtime connection.
5. Verify `GET /health/live` and `GET /health/ready`. Record the exact image
   digest, `SOURCE_SHA`, and `stack_id` from the deployment and startup
   evidence.
6. Verify the public Electrum endpoint is exactly
   `ssl://bitkit.to:9999`; do not place credentials in this runbook.
7. Complete the W1.10 cutover checklist and signed `prepare`, `activate`,
   `void`, and `resolve` gates while creation remains disabled.
8. After parent approval, run one exclusive seller canary. Do not add a
   second seller or enable general creation as part of this rehearsal.

## Production-schema clone gate for migration 0024

Before deploying the image, run the read-only pre-image proof through the
Railway SSH database connection:

```bash
railway connect "$RAILWAY_DATABASE_SERVICE" \
  --project "$RAILWAY_PROJECT_ID" \
  --environment "$RAILWAY_ENVIRONMENT" --ssh
```

Then run this exact query in the opened `psql` session:

```sql
SELECT
    array_agg(version ORDER BY version) AS versions,
    count(*) = 23
        AND min(version) = 1
        AND max(version) = 23
        AND bool_and(success) AS exact_successful_1_through_23
FROM public._sqlx_migrations;
```

The only acceptable result is the array containing every integer from 1
through 23 exactly once and `exact_successful_1_through_23 = t`. Any missing,
failed, duplicate, additional, or version-24 row blocks the rehearsal and
deployment.

With `RAILWAY_PROJECT_ID`, `RAILWAY_ENVIRONMENT`, and
`RAILWAY_DATABASE_SERVICE` set to the reviewed production targets, run:

```bash
scripts/rehearse-production-schema-clone.sh
```

The script defaults `CARGO_TARGET_DIR` to the shared low-disk build cache used
by the release worker. Set `CARGO_TARGET_DIR` explicitly when running on
another machine.

The script opens a Railway SSH tunnel and captures any connection details in
a mode-0600 scratch file that it never prints. It takes a roles-only dump with
role passwords omitted, a schema-only dump, and a data-only dump restricted to
`public._sqlx_migrations`. It rejects any schema dump containing table data,
any data dump containing an object other than the migration ledger, and any
source ledger other than successful versions 1–23.

The dumps are restored into a fresh disposable local PostgreSQL cluster whose
bootstrap superuser is `clone_admin`, not `postgres`. That distinction is
required: the roles-only production dump must be able to restore the
production `postgres` role without colliding with the bootstrap role. The
rehearsal then invokes real `initialize_database`, which validates embedded
checksums for migrations 1–23 and applies 0024, and boots the real `Server`
composition. For this transitional image, both clone URLs deliberately
authenticate as the restored `postgres` role. The gate asserts migration
versions 1–24, the restricted NOLOGIN `paykit` role, and every 0024 grant.
Traps stop the tunnel and local PostgreSQL process and delete all scratch data.
It never mutates production.

“Full migration set 0001→0024 on a production-schema clone” does not mean
replaying migration 0001 over existing objects. The clone already contains
the objects produced by migrations 0001–0023 and restores only their real
`_sqlx_migrations` metadata. The real migrator checks those embedded
checksums, then applies only pending migration 0024. Replaying 0001 against
the cloned schema would collide with existing objects and would not faithfully
exercise an upgrade from the production pre-image.

The two cluster-role migration tests must run against a dedicated disposable
PostgreSQL cluster because they intentionally drop or alter the cluster-wide
`paykit` role. They are ignored by the shared-database suite. The focused
isolated-cluster gate is:

```bash
TEST_DATABASE_URL=postgresql://<isolated-admin>@127.0.0.1:<port>/postgres \
CARGO_TARGET_DIR=/Users/johncarvalho/work/.cargo-target/paykit-server \
cargo test --locked -p paykit-server-e2e --test migrations \
  migration_0024_ -- --include-ignored --test-threads=1
```

## Health interpretation

`/health/live` proves only that the process is serving. `/health/ready` must
be checked after migrations and dependency probes; a non-200 response blocks
the rehearsal and the canary.

The image intentionally has no Docker `HEALTHCHECK`; Railway (or the selected
deployment platform) must configure `/health/ready` as the service health
probe, and the final rehearsal must prove that probe succeeds.
