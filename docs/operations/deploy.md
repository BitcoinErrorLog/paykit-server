# Deploying Paykit Server on Railway

Paykit Server runs as one process per seat (`README.md`, Known limitations:
"One process only"). Each seat (staging, production) is a Railway service that
runs a pinned GHCR image digest. The service has no repository trigger and no
`railway up` binding; never run `railway up` against it, because that rebinds the
service from the immutable digest to an upload build.

Deploys are **stop-then-start**: stop the running deployment, confirm the old
process is gone, then connect the new image. Always deploy staging first, then
production.

## Why stop-then-start

Readiness depends on observer leadership. A second replica is a non-leader and
never reports Electrum ready while the old leader holds the lease, so a
start-first (rolling) deploy fails Railway's healthcheck and deadlocks. Stopping
first costs about one minute with no process; that is cheaper than the deadlock.

The cost of stopping first is that a new image which fails at startup (for
example `postgres migration failed`) leaves the seat down until the previous
digest is reconnected. That happened once on production (about 7 minutes). The
script guards against it by recording the rollback digest before the stop,
checking startup logs, and printing the rollback image on every failure path.

## Railway quirk: a stopped deployment still says `SUCCESS`

After `deploymentStop`, `railway deployment list` keeps reporting the stopped
deployment as `SUCCESS` until Railway later marks it `REMOVED`. A status change
never arrives, so waiting for one hangs, and "exactly one `SUCCESS` deployment"
is not a valid way to find the live one. The live deployment is the `SUCCESS`
deployment whose GraphQL field `deploymentStopped` is `false`. The old process
is confirmed gone when `deploymentStopped` is `true` **and** `/health/live` stops
answering 200 on three consecutive probes.

## Prerequisites

- `railway` CLI logged in (`railway login`). The scripts read the CLI session
  token from `~/.railway/config.json` (`user.accessToken`, falling back to
  `user.token`) and never print it. GraphQL calls send a `User-Agent` header;
  without one Cloudflare answers 403 (error 1010).
- A seats file with the Railway ids and public hosts of both seats, passed as
  `PAYKIT_SEATS_FILE`. Keep it outside the repository. Required keys:
  `STAGING_PROJECT_ID`, `STAGING_ENVIRONMENT_ID`, `STAGING_SERVICE_ID`,
  `STAGING_HOST`, `PRODUCTION_PROJECT_ID`, `PRODUCTION_ENVIRONMENT_ID`,
  `PRODUCTION_SERVICE_ID`, `PRODUCTION_HOST`. The script refuses a staging run
  whose ids or host match production.
- `python3`, `curl`, `rg`.
- An evidence directory for the run's logs and JSON snapshots.

## Procedure

1. **Merge and publish.** Merge to `master`, then run the image workflow:
   `gh workflow run production-image.yml --repo BitcoinErrorLog/paykit-server --ref master`.
   Take the digest only from the run's `publish-evidence.json` artifact (field
   `.digest`) and confirm its `org.opencontainers.image.revision` label equals
   the 40-character source SHA.
2. **Rehearse migrations.** If the image contains a migration that production
   has not applied, run `scripts/rehearse-production-schema-clone.sh` first
   ([production-rehearsal.md](../production-rehearsal.md)). A failed or skipped
   rehearsal is a hard stop.
3. **Record the rollback digest.** The currently live digest is in
   [production-image.md](production-image.md); it is also printed by the dry run.
4. **Dry run each seat.** Read-only: lists deployments, selects the live
   deployment, checks nothing is in flight, checks the live digest, reads
   `/health/ready`.

   ```bash
   PAYKIT_SEATS_FILE=<seats.env> scripts/release/deploy-seat.sh --dry-run \
     staging ghcr.io/bitcoinerrorlog/paykit-server@sha256:<new> sha256:<live> <source-sha> <evidence-dir>
   ```

5. **Deploy staging**: the same command without `--dry-run`. The script stops
   the old deployment, waits until it is confirmed gone, connects the new image,
   waits for `SUCCESS`, then checks: new digest, exactly one running deployment,
   old deployment still stopped, source SHA and `listening` in the startup logs,
   no `[ERROR]`/panic lines, three `/health/ready` probes (staging expects
   `bitcoin_creation_enabled: false`), and observer leadership in the logs.
   Exit 0 means every check passed.
6. **Deploy production** the same way. Production health additionally requires
   a `production:` `stack_id`, `bitcoin_creation_enabled: true` and
   `bitcoin_offer_available: true`.
7. **Close out.** Update [production-image.md](production-image.md) (source SHA,
   digest, workflow run, deployment ids, migration ledger, rollback digest) in a
   release closeout PR. When a migration shipped, add its line to
   `paykit-server/migrations/APPLIED_CHECKSUMS.txt` in the same release.

## Exit codes

| Code | Meaning | Seat state |
| --- | --- | --- |
| 0 | Deployed, every check passed (or dry run passed) | New image live |
| 1 | Deployed, a post-check failed | New image live; read the `CHECK FAIL` lines |
| 2 | Usage or input error | Unchanged |
| 11 | Seat or target guard | Unchanged |
| 12 | Deployment list failed | Unchanged |
| 13 | Live deployment ambiguous, or a deployment in flight | Unchanged |
| 14 | Live digest differs from the expected one | Unchanged |
| 15 | Railway did not confirm the stop | Unknown: check the list and `/health/live` |
| 16 | Old process still answering after the stop | Old deployment may still be live |
| 20 | New deployment `FAILED` or `CRASHED` | **Down**: roll back |

## Rollback

Reconnect the recorded previous digest on the affected seat:

```bash
railway service source connect -p <project-id> -e <environment-id> -s <service-id> \
  --image ghcr.io/bitcoinerrorlog/paykit-server@sha256:<previous-digest>
```

Then run the post-checks by hand (`/health/ready`, startup logs). Rolling back to
an image older than the newest applied migration is not viable: the migrator
runs with `ignore_missing: false` (`paykit-server/src/persistence/migrations.rs`),
so an older binary refuses a database that has migrations it does not know, and
recovery past that point is a forward fix ([production-image.md](production-image.md)).

Applied migrations are immutable, including comments: sqlx checksums every
applied file, and changing one byte makes the next start fail with
`postgres migration failed`. Put notes in `docs/` or in a new migration.

## Tests

`python3 scripts/release/test_railway_seat.py` covers live-deployment selection
(including the two-`SUCCESS` state after a stop), in-flight detection, new
deployment detection, and token lookup.
