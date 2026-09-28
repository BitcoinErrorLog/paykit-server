# Production image (pinned)

This file records the immutable Paykit Server image connected on Railway
production and staging after migration **0027** (first-seen payment facts).
Update it only in a release closeout PR after a successful deploy proof.

| Field | Value |
| --- | --- |
| Source SHA | `d1692cb278e97a088ab9070ca032720e176284b7` |
| Immutable image | `ghcr.io/bitcoinerrorlog/paykit-server@sha256:2841f719232deb4b28f87c0c4f12827938c6c26660a303a0267008d01d4f8e5e` |
| GitHub Actions run | `36459207533` (`production-image.yml` on `master`) |
| Production deploy | `70ad49d0-c378-4fe2-83a0-c00c2a1fa20c` |
| Staging deploy | `37a0966c-725f-4e16-a725-fdf8e9fca250` |
| Migration ledger | successful versions **1–27** |
| Public host | `https://paykit-shop.pubky.app` |
| Rollback digest (pre-0027) | `ghcr.io/bitcoinerrorlog/paykit-server@sha256:6a961c247920e8950eacb28dcca40ae42cccad4ffa7cacf3e21ec11d98e6360c` |

After **0027**, rollback to a pre-migration image is not viable; recovery is
hotfix-forward only (see [`docs/production-rehearsal.md`](../production-rehearsal.md)).
