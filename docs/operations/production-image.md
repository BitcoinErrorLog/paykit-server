# Production image (pinned)

This file records the immutable Paykit Server image connected on Railway
production and staging. The latest migration is **0027** (first-seen payment
facts).
Update it only in a release closeout PR after a successful deploy proof.

| Field | Value |
| --- | --- |
| Source SHA | `456148a6f1f3e5b892c4038546800a5a625cef8e` |
| Immutable image | `ghcr.io/bitcoinerrorlog/paykit-server@sha256:0c132b428ec45e37690ff3b1c70715e1ffdb1c178a960968b188bd8fb953f628` |
| GitHub Actions run | `36848751062` (`production-image.yml` on `master`) |
| Production deploy | `f6c0d17b-d6f2-4c25-a5c9-ced396c364b6` |
| Staging deploy | `3a13583c-b4f3-4f99-bb28-ca31c98ba79f` |
| Migration ledger | successful versions **1–27** |
| Public host | `https://paykit-shop.pubky.app` |
| Rollback digest (`d1692cb`, contains 0027) | `ghcr.io/bitcoinerrorlog/paykit-server@sha256:2841f719232deb4b28f87c0c4f12827938c6c26660a303a0267008d01d4f8e5e` |

The rollback digest has the same migration set as the current image, so
reconnecting it is a valid rollback. Rollback to any image older than **0027**
is not viable; recovery past that point is hotfix-forward only (see
[`docs/production-rehearsal.md`](../production-rehearsal.md)).
