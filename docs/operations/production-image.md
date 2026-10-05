# Production image (pinned)

This file records the immutable Paykit Server image connected on Railway
production and staging. The latest migration is **0027** (first-seen payment
facts).
Update it only in a release closeout PR after a successful deploy proof.
Deploy procedure and rollback: [deploy.md](deploy.md).

| Field | Value |
| --- | --- |
| Source SHA | `aa53f66404a2551c89ebfc202dee756401c376ff` |
| Immutable image | `ghcr.io/bitcoinerrorlog/paykit-server@sha256:ea6065aa4a04d6206d2f0e1805b9b1190a5175d6d6746cb3fe1e709dbc8c0b96` |
| GitHub Actions run | `37292813791` (`production-image.yml` on `master`) |
| Production deploy | `a303173e-e689-4f4b-85ff-5980faa205f8` |
| Staging deploy | `c48a8ef6-05ce-4fdd-93a0-05c3418c2410` |
| Migration ledger | successful versions **1–27** |
| Public host | `https://paykit-shop.pubky.app` |
| Rollback digest (`456148a`, contains 0027) | `ghcr.io/bitcoinerrorlog/paykit-server@sha256:0c132b428ec45e37690ff3b1c70715e1ffdb1c178a960968b188bd8fb953f628` |

The rollback digest has the same migration set as the current image, so
reconnecting it is a valid rollback. Rollback to any image older than **0027**
is not viable; recovery past that point is hotfix-forward only (see
[`docs/production-rehearsal.md`](../production-rehearsal.md)).
