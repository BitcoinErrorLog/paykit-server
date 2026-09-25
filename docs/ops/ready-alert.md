# Paykit readiness alert

`paykit-ready-alert` is a Railway Cron service in the production Paykit project.
Its scheduled command is:

```text
paykit-ready-alert --url https://paykit-shop.pubky.app/health/ready --state-file /data/paykit-ready-alert-state.json
```

Schedule it every 60 seconds and attach a persistent Railway volume at `/data`.
The state file retains the five-minute terminal-transition window across cron
containers. The checker fails closed for unreachable endpoints, non-success
HTTP, malformed or unknown readiness fields, non-ready dependencies, and drift
from the deployed 20-attempt / 900-second link-establishment contract.

Set `ALERT_WEBHOOK_URL` on the Railway service. The value is provisioned by
John and must never be committed or printed. When it is absent the checker logs
`no webhook configured`, records its readiness decision, and exits normally;
this makes the missing value visible without preventing service startup.

`--check-only` performs a read-only readiness evaluation without writing the
sample store or delivering a webhook:

```text
paykit-ready-alert --url https://paykit-shop.pubky.app/health/ready --check-only
```

Deployment actions:

1. Create Railway Cron service `paykit-ready-alert` in the production Paykit
   project and schedule it for `* * * * *`.
2. Mount a persistent volume at `/data`.
3. John provisions `ALERT_WEBHOOK_URL`.
4. Send one synthetic critical decision and verify delivery before calling the
   alert operational.
