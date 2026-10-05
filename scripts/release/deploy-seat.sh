#!/usr/bin/env bash
# Stop-then-start deploy of one Paykit Server seat (one process only).
# Procedure and rationale: docs/operations/deploy.md.
#
# Usage:
#   PAYKIT_SEATS_FILE=<seats.env> scripts/release/deploy-seat.sh [--dry-run] \
#     <staging|production> <ghcr.io/...@sha256:digest> <expected-live-digest> <source-sha> <evidence-dir>
#
# --dry-run runs every read-only preflight (deployment list, live-deployment
# selection, in-flight check, live digest, /health/ready) and exits before the
# stop. It changes nothing on Railway.
#
# Exit codes: 0 deployed and all checks passed (or dry-run preflight passed);
# 1 deployed but a post-check failed; 2 usage; 11 seat/target guard;
# 12 deployment list failed; 13 live deployment ambiguous or in-flight;
# 14 live digest mismatch; 15 stop not confirmed by Railway;
# 16 old process still answering; 20 new deployment FAILED or CRASHED;
# 17 observer lease unreadable; 21 image connect failed (seat down);
# 22 new deployment not SUCCESS in time (seat down).
set -uo pipefail

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then DRY_RUN=1; shift; fi
[ $# -eq 5 ] || { sed -n '2,19p' "$0" >&2; exit 2; }
SEAT="$1"; IMAGE="$2"; EXPECTED_LIVE="$3"; SOURCE_SHA="$4"; EV="$5"

HERE="$(cd "$(dirname "$0")" && pwd)"
SEATPY=(python3 "$HERE/railway_seat.py")

[[ "$IMAGE" =~ ^ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]] || { echo "ABORT image must be an immutable ghcr.io/...@sha256:<64 hex> reference"; exit 2; }
[[ "$EXPECTED_LIVE" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "ABORT expected-live-digest must be sha256:<64 hex>"; exit 2; }
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "ABORT source-sha must be the 40-char commit"; exit 2; }
[ -d "$EV" ] && [ -w "$EV" ] || { echo "ABORT evidence dir missing or not writable: $EV"; exit 2; }
: "${PAYKIT_SEATS_FILE:?PAYKIT_SEATS_FILE is required (seat ids; see docs/operations/deploy.md)}"
[ -f "$PAYKIT_SEATS_FILE" ] || { echo "ABORT seats file not found: $PAYKIT_SEATS_FILE"; exit 2; }

# shellcheck disable=SC1090
. "$PAYKIT_SEATS_FILE"
for v in STAGING_PROJECT_ID STAGING_ENVIRONMENT_ID STAGING_SERVICE_ID STAGING_HOST STAGING_DATABASE_SERVICE \
         PRODUCTION_PROJECT_ID PRODUCTION_ENVIRONMENT_ID PRODUCTION_SERVICE_ID PRODUCTION_HOST PRODUCTION_DATABASE_SERVICE; do
  [ -n "${!v:-}" ] || { echo "ABORT $v missing from $PAYKIT_SEATS_FILE"; exit 11; }
done
for s_id in "$STAGING_PROJECT_ID" "$STAGING_ENVIRONMENT_ID" "$STAGING_SERVICE_ID"; do
  case " $PRODUCTION_PROJECT_ID $PRODUCTION_ENVIRONMENT_ID $PRODUCTION_SERVICE_ID " in
    *" $s_id "*) echo "ABORT staging and production seats share id $s_id in $PAYKIT_SEATS_FILE"; exit 11;;
  esac
done
[ "$STAGING_HOST" != "$PRODUCTION_HOST" ] || { echo "ABORT staging host equals production host"; exit 11; }
# The Railway CLI honours these and would override the explicit -p/-e/-s flags.
unset RAILWAY_TOKEN RAILWAY_API_TOKEN RAILWAY_PROJECT_ID RAILWAY_ENVIRONMENT_ID RAILWAY_SERVICE_ID RAILWAY_ENVIRONMENT RAILWAY_SERVICE

case "$SEAT" in
  staging)
    P=$STAGING_PROJECT_ID; E=$STAGING_ENVIRONMENT_ID; S=$STAGING_SERVICE_ID; HOST=$STAGING_HOST; DB=$STAGING_DATABASE_SERVICE ;;
  production)
    P=$PRODUCTION_PROJECT_ID; E=$PRODUCTION_ENVIRONMENT_ID; S=$PRODUCTION_SERVICE_ID; HOST=$PRODUCTION_HOST; DB=$PRODUCTION_DATABASE_SERVICE ;;
  *) echo "ABORT seat must be staging or production"; exit 11 ;;
esac

export PATH="${PAYKIT_PG_CLIENT_BIN:-/opt/homebrew/opt/libpq/bin}:$PATH"
command -v psql >/dev/null || { echo "ABORT psql not found (set PAYKIT_PG_CLIENT_BIN)"; exit 2; }

deps() { railway deployment list -s "$S" -p "$P" -e "$E" --json; }
# Observer lease row as "holder|live|fence" (read-only SELECT through a Railway tunnel).
# Only the parsed row is kept: tunnel output is never written to evidence.
lease() {
  printf '%s\n' '\pset format unaligned' '\pset tuples_only on' \
    "SELECT holder, lease_until > now(), fence FROM observer_leadership WHERE name = 'observer';" \
    | railway connect "$DB" -p "$P" -e "$E" 2>/dev/null \
    | rg -o '^[0-9a-f-]{36}\|[tf]\|[0-9]+$' | tail -n 1
}
summ() { python3 -c '
import json,sys
for d in json.load(sys.stdin)[:4]:
    print(d.get("id"), d.get("status"), (d.get("meta") or {}).get("imageDigest"), d.get("createdAt"))'; }

echo "== $SEAT preflight $(date -u +%FT%TZ) dry_run=$DRY_RUN"
deps > "$EV/$SEAT-deployments-pre.json" || { echo "ABORT deployment list failed"; exit 12; }
summ < "$EV/$SEAT-deployments-pre.json"
PRE=$("${SEATPY[@]}" preflight "$EV/$SEAT-deployments-pre.json") || exit 13
read -r OLD OLD_DIGEST INFLIGHT <<<"$PRE"
echo "OLD=$OLD OLD_DIGEST=$OLD_DIGEST INFLIGHT=$INFLIGHT"
[ "$INFLIGHT" = 0 ] || { echo "ABORT in-flight deployment"; exit 13; }
[ "$OLD_DIGEST" = "$EXPECTED_LIVE" ] || { echo "ABORT live digest $OLD_DIGEST != $EXPECTED_LIVE"; exit 14; }
curl -sS -m 10 "$HOST/health/ready" > "$EV/$SEAT-health-pre.json"
echo "health-pre: $(head -c 200 "$EV/$SEAT-health-pre.json")"
python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("status")=="ready" else 1)' "$EV/$SEAT-health-pre.json" 2>/dev/null \
  || echo "WARN seat is not ready before the deploy (proceeding: a deploy may be the fix)"
LEASE_PRE=$(lease)
[ -n "$LEASE_PRE" ] || { echo "ABORT could not read the observer lease from $DB"; exit 17; }
echo "$LEASE_PRE" > "$EV/$SEAT-lease-pre.txt"
PRE_FENCE=${LEASE_PRE##*|}
echo "lease-pre: holder=${LEASE_PRE%%|*} live=$(cut -d'|' -f2 <<<"$LEASE_PRE") fence=$PRE_FENCE"

if [ "$DRY_RUN" = 1 ]; then
  echo "DRY-RUN OK seat=$SEAT lease fence $PRE_FENCE; would stop $OLD ($OLD_DIGEST), then connect $IMAGE"
  exit 0
fi

echo "== stop old $OLD $(date -u +%FT%TZ)"
"${SEATPY[@]}" stop "$OLD" | tee "$EV/$SEAT-stop.txt"
rg -q 'deploymentStop=true' "$EV/$SEAT-stop.txt" || { echo "ABORT deploymentStop not confirmed"; exit 15; }
# A stopped deployment keeps status SUCCESS; deploymentStopped plus a dead /health/live is the signal.
dead=0
for _ in $(seq 1 40); do
  ST=$("${SEATPY[@]}" stopped "$OLD" 2>/dev/null || echo error)
  code=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "$HOST/health/live" 2>/dev/null || true)
  echo "$(date +%H:%M:%S) old_stopped=$ST live=$code"
  if [ "$ST" = true ] && [ "$code" != 200 ]; then dead=$((dead+1)); else dead=0; fi
  [ $dead -ge 3 ] && break
  sleep 5
done
[ $dead -ge 3 ] || { echo "ABORT old deployment not confirmed stopped; rollback: reconnect $OLD_DIGEST"; exit 16; }
STOPPED_AT=$(date -u +%FT%TZ); echo "old stopped, confirmed at $STOPPED_AT"

echo "== connect $IMAGE"
if ! railway service source connect -p "$P" -e "$E" -s "$S" --image "$IMAGE" > "$EV/$SEAT-connect.log" 2>&1; then
  cat "$EV/$SEAT-connect.log"
  echo "RESULT connect failed; seat is DOWN (old stopped). Rollback: reconnect ${IMAGE%@*}@$OLD_DIGEST"; exit 21
fi
cat "$EV/$SEAT-connect.log"

NEW="-"; NEW_STATUS="-"; NEW_DIGEST="-"
for _ in $(seq 1 120); do
  deps > "$EV/$SEAT-deployments-poll.json" 2>/dev/null || { sleep 10; continue; }
  read -r NEW NEW_STATUS NEW_DIGEST <<<"$("${SEATPY[@]}" new "$EV/$SEAT-deployments-poll.json" "$OLD" "$STOPPED_AT")"
  echo "$(date +%H:%M:%S) new=$NEW $NEW_STATUS $NEW_DIGEST"
  case "$NEW_STATUS" in FAILED|CRASHED) echo "RESULT new deployment $NEW_STATUS; rollback: reconnect ${IMAGE%@*}@$OLD_DIGEST"; exit 20;; esac
  [ "$NEW_STATUS" = SUCCESS ] && break
  sleep 10
done
cp "$EV/$SEAT-deployments-poll.json" "$EV/$SEAT-deployments-post.json"
summ < "$EV/$SEAT-deployments-post.json"
[ "$NEW_STATUS" = SUCCESS ] || { echo "RESULT new deployment $NEW is $NEW_STATUS after 20 min; seat may be DOWN. Rollback: reconnect ${IMAGE%@*}@$OLD_DIGEST"; exit 22; }
fail=0
[ "$NEW_DIGEST" = "${IMAGE##*@}" ] || { echo "CHECK FAIL digest $NEW_DIGEST"; fail=1; }
RUNNING=$("${SEATPY[@]}" running "$EV/$SEAT-deployments-post.json" | awk '{print $1}' | tr '\n' ' ')
[ "$RUNNING" = "$NEW " ] && echo "CHECK PASS exactly one running deployment ($NEW)" || { echo "CHECK FAIL running deployments: ${RUNNING:-none}"; fail=1; }
[ "$("${SEATPY[@]}" stopped "$OLD")" = true ] && echo "CHECK PASS old deployment stays stopped" || { echo "CHECK FAIL old deployment not stopped"; fail=1; }

sleep 20
railway logs -s "$S" -p "$P" -e "$E" -d "$NEW" -n 300 > "$EV/$SEAT-logs-$NEW.txt" 2>&1
rg -i 'source_sha|migration|leadership|error|panic' "$EV/$SEAT-logs-$NEW.txt" | head -25 | tee "$EV/$SEAT-logs-hits.txt"
# The startup metadata line carries source_sha; serving is proven by /health/live below.
rg -q "\"source_sha\":\"$SOURCE_SHA\"" "$EV/$SEAT-logs-$NEW.txt" && echo "CHECK PASS source_sha in startup logs" || { echo "CHECK FAIL source_sha missing"; fail=1; }
# `railway logs` prefixes each line with its level, e.g. [ERROR].
if rg -qi '\[ERROR\]|"level":"ERROR"|panicked' "$EV/$SEAT-logs-$NEW.txt"; then echo "CHECK FAIL error lines in logs"; fail=1; else echo "CHECK PASS no ERROR/panic lines"; fi

for n in 1 2 3; do
  ok=0
  for _ in $(seq 1 18); do
    curl -sS -m 10 "$HOST/health/ready" > "$EV/$SEAT-health-post-$n.json" 2>/dev/null
    code_live=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' "$HOST/health/live")
    python3 - "$EV/$SEAT-health-post-$n.json" "$SEAT" "$code_live" <<'PY' && { ok=1; break; }
import json, sys
try:
    h = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
seat, live = sys.argv[2], sys.argv[3]
ok = (h.get("status") == "ready" and h.get("postgres") == "ready"
      and (h.get("electrum") or {}).get("available") is True
      and h.get("paykit_delivery") == "ready" and h.get("outbox") == "ready" and live == "200")
if seat == "production":
    ok = ok and str(h.get("stack_id", "")).startswith("production:") \
        and h.get("bitcoin_creation_enabled") is True and h.get("bitcoin_offer_available") is True
else:
    ok = ok and h.get("bitcoin_creation_enabled") is False
keys = {k: h.get(k) for k in ("status", "stack_id", "postgres", "paykit_delivery", "outbox",
                              "bitcoin_creation_enabled", "bitcoin_offer_available")}
print("CHECK PASS" if ok else "waiting", "health", keys,
      "electrum.available=", (h.get("electrum") or {}).get("available"), "live=", live)
sys.exit(0 if ok else 1)
PY
    sleep 10
  done
  [ $ok = 1 ] || { echo "CHECK FAIL health probe $n"; fail=1; }
  sleep 5
done
# A standby also passes /health/ready, so leadership is checked on the lease row:
# the new process must hold a live lease with a higher fence than before the stop.
# (The info-level "observer leadership acquired" line is filtered out of production logs.)
lease_ok=0
for _ in $(seq 1 30); do
  L=$(lease)
  echo "$(date +%H:%M:%S) lease=${L:-unreadable}"
  if [ -n "$L" ] && [ "$(cut -d'|' -f2 <<<"$L")" = t ] && [ "${L##*|}" -gt "$PRE_FENCE" ]; then lease_ok=1; break; fi
  sleep 10
done
echo "${L:-unreadable}" > "$EV/$SEAT-lease-post.txt"
[ $lease_ok = 1 ] && echo "CHECK PASS observer lease live with fence ${L##*|} > $PRE_FENCE" || { echo "CHECK FAIL observer lease not re-acquired (pre fence $PRE_FENCE, now ${L:-unreadable})"; fail=1; }
echo "RESULT seat=$SEAT new=$NEW old=$OLD digest=$NEW_DIGEST rollback=${IMAGE%@*}@$OLD_DIGEST fail=$fail"
exit $fail
