#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
export LC_ALL=C

readonly EXPECTED_SOURCE_VERSIONS="1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23"
readonly EXPECTED_CLONE_VERSIONS="${EXPECTED_SOURCE_VERSIONS},24"
readonly CLONE_DATABASE="paykit_production_clone"
readonly CLONE_BOOTSTRAP_USER="clone_admin"

: "${RAILWAY_PROJECT_ID:?RAILWAY_PROJECT_ID is required}"
: "${RAILWAY_ENVIRONMENT:?RAILWAY_ENVIRONMENT is required}"
: "${RAILWAY_DATABASE_SERVICE:?RAILWAY_DATABASE_SERVICE is required}"

pg_client_bin="${PAYKIT_PG_CLIENT_BIN:-/opt/homebrew/opt/libpq/bin}"
pg_server_bin="${PAYKIT_PG_SERVER_BIN:-/opt/homebrew/opt/postgresql@18/bin}"
export PATH="$pg_client_bin:$pg_server_bin:$PATH"

for tool in railway python3 psql pg_dump pg_dumpall pg_restore initdb pg_ctl; do
  command -v "$tool" >/dev/null || {
    printf 'required tool is unavailable: %s\n' "$tool" >&2
    exit 1
  }
done

scratch="$(mktemp -d "${TMPDIR:-/tmp}/paykit-production-clone.XXXXXX")"
tunnel_pid=""
cluster_started=false
clone_target_dir="${CARGO_TARGET_DIR:-/Users/johncarvalho/work/.cargo-target/paykit-server}"

stop_process_tree() {
  local parent_pid=$1
  local child_pid
  while read -r child_pid; do
    [[ -n "$child_pid" ]] && stop_process_tree "$child_pid"
  done < <(pgrep -P "$parent_pid" 2>/dev/null || true)
  kill "$parent_pid" 2>/dev/null || true
}

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM
  if [[ -n "$tunnel_pid" ]] && kill -0 "$tunnel_pid" 2>/dev/null; then
    stop_process_tree "$tunnel_pid"
    wait "$tunnel_pid" 2>/dev/null || true
  fi
  if [[ "$cluster_started" == true ]]; then
    pg_ctl -D "$scratch/pgdata" -m immediate -w stop >/dev/null 2>&1 || true
  fi
  rm -rf "$scratch"
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

tunnel_log="$scratch/railway-tunnel.log"
: >"$tunnel_log"
chmod 0600 "$tunnel_log"
railway connect "$RAILWAY_DATABASE_SERVICE" \
  --project "$RAILWAY_PROJECT_ID" \
  --environment "$RAILWAY_ENVIRONMENT" \
  --tunnel-only >"$tunnel_log" 2>&1 &
tunnel_pid=$!

for _ in {1..120}; do
  if ! kill -0 "$tunnel_pid" 2>/dev/null; then
    printf 'Railway SSH database tunnel exited before becoming ready\n' >&2
    exit 1
  fi
  if python3 - "$tunnel_log" "$scratch" <<'PY'
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

text = Path(sys.argv[1]).read_text(errors="replace")
output_dir = Path(sys.argv[2])
text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
match = re.search(r"postgres(?:ql)?://[^\s]+", text)
if match is None:
    raise SystemExit(1)
url = urlsplit(match.group(0).rstrip(".,;"))
if not all((url.hostname, url.port, url.username, url.path.lstrip("/"))):
    raise SystemExit(1)
parts = {
    "source-host": url.hostname,
    "source-port": str(url.port),
    "source-user": unquote(url.username),
    "source-database": unquote(url.path.lstrip("/")),
}
for name, value in parts.items():
    (output_dir / name).write_text(value)
def pgpass_escape(value):
    return value.replace("\\", "\\\\").replace(":", "\\:")
(output_dir / "source.pgpass").write_text(":".join((
    pgpass_escape(url.hostname),
    str(url.port),
    pgpass_escape(unquote(url.path.lstrip("/"))),
    pgpass_escape(unquote(url.username)),
    pgpass_escape(unquote(url.password or "")),
)) + "\n")
PY
  then
    break
  fi
  sleep 0.5
done
if [[ ! -f "$scratch/source-database" ]]; then
  printf 'Railway SSH database tunnel did not expose parseable connection details\n' >&2
  exit 1
fi

source_host="$(<"$scratch/source-host")"
source_port="$(<"$scratch/source-port")"
source_user="$(<"$scratch/source-user")"
source_database="$(<"$scratch/source-database")"
chmod 0600 "$scratch/source.pgpass"
export PGPASSFILE="$scratch/source.pgpass"

source_server_version_num="$(
  psql -X -A -t -v ON_ERROR_STOP=1 \
    --host "$source_host" --port "$source_port" --username "$source_user" \
    --dbname "$source_database" --command "SHOW server_version_num"
)"
source_server_major=$((source_server_version_num / 10000))
dump_client_major="$(pg_dump --version | awk '{split($3, version, "."); print version[1]}')"
scratch_server_major="$(initdb --version | awk '{split($3, version, "."); print version[1]}')"
if [[ "$dump_client_major" != "$source_server_major" ]]; then
  printf 'pg_dump major %s does not match production PostgreSQL major %s\n' \
    "$dump_client_major" "$source_server_major" >&2
  exit 1
fi
if [[ "$scratch_server_major" != "$source_server_major" ]]; then
  printf 'local scratch PostgreSQL major %s does not match production major %s\n' \
    "$scratch_server_major" "$source_server_major" >&2
  exit 1
fi

source_versions="$(
  psql -X -A -t -v ON_ERROR_STOP=1 \
    --host "$source_host" --port "$source_port" --username "$source_user" \
    --dbname "$source_database" \
    --command "SELECT string_agg(version::text, ',' ORDER BY version)
                      || '|' || bool_and(success)::text
               FROM public._sqlx_migrations"
)"
if [[ "$source_versions" != "${EXPECTED_SOURCE_VERSIONS}|true" ]]; then
  printf 'production pre-image is not exactly successful migrations 1..23; refusing rehearsal\n' >&2
  exit 1
fi

roles_dump="$scratch/roles.sql"
schema_dump="$scratch/schema.dump"
migration_data_dump="$scratch/migration-data.dump"
pg_dumpall \
  --host "$source_host" --port "$source_port" --username "$source_user" \
  --database "$source_database" --roles-only --no-role-passwords >"$roles_dump"
pg_dump \
  --host "$source_host" --port "$source_port" --username "$source_user" \
  --dbname "$source_database" --format=custom --schema-only \
  --file "$schema_dump"
pg_dump \
  --host "$source_host" --port "$source_port" --username "$source_user" \
  --dbname "$source_database" --format=custom --data-only \
  --table public._sqlx_migrations --file "$migration_data_dump"
unset PGPASSFILE

if pg_restore --list "$schema_dump" |
  awk '$4 == "BLOB" ||
       ($4 == "TABLE" && $5 == "DATA") ||
       ($4 == "SEQUENCE" && $5 == "SET") { found = 1 }
       END { exit !found }'
then
  printf 'schema dump unexpectedly contains table data; refusing restore\n' >&2
  exit 1
fi
dumped_data_objects="$(
  pg_restore --list "$migration_data_dump" |
    awk '$4 == "TABLE" && $5 == "DATA" { print $6 "." $7 }'
)"
if [[ "$dumped_data_objects" != "public._sqlx_migrations" ]]; then
  printf 'data dump contains an object other than public._sqlx_migrations; refusing restore\n' >&2
  exit 1
fi
unset dumped_data_objects

initdb -D "$scratch/pgdata" --username="$CLONE_BOOTSTRAP_USER" \
  --auth-local=trust --auth-host=reject --no-instructions >"$scratch/initdb.log"
clone_port=5432
pg_ctl -D "$scratch/pgdata" -l "$scratch/postgres.log" -w start \
  -o "-h '' -k $scratch -p $clone_port"
cluster_started=true

psql -X -v ON_ERROR_STOP=1 --host "$scratch" --port "$clone_port" \
  --username "$CLONE_BOOTSTRAP_USER" --dbname postgres \
  --file "$roles_dump" >/dev/null
psql -X -v ON_ERROR_STOP=1 --host "$scratch" --port "$clone_port" \
  --username "$CLONE_BOOTSTRAP_USER" --dbname postgres \
  --command "CREATE DATABASE $CLONE_DATABASE" >/dev/null
pg_restore --exit-on-error --host "$scratch" --port "$clone_port" \
  --username "$CLONE_BOOTSTRAP_USER" --dbname "$CLONE_DATABASE" "$schema_dump"
pg_restore --exit-on-error --host "$scratch" --port "$clone_port" \
  --username "$CLONE_BOOTSTRAP_USER" --dbname "$CLONE_DATABASE" "$migration_data_dump"

encoded_socket="$(
  python3 -c 'from urllib.parse import quote; import sys; print(quote(sys.argv[1], safe=""))' \
    "$scratch"
)"
clone_url="postgresql://postgres@localhost/${CLONE_DATABASE}?host=${encoded_socket}&port=${clone_port}"
PAYKIT_CLONE_MIGRATOR_DATABASE_URL="$clone_url" \
PAYKIT_CLONE_RUNTIME_DATABASE_URL="$clone_url" \
CARGO_TARGET_DIR="$clone_target_dir" \
  cargo test --locked -p paykit-server-e2e --test production_clone \
    production_schema_clone_runs_real_startup_and_server_composition \
    -- --ignored --exact --nocapture
unset clone_url

clone_versions="$(
  psql -X -A -t -v ON_ERROR_STOP=1 --host "$scratch" --port "$clone_port" \
    --username postgres --dbname "$CLONE_DATABASE" \
    --command "SELECT string_agg(version::text, ',' ORDER BY version)
                      || '|' || bool_and(success)::text
               FROM public._sqlx_migrations"
)"
if [[ "$clone_versions" != "${EXPECTED_CLONE_VERSIONS}|true" ]]; then
  printf 'clone migration ledger is not exactly successful migrations 1..24\n' >&2
  exit 1
fi

role_and_grants="$(
  psql -X -A -t -v ON_ERROR_STOP=1 --host "$scratch" --port "$clone_port" \
    --username postgres --dbname "$CLONE_DATABASE" \
    --command "SELECT
      NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb
      AND NOT r.rolcreaterole AND NOT r.rolinherit AND NOT r.rolreplication
      AND NOT r.rolbypassrls
      AND has_schema_privilege('paykit', 'public', 'USAGE')
      AND has_table_privilege('paykit', 'public._sqlx_migrations', 'SELECT')
      AND has_column_privilege('paykit', 'public.outbox', 'handoff_invocation_token', 'SELECT')
      AND has_column_privilege('paykit', 'public.outbox', 'handoff_invocation_token', 'UPDATE')
      AND has_column_privilege('paykit', 'public.outbox', 'recovery_attempts', 'SELECT')
      AND has_column_privilege('paykit', 'public.outbox', 'recovery_attempts', 'UPDATE')
      AND has_column_privilege('paykit', 'public.outbox', 'recovery_first_at', 'SELECT')
      AND has_column_privilege('paykit', 'public.outbox', 'recovery_first_at', 'UPDATE')
      AND has_column_privilege('paykit', 'public.outbox', 'recovery_last_at', 'SELECT')
      AND has_column_privilege('paykit', 'public.outbox', 'recovery_last_at', 'UPDATE')
      AND has_column_privilege('paykit', 'public.sdk_outbound_invocations', 'creator_id', 'SELECT')
      AND has_column_privilege('paykit', 'public.sdk_outbound_invocations', 'creator_id', 'INSERT')
      AND has_column_privilege('paykit', 'public.sdk_outbound_invocations', 'sdk_outbound_message_id', 'SELECT')
      AND has_column_privilege('paykit', 'public.sdk_outbound_invocations', 'sdk_outbound_message_id', 'INSERT')
      AND has_column_privilege('paykit', 'public.sdk_outbound_invocations', 'invocation_token', 'SELECT')
      AND has_column_privilege('paykit', 'public.sdk_outbound_invocations', 'invocation_token', 'INSERT')
      AND NOT has_function_privilege(
        'paykit', 'public.reject_sdk_outbound_invocation_mutation()', 'EXECUTE'
      )
    FROM pg_catalog.pg_roles r WHERE r.rolname = 'paykit'"
)"
if [[ "$role_and_grants" != "t" ]]; then
  printf 'clone paykit role attributes or migration 0024 grants are invalid\n' >&2
  exit 1
fi

printf 'production-schema clone rehearsal passed without production mutation\n'
