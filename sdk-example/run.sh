#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
compose=(docker compose --project-name "paykit-sdk-example-$$" --file sdk-example/docker-compose.yml)

cleanup() {
  local result=$?
  if (( result != 0 )); then
    "${compose[@]}" logs --tail=30 >&2 || true
  fi
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Compile before starting disposable services. No credentials or identities are saved.
cargo build --locked -p paykit-server-e2e --example sdk-payment
"${compose[@]}" up --detach --wait --wait-timeout 120

port() {
  local address
  address=$("${compose[@]}" port "$1" "$2")
  printf '%s' "${address##*:}"
}

export TEST_DATABASE_URL="postgres://postgres:example@127.0.0.1:$(port postgres 5432)/postgres"
export EXAMPLE_BITCOIN_RPC="http://127.0.0.1:$(port bitcoin 18443)"
export EXAMPLE_ELECTRUM="tcp://127.0.0.1:$(port electrs 50001)"
cargo run --locked -p paykit-server-e2e --example sdk-payment
