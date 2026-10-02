# Contributing to Paykit Server

Paykit Server is pre-production. Small, focused changes with explicit verification are preferred over broad refactors or compatibility layers for unreleased behavior.

## Prerequisites

- Git
- the Rust toolchain pinned by `rust-toolchain.toml`
- PostgreSQL for database-backed E2E tests
- Docker with BuildKit only for the optional local Locks demo image

All Git dependencies are pinned and anonymously readable over HTTPS.

## Setup

```bash
git clone https://github.com/pubky/paykit-server.git
cd paykit-server
cargo check --locked
```

Copy `config/paykit-server.example.toml` to an operator-controlled path only when running the service. Never commit a populated local config, `.env` file, database URL, master key, account xpub, Pubky session material, or generated state.

## Tests and checks

Run the deterministic package checks before opening a pull request:

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked -p paykit-server -- --test-threads=1
cargo test --locked -p paykit-server-e2e --no-run
git diff --check
```

The server suite is intentionally serialized because subprocess deadline tests can become load-sensitive under parallel execution.

Database-backed E2E tests create and drop isolated databases. `TEST_DATABASE_URL` must point to a PostgreSQL database whose role may create databases:

```bash
TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
  cargo test --locked -p paykit-server-e2e -- --test-threads=1
```

Two live-adapter tests are ignored by default. They require external Pubky or Electrum infrastructure and are documented in `docs/live-adapter-smoke.md`. Do not claim those paths passed unless they were run explicitly against the documented environment.

## Continuous integration

CI runs for every pull request and for pushes merged to `master`. Other branch pushes run through their pull request rather than triggering a duplicate workflow. Superseded pull-request runs are cancelled; every `master` run completes.

The four required checks are independent and run these exact commands:

- **Formatting:** `cargo fmt --all --check`
- **Clippy:** `cargo clippy --locked --workspace --all-targets -- -D warnings`
- **Server tests:** `cargo test --locked -p paykit-server -- --test-threads=1`
- **PostgreSQL E2E:** `cargo test --locked -p paykit-server-e2e -- --test-threads=1`

The E2E check executes against PostgreSQL; it is not a compile-only gate. Rust build caches accelerate Clippy and tests, but cache failures fall back to cold builds and do not weaken any required check. CI does not automatically retry failed tests or jobs: reproducible flakes must be fixed at their source.

## Pull requests

- Keep each pull request coherent and reviewable.
- Explain the behavior or contract being changed and why.
- Include reproduction and regression evidence for bug fixes where practical.
- State exactly which checks were run and which external checks were unavailable.
- Add tests for behavior changes.
- Update README, configuration examples, rustdoc, and active documentation when their contracts change.
- Avoid drive-by formatting, renames, dependency updates, and unrelated cleanup.
- Do not weaken validation or persistence invariants to accept drift from pre-production branches.

All CI checks must pass unless a reviewer explicitly accepts and records the risk. Authors should not self-merge; human reviewers remain accountable for changes produced with AI assistance.

## Security

Follow `SECURITY.md`. Never include vulnerability details or sensitive operational material in a public issue or pull request.
