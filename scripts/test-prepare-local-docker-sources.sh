#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-.}/paykit-local-sources.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

cat >"$tmp/Cargo.toml" <<'EOF'
[workspace.dependencies]
locks-core = { git = "https://github.com/pubky/locks.git", tag = "v0.1.1-rc5" }
paykit-lib = { git = "https://github.com/pubky/paykit-rs.git", tag = "v0.1.1-rc9" }
paykit-sdk = { git = "https://github.com/pubky/paykit-rs.git", tag = "v0.1.1-rc9" }
EOF

cat >"$tmp/Cargo.lock" <<'EOF'
[[package]]
name = "locks-core"
version = "0.1.1-rc5"
source = "git+https://github.com/pubky/locks.git?tag=v0.1.1-rc5#34c308d6c190dfa7e4445e40f7f018cf88ba74fa"

[[package]]
name = "paykit-lib"
version = "0.1.1-rc9"
source = "git+https://github.com/pubky/paykit-rs.git?tag=v0.1.1-rc9#0b9c63d25dbd0cd5e7cf6ec577bc170732d350be"

[[package]]
name = "paykit-sdk"
version = "0.1.1-rc9"
source = "git+https://github.com/pubky/paykit-rs.git?tag=v0.1.1-rc9#0b9c63d25dbd0cd5e7cf6ec577bc170732d350be"
EOF

sh "$root/scripts/prepare-local-docker-sources.sh" \
    "$tmp/Cargo.toml" "$tmp/Cargo.lock"

grep -Fx 'locks-core = { path = "/build/locks/locks-core" }' "$tmp/Cargo.toml"
grep -Fx 'paykit-lib = { path = "/build/paykit-rs/paykit-lib" }' "$tmp/Cargo.toml"
grep -Fx 'paykit-sdk = { path = "/build/paykit-rs/paykit-sdk" }' "$tmp/Cargo.toml"
! grep -Fq 'git+https://github.com/pubky/locks.git?tag=v0.1.1-rc5' "$tmp/Cargo.lock"
! grep -Fq 'git+https://github.com/pubky/paykit-rs.git' "$tmp/Cargo.lock"
