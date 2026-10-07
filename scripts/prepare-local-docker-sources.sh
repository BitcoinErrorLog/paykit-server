#!/bin/sh
set -eu

manifest=${1:-Cargo.toml}
lockfile=${2:-Cargo.lock}

sed -i \
    -e 's#locks-core = { git = "https://github.com/pubky/locks.git", tag = "v0.1.0-rc8" }#locks-core = { path = "/build/locks/locks-core" }#' \
    -e 's#paykit-lib = { git = "https://github.com/pubky/paykit-rs.git", tag = "v0.1.0-rc71" }#paykit-lib = { path = "/build/paykit-rs/paykit-lib" }#' \
    -e 's#paykit-sdk = { git = "https://github.com/pubky/paykit-rs.git", tag = "v0.1.0-rc71" }#paykit-sdk = { path = "/build/paykit-rs/paykit-sdk" }#' \
    "$manifest"

sed -i \
    -e '/source = "git+https:\/\/github.com\/pubky\/locks.git?tag=v0.1.0-rc8#b3dc87c961f6b907d76cde9c4a28f00670d5231e"/d' \
    -e '/source = "git+https:\/\/github.com\/pubky\/paykit-rs.git?tag=v0.1.0-rc71#e4e58d3ee6c6aa19d6262d4cd96a58890a65b6fa"/d' \
    "$lockfile"

grep -Fx 'locks-core = { path = "/build/locks/locks-core" }' "$manifest"
grep -Fx 'paykit-lib = { path = "/build/paykit-rs/paykit-lib" }' "$manifest"
grep -Fx 'paykit-sdk = { path = "/build/paykit-rs/paykit-sdk" }' "$manifest"
! grep -Eq 'git = "(ssh://git@github\.com/pubky/locks|https://github\.com/pubky/(locks|paykit-rs))' "$manifest"
! grep -Eq 'source = "git\+(ssh://git@github\.com/pubky/locks|https://github\.com/pubky/(locks|paykit-rs))' "$lockfile"
