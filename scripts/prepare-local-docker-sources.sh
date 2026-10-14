#!/bin/sh
set -eu

manifest=${1:-Cargo.toml}
lockfile=${2:-Cargo.lock}

sed -i \
    -e 's#locks-core = { git = "https://github.com/pubky/locks.git", tag = "v0.1.0-rc13" }#locks-core = { path = "/build/locks/locks-core" }#' \
    -e 's#paykit-lib = { git = "https://github.com/pubky/paykit-rs.git", rev = "03d4f05721e92d3944cb4d5af4b2c98c4390a5a8" }#paykit-lib = { path = "/build/paykit-rs/paykit-lib" }#' \
    -e 's#paykit-sdk = { git = "https://github.com/pubky/paykit-rs.git", rev = "03d4f05721e92d3944cb4d5af4b2c98c4390a5a8" }#paykit-sdk = { path = "/build/paykit-rs/paykit-sdk" }#' \
    "$manifest"

sed -i \
    -e '/source = "git+https:\/\/github.com\/pubky\/locks.git?tag=v0.1.0-rc13#5e5ed00463688046716d2fb1022eecd9c8997b56"/d' \
    -e '/source = "git+https:\/\/github.com\/pubky\/paykit-rs.git?rev=03d4f05721e92d3944cb4d5af4b2c98c4390a5a8#03d4f05721e92d3944cb4d5af4b2c98c4390a5a8"/d' \
    "$lockfile"

grep -Fx 'locks-core = { path = "/build/locks/locks-core" }' "$manifest"
grep -Fx 'paykit-lib = { path = "/build/paykit-rs/paykit-lib" }' "$manifest"
grep -Fx 'paykit-sdk = { path = "/build/paykit-rs/paykit-sdk" }' "$manifest"
! grep -Eq 'git = "(ssh://git@github\.com/pubky/locks|https://github\.com/pubky/(locks|paykit-rs))' "$manifest"
! grep -Eq 'source = "git\+(ssh://git@github\.com/pubky/locks|https://github\.com/pubky/(locks|paykit-rs))' "$lockfile"
