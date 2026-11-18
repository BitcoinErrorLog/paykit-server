#!/bin/sh
set -eu

manifest=${1:-Cargo.toml}
lockfile=${2:-Cargo.lock}

sed -i \
    -e 's#locks-core = { git = "https://github.com/pubky/locks.git", tag = "v0.1.1-rc5" }#locks-core = { path = "/build/locks/locks-core" }#' \
    -e 's#paykit-lib = { git = "https://github.com/pubky/paykit-rs.git", tag = "v0.1.1-rc9" }#paykit-lib = { path = "/build/paykit-rs/paykit-lib" }#' \
    -e 's#paykit-sdk = { git = "https://github.com/pubky/paykit-rs.git", tag = "v0.1.1-rc9" }#paykit-sdk = { path = "/build/paykit-rs/paykit-sdk" }#' \
    "$manifest"

sed -i \
    -e '/source = "git+https:\/\/github.com\/pubky\/locks.git?tag=v0.1.1-rc5#34c308d6c190dfa7e4445e40f7f018cf88ba74fa"/d' \
    -e '/source = "git+https:\/\/github.com\/pubky\/paykit-rs.git?tag=v0.1.1-rc9#0b9c63d25dbd0cd5e7cf6ec577bc170732d350be"/d' \
    "$lockfile"

grep -Fx 'locks-core = { path = "/build/locks/locks-core" }' "$manifest"
grep -Fx 'paykit-lib = { path = "/build/paykit-rs/paykit-lib" }' "$manifest"
grep -Fx 'paykit-sdk = { path = "/build/paykit-rs/paykit-sdk" }' "$manifest"
! grep -Eq 'git = "https://github\.com/pubky/paykit-rs' "$manifest"
! grep -Eq 'git = "https://github\.com/pubky/locks' "$manifest"
! grep -Eq 'source = "git\+https://github\.com/pubky/paykit-rs' "$lockfile"
! grep -Eq 'source = "git\+https://github\.com/pubky/locks' "$lockfile"
