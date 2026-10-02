# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG RUST_IMAGE=rust:1.91.1-slim-bookworm@sha256:8514999d4786ef12efe89239e86b3d0a021b94b9d35108c8efe6c79ca7dc1a65
ARG RUNTIME_IMAGE=debian:bookworm-20260112-slim@sha256:56ff6d36d4eb3db13a741b342ec466f121480b5edded42e4b7ee850ce7a418ee

FROM ${RUST_IMAGE} AS builder
ENV RUSTUP_TOOLCHAIN=1.91.1
WORKDIR /build/paykit-server

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates git

COPY . /build/paykit-server

# locks-core, paykit-lib and paykit-sdk resolve from their pinned public git
# sources in Cargo.toml. Dockerfile.local rewrites them to path dependencies for
# local worktree builds; a published image must build the pinned revisions.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/paykit-server/target \
    cargo build --locked --release -p paykit-server --bin paykit-server && \
    install -Dm755 target/release/paykit-server /out/paykit-server

FROM ${RUNTIME_IMAGE} AS runtime
LABEL org.opencontainers.image.title="Paykit Server" \
      org.opencontainers.image.description="Receiver-side Paykit service for Locks invoice and Bitcoin settlement workflows" \
      org.opencontainers.image.source="https://github.com/pubky/paykit-server"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

RUN groupadd --system --gid 10001 paykit && \
    useradd --system --uid 10001 --gid paykit --create-home --home-dir /home/paykit paykit

COPY --from=builder /out/paykit-server /usr/local/bin/paykit-server

RUN set -eu; \
    test "$(/usr/local/bin/paykit-server 2>&1 >/dev/null || true)" = \
        'Error: PAYKIT_CONFIG is required'

USER paykit:paykit
WORKDIR /home/paykit
EXPOSE 3001
ENTRYPOINT ["/usr/local/bin/paykit-server"]
