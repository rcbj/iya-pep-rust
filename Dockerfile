# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test .` runs the suite. Do not run Cargo on the host.
FROM rust:1-bookworm AS test
WORKDIR /src
COPY . .
RUN rustup component add clippy \
 && cargo test --all-features \
 && cargo test \
 && cargo test --no-default-features --features rustls,local \
 && cargo clippy --all-features --all-targets -- -D warnings \
 && cargo clippy --all-targets -- -D warnings \
 && cargo clippy --no-default-features --features rustls --all-targets -- -D warnings \
 && cargo build --lib \
 && cargo tree --no-default-features --features rustls,local -e normal | (! grep -E "openssl|native-tls")
