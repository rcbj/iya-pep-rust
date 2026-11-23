# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test .` runs the suite. Do not run Cargo on the host.
FROM rust:1-bookworm AS test
WORKDIR /src
COPY . .
RUN cargo test --all-features && cargo test --no-default-features && cargo build --lib
