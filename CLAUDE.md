# iya-pep-rust

The shared embedded PEP crate (`iya-pep`) for the Rust authentication libraries. The design and decisions are on rcbj/iya-sts#1206, decisions D1–D4.

- **It knows no sign-in protocol.** A library adapts its own identity into the crate's subject, verifies its SET stream, and checks that the PEP key differs from its own keys. The crate exposes its key's JWK thumbprint for that check.
- **`sts-xacml` in iya-sts is the reference engine.** The local engine must give the same decision on every case of the versioned conformance corpus (rcbj/iya-sts#2024), pinned here.
- **Fail closed.** With no policy held, or the service unreachable in `central` mode, the answer is `Unavailable`, never a Permit.
- **Tests run in the container:** `docker build --target test .`. Do not run Cargo on the host.
- **Branches:** work lands on `develop`, and `main` is the released branch. There is no publish workflow yet; add one, as in `oidc-caep-risc-rust`, with the first release.
