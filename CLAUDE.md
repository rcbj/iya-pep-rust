# iya-pep-rust

The shared embedded PEP crate (`iya-pep`) for the Rust authentication libraries. The design and decisions are on rcbj/iya-sts#1206, decisions D1–D4.

- **It knows no sign-in protocol.** A library adapts its own identity into the crate's subject, verifies its SET stream, and checks that the PEP key differs from its own keys. The crate exposes its key's JWK thumbprint for that check.
- **`sts-xacml` in iya-sts is the reference engine.** The local engine must give the same decision on every case of the versioned conformance corpus (rcbj/iya-sts#2024), pinned in `tests/corpus/`. Never edit the corpus. A newer one is taken deliberately: update `PROVENANCE.md` and the two constants in `tests/corpus.rs`.
- **Both modes give one answer.** `src/authzen.rs` maps an evaluation through the realm's catalogue exactly as the service's `authzen_map.ts` and the container's `authzen_map.rs` do, held to `tests/authzen/authzen_cases.json`. A catalogue-undeclared subject property is never sent (STS-AUTHZEN-0004 at the service), so `central` pulls the catalogue too.
- **Fail closed.** With no policy held, or the service unreachable in `central` mode, the answer is `Unavailable`, never a Permit. An Indeterminate over a missing attribute is a Deny; over a processing or syntax error, `Unavailable`. A Permit carrying an obligation the host didn't declare is a Deny.
- **The engine's public types are a contract** with `src/local.rs` and `src/authzen.rs` (`src/engine/mod.rs`).
- **Not yet on the service:** the registration's `kind`, `application`, `mode` and `protocolVersion` (iya-sts#2026), `?scope=bound-application` (#2027), the event (#2028), and the heartbeat's `policyEvents` member. The crate follows the contract on #1206, and the stub PDP holds it to that contract.
- **Tests run in the container:** `docker build --target test .`. This runs the suite with every feature set, plus clippy with `-D warnings`. Don't run Cargo on the host.
- **Commits:** author `rcbjBlueMars <9321971+rcbjBlueMars@users.noreply.github.com>`, no Co-Authored-By trailer.
- **Branches:** work lands on `develop`, and `main` is the released branch. There is no publish workflow yet. Add one, as in `oidc-caep-risc-rust`, with the first release.
