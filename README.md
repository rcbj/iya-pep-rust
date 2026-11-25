# iya-pep

The [iya-sts](https://github.com/rcbj/iya-sts) remote Policy Enforcement Point, embedded in a Rust application.

It is the shared PEP for the Rust authentication libraries: [`oidc-caep-risc`](https://github.com/rcbj/oidc-caep-risc-rust), [`saml2-sp`](https://github.com/rcbj/saml2-sp-rust), [`wsfed-caep`](https://github.com/rcbj/wsfed-caep-rust) and [`gnap-caep-risc`](https://github.com/rcbj/gnap-caep-risc-rust). Each library depends on it and enables it from its own configuration, so an application doesn't normally use this crate directly. The design is in [iya-sts #1206](https://github.com/rcbj/iya-sts/issues/1206).

## Modes

- **`central`:** every decision is an AuthZEN evaluation (`POST /access/v1/evaluation`) at iya-sts. An optional Permit cache (`permitCacheMs`, at most 60 s) is off by default.
- **`local`** (the `local` feature): a lightweight XACML 3.0 engine decides in process. It holds only the bound application's policies (`GET /xacml/pep/policies?scope=bound-application`) and the realm's AuthZEN catalogue. It refreshes them when a `pep-policies-changed` Shared Signals event arrives, at `fallbackPollMs` (5 minutes) otherwise, or at `pollIntervalMs` (15 s) when the host has no signal stream.

Both modes take the same AuthZEN-shaped request and give the same answer. `local` maps an evaluation through the catalogue exactly as the service does, and its engine is held to the service's conformance corpus.

## Use

```rust
use iya_pep::{Access, Decision, Mode, Pep, PepConfig, Subject};

let config = PepConfig::new("pep-orders", Mode::Local, "/etc/app/pep-key.pem",
    "https://sts.example/realm/shop", "orders");
let pep = Pep::new(config)?;
pep.start()?;

let subject = Subject::user("alice", claims);
match pep.decide(&subject, &Access::new("read", "order", "42")) {
    Decision::Permit { obligations, .. } => { /* discharge the obligations, then serve */ }
    Decision::Deny { why } => { /* 403 */ }
    Decision::Unavailable { why } => { /* 403: fail closed */ }
}
// Or let the PEP choose the status: 200 for a Permit, 403 for anything else.
let status = pep.decide(&subject, &access).http_status();

// From the host library's verified SET stream:
pep.on_policy_event(&event_payload);
```

- **The subject** is a claims map the host library builds from its own sign-in. Only the claims the realm's catalogue declares are sent, because the service refuses an evaluation that names any other.
- **`decide` never fails, and every failure is a 403.** No policy held yet, a service that can't be reached or answers badly, an engine fault, or a panic while deciding is `Unavailable`, never a Permit; `Decision::http_status()` is 403 for it as for a Deny (200 only for a Permit).
- **A cached Permit does not outlive an outage.** In `central` mode with `permitCacheMs`, a failed evaluation or a failed heartbeat drops every cached Permit, and none is served until the service answers an evaluation again.
- **Obligations:** a Permit carries only obligations of the types named in `supportedObligations`. Anything else turns the Permit into a Deny.

## The PEP's credential

The PEP has a key of its own: EC P-256, or RSA of 2048 bits or more. With it, the PEP:
- signs an RFC 7523 self-assertion through the `sts-remote-pep` client;
- gets a DPoP-bound token for each audience: `xacml:pep`, `xacml:pep-audit` and `authzen:evaluate`.

The key is certified, and the PEP bound to its application, with iya-sts's `issue-pep-credential`. `key_thumbprint()` lets the host library refuse a configuration where the PEP's key is one of its own. `reload_key()` reads a rotated key at once; otherwise the file is checked every 30 s.

## Configuration

`PepConfig::from_json` reads a library's `pep` section:

| Member | Default | |
|---|---|---|
| `name` | (required) | The PEP's service account. |
| `mode` | `local` | `local` (pull the bound application's policies and decide in process; needs the `local` feature) or `central` (ask the service for every decision). A build without the `local` feature that leaves `mode` out is refused with a message saying so. |
| `assertionKey` | (required) | The path of the PEP's private key, in PEM. |
| `clientId` | `sts-remote-pep` | |
| `pdpUrl` | the library's issuer | The service, with `/realm/<id>`. |
| `application` | the library's client | The application the PEP is bound to. |
| `pollIntervalMs` | 15000 | `local` without a signal stream. |
| `fallbackPollMs` | 300000 | `local` with one. |
| `heartbeatIntervalMs` | 30000 | |
| `decisionRecords` | true | `local`: each decision is sent to the service's audit log. |
| `permitCacheMs` | 0 | `central` only; at most 60000. |
| `signals` | false | The host hands over `pep-policies-changed` events. |
| `supportedObligations` | [] | Obligation types the application discharges. |
| `tlsCa` | | PEM trust anchors for the service. |
| `timeoutMs` | 10000 | |

## Features

- **`local`:** the engine and the policy pull. Without it, only `central` is compiled.
- **`tokio`:** `start_async`, `decide_async` and `stop_async`. These are `spawn_blocking` around the same calls, as in `oidc-caep-risc`.

## Tests

```sh
docker build --target test .
```

- **The engine:** it must match the reference engine on every case of the pinned corpus (`tests/corpus/`, iya-sts's `xacml/pep-corpus` version 1).
- **The AuthZEN mapping:** held to the table the service and the container PEP are held to (`tests/authzen/`).
- **Both modes and the control plane:** run against a stub PDP (`tests/central.rs`, `tests/local.rs`).

## License

MIT, in `LICENSE`. `tests/corpus/oasis/` is Apache-2.0 (`LICENSES/Apache-2.0.txt`). `tests/corpus/PROVENANCE.md` says why.
