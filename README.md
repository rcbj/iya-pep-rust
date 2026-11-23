# iya-pep

The [iya-sts](https://github.com/rcbj/iya-sts) remote Policy Enforcement Point, embedded in a Rust application.

It is the shared PEP for the Rust authentication libraries: [`oidc-caep-risc`](https://github.com/rcbj/oidc-caep-risc-rust), [`saml2-sp`](https://github.com/rcbj/saml2-sp-rust), [`wsfed-caep`](https://github.com/rcbj/wsfed-caep-rust) and [`gnap-caep-risc`](https://github.com/rcbj/gnap-caep-risc-rust). Each library depends on it and enables it through its own configuration. An application does not normally use this crate directly.

**Status: not implemented yet.** The design is in [iya-sts #1206](https://github.com/rcbj/iya-sts/issues/1206).

## Modes

- `central`: every decision is an AuthZEN evaluation at iya-sts.
- `local` (the `local` feature): a lightweight XACML 3.0 engine decides in process. It uses only the policies relevant to the bound application, pulled from iya-sts and refreshed when a `pep-policies-changed` Shared Signals event arrives.

## Tests

```sh
docker build --target test .
```

## License

MIT. See `LICENSE`.
