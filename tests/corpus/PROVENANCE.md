# Where this corpus came from

A vendored copy of `xacml/pep-corpus/` from [rcbj/iya-sts](https://github.com/rcbj/iya-sts) at commit `58cc50f6a` (rcbj/iya-sts#2024). `README.md` beside this file is iya-sts's description of the format and of how a package compares its answers. **Nothing here is edited by hand.**

| Pinned | Value |
|---|---|
| `version` | 1 |
| `sha256` | `d28672aefda0f4c4d6135afce21ac32030b66f4502043d5ebc6f17351d31cc91` |

`tests/corpus.rs` fails when `MANIFEST.json` names another version or digest, or when a case's decision differs from the one expected. A newer corpus is taken deliberately: copy the directory again, update this table and the two constants in `tests/corpus.rs`.

## Licences

- **`oasis/`** is derived from the OASIS XACML 3.0 conformance suite, as adapted by AT&T and then by AuthzForce (OW2). It is **Apache-2.0**, like its source (`LICENSES/Apache-2.0.txt`). Under section 4(b) of that licence, each case is a modified form of its source: the policies are carried verbatim, the request was converted from `Request.xml` into the attribute form, and the expected answer is the reference engine's, checked against `Response.xml`. iya-sts's `xacml/conformance/PROVENANCE.md` records the chain in full.
- **`MANIFEST.json`, `enforcement.json`, `README.md` and this file** are MIT (`LICENSES/MIT.txt`).
