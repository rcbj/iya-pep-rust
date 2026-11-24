# Where this table came from

`authzen_cases.json` is a byte-for-byte copy of `xacml-pep/authzen_cases.json` from [rcbj/iya-sts](https://github.com/rcbj/iya-sts) at commit `ddda62f44`. It is the AuthZEN mapping contract that the service's `authzen/authzen_map.ts` and the container PEP's `authzen_map.rs` are both held to. `tests/authzen_cases.rs` holds `src/authzen.rs` to it too, so all three map an evaluation the same way. **Never edit it here.** Take a newer copy deliberately and record its commit above.

**Licence:** this file is iya-sts's, and is not yet part of the MIT-licensed PEP corpus (`tests/corpus/`). Until iya-sts publishes it there, it is here under rcbj's own decision as copyright holder.
