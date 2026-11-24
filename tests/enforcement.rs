// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The corpus's `enforcement.json` (section 7.2 as a table), held to the
//! embedded PEP's outcome. An embedded PEP is deny-biased whatever happens
//! (fail closed), so its column is `deny-biased`. And an Indeterminate is a
//! fault only over a processing or syntax error: over a missing attribute it
//! is an ordinary deny, as at the service.

#![cfg(feature = "local")]

use iya_pep::authzen::outcome;
use iya_pep::engine::{Decision, Obligation, Response, STATUS_OK};
use serde_json::Value;

fn decision(name: &str) -> Decision {
    match name {
        "Permit" => Decision::Permit,
        "Deny" => Decision::Deny,
        "NotApplicable" => Decision::NotApplicable,
        _ => Decision::Indeterminate,
    }
}

#[test]
fn every_row_of_the_table_is_enforced_deny_biased() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus/enforcement.json")).unwrap();
    let table: Value = serde_json::from_str(&text).unwrap();
    let cases = table["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    let mut wrong = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        let response = Response {
            decision: decision(case["decision"].as_str().unwrap()),
            obligations: case["obligations"].as_array().unwrap().iter().map(|o| Obligation { id: o.as_str().unwrap().into(), assignments: Vec::new() }).collect(),
            advice: Vec::new(),
            status_code: if case["decision"] == "Indeterminate" { "urn:oasis:names:tc:xacml:1.0:status:missing-attribute".into() } else { STATUS_OK.into() },
        };
        let got = outcome(&response, None, false);
        if got.decision != case["deny-biased"].as_bool().unwrap() {
            wrong.push(format!("case {i} ({case}): allowed {}", got.decision));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn only_a_processing_or_syntax_error_is_a_fault() {
    let indeterminate = |status: &str| Response { decision: Decision::Indeterminate, obligations: Vec::new(), advice: Vec::new(), status_code: status.into() };
    let missing = outcome(&indeterminate("urn:oasis:names:tc:xacml:1.0:status:missing-attribute"), None, false);
    assert!(!missing.decision && !missing.fault, "a missing attribute is an ordinary deny");
    for status in ["urn:oasis:names:tc:xacml:1.0:status:processing-error", "urn:oasis:names:tc:xacml:1.0:status:syntax-error"] {
        let got = outcome(&indeterminate(status), None, false);
        assert!(!got.decision && got.fault, "{status}");
    }
}
