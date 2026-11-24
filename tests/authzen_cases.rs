// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! `src/authzen.rs` held to `tests/authzen/authzen_cases.json`, the table
//! iya-sts's `authzen/authzen_map.ts` (`tests/authzen_map.js` S) and the
//! container PEP's `authzen_map.rs` are held to, run the way the container
//! runs it.
//!
//! - `catalogue`: each value read as a row, accepted or refused with the
//!   case's code.
//! - `requests`: each body mapped through the table's `rows`, accepted or
//!   refused with the case's code (status 400), and, where the case names
//!   them, the supplied paths and the mapped attributes.
//! - `obligations`: each XACML answer mapped back under the case's profile
//!   switch and declaration: the decision, the types handed and the number
//!   of problems.
//! - `binding` is SKIPPED: it holds which tuples the service answers by the
//!   OAuth token-exchange binding's fixed rules (and the container answers
//!   501). An embedded PEP never evaluates a token-exchange gate, so the
//!   section has nothing here to hold.
//!
//! Every mismatch is collected and the test fails once, listing them all.

#![cfg(feature = "local")]

use iya_pep::authzen::{map_evaluation, outcome, Catalogue, Row, Trusted};
use iya_pep::engine::{Assignment, Decision, Obligation, Request, Response, STRING};
use serde_json::{json, Value};

const SUPPLIED: &str = "urn:sts:xacml:authzen:supplied";

/// The attributes the builder writes before the catalogue's rows.
const FIXED: [&str; 10] = [
    "urn:oasis:names:tc:xacml:1.0:subject:subject-id",
    "urn:sts:xacml:authzen:subject-type",
    "urn:oasis:names:tc:xacml:1.0:action:action-id",
    "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
    "urn:sts:xacml:authzen:resource-type",
    "urn:sts:xacml:protocol",
    "urn:sts:xacml:realm",
    "urn:sts:xacml:authzen:caller",
    "urn:sts:xacml:authzen:application",
    SUPPLIED,
];

fn table() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/authzen/authzen_cases.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("the table")).expect("the table is JSON")
}

/// The trusted facts the container's own test uses.
fn trusted() -> Trusted {
    Trusted { realm: "acme".into(), caller: "cn=pep-1,ou=users,dc=acme".into(), application: "portal".into() }
}

fn what(case: &Value) -> String {
    case["what"].as_str().unwrap_or("?").to_string()
}

fn supplied_of(request: &Request) -> Vec<String> {
    request
        .categories
        .iter()
        .flat_map(|c| &c.attributes)
        .filter(|a| a.attribute_id == SUPPLIED)
        .flat_map(|a| a.values.iter().map(|v| v.value.clone()))
        .collect()
}

/// The catalogue-mapped attributes, in request order.
fn mapped_of(request: &Request) -> Value {
    Value::Array(
        request
            .categories
            .iter()
            .flat_map(|c| &c.attributes)
            .filter(|a| !FIXED.contains(&a.attribute_id.as_str()))
            .map(|a| json!({ "attributeId": a.attribute_id, "values": a.values.iter().map(|v| v.value.clone()).collect::<Vec<_>>() }))
            .collect(),
    )
}

fn run_catalogue(table: &Value, failures: &mut Vec<String>) -> usize {
    let cases = table["catalogue"].as_array().expect("catalogue cases");
    let mut passed = 0;
    for case in cases {
        let got = match Row::read(&case["value"]) {
            Ok(_) => String::new(),
            Err(refusal) => refusal.code.to_string(),
        };
        let want = case["code"].as_str().unwrap_or("");
        if got == want {
            passed += 1;
        } else {
            failures.push(format!("catalogue {}: code {:?}, want {:?}", what(case), got, want));
        }
    }
    passed
}

fn run_requests(table: &Value, failures: &mut Vec<String>) -> usize {
    let rows: Vec<Row> = table["rows"].as_array().expect("rows").iter().map(|v| Row::read(v).expect("a table row reads")).collect();
    let catalogue = Catalogue { rows, obligations_profile: false };
    let cases = table["requests"].as_array().expect("request cases");
    let mut passed = 0;
    for case in cases {
        let before = failures.len();
        let mapped = map_evaluation(&case["body"], &catalogue, &trusted());
        let want = case["code"].as_str().unwrap_or("");
        match &mapped {
            Ok(_) if !want.is_empty() => failures.push(format!("request {}: accepted, want {}", what(case), want)),
            Err(r) if r.code != want => failures.push(format!("request {}: code {}, want {:?} ({})", what(case), r.code, want, r.message)),
            Err(r) if r.status != 400 => failures.push(format!("request {}: status {}, want 400", what(case), r.status)),
            _ => {}
        }
        if let Ok(mapped) = &mapped {
            if let Some(expected) = case.get("supplied") {
                let got = supplied_of(&mapped.request);
                if json!(got) != *expected {
                    failures.push(format!("request {}: supplied {:?}, want {}", what(case), got, expected));
                }
            }
            if let Some(expected) = case.get("attributes") {
                let got = mapped_of(&mapped.request);
                if got != *expected {
                    failures.push(format!("request {}: attributes {}, want {}", what(case), got, expected));
                }
            }
        }
        if failures.len() == before {
            passed += 1;
        }
    }
    passed
}

fn run_obligations(table: &Value, failures: &mut Vec<String>) -> usize {
    let cases = table["obligations"].as_array().expect("obligation cases");
    let mut passed = 0;
    for case in cases {
        let said = &case["answer"];
        let decision = match said["decision"].as_str() {
            Some("Permit") => Decision::Permit,
            Some("Deny") => Decision::Deny,
            Some("NotApplicable") => Decision::NotApplicable,
            _ => Decision::Indeterminate,
        };
        let obligations = said["obligations"]
            .as_array()
            .map(|list| {
                list.iter()
                    .map(|one| Obligation {
                        id: one["id"].as_str().unwrap_or("").to_string(),
                        assignments: one["assignments"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .map(|a| Assignment {
                                        attribute_id: a["attributeId"].as_str().unwrap_or("").to_string(),
                                        category: None,
                                        issuer: None,
                                        data_type: STRING.to_string(),
                                        value: a["value"].as_str().unwrap_or("").to_string(),
                                    })
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let response = Response { decision, obligations, advice: Vec::new() };
        let supported: Option<Vec<String>> = serde_json::from_value(case["supported"].clone()).expect("supported");
        let profile = case["profile"].as_bool().unwrap_or(false);
        let got = outcome(&response, supported.as_deref(), profile);
        let expect = &case["expect"];
        let handed: Vec<&str> = got.handed.iter().map(|h| h.kind.as_str()).collect();
        let want_handed: Vec<&str> = expect["handed"].as_array().map(|l| l.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        let mut wrong = Vec::new();
        if Some(got.decision) != expect["decision"].as_bool() {
            wrong.push(format!("decision {}, want {}", got.decision, expect["decision"]));
        }
        if handed != want_handed {
            wrong.push(format!("handed {:?}, want {:?}", handed, want_handed));
        }
        if Some(got.obligation_problems.len() as u64) != expect["problems"].as_u64() {
            wrong.push(format!("{} problem(s), want {}", got.obligation_problems.len(), expect["problems"]));
        }
        // Each handed object is the service's shape.
        for (i, h) in got.handed.iter().enumerate() {
            let o = &h.obligation;
            let shaped = o["id"] == json!(format!("obligation-{}", i + 1)) && o["type"] == json!(h.kind) && o["properties"].is_object();
            if !shaped {
                wrong.push(format!("handed object {} is not {{id, type, properties}}", o));
            }
        }
        if wrong.is_empty() {
            passed += 1;
        } else {
            failures.push(format!("obligations {}: {}", what(case), wrong.join("; ")));
        }
    }
    passed
}

#[test]
fn agrees_with_the_shared_authzen_table() {
    let table = table();
    let mut failures = Vec::new();
    let catalogue = run_catalogue(&table, &mut failures);
    let requests = run_requests(&table, &mut failures);
    let obligations = run_obligations(&table, &mut failures);
    eprintln!(
        "authzen_cases: catalogue {}/{}, requests {}/{}, obligations {}/{}; binding skipped (token exchange)",
        catalogue,
        table["catalogue"].as_array().map_or(0, Vec::len),
        requests,
        table["requests"].as_array().map_or(0, Vec::len),
        obligations,
        table["obligations"].as_array().map_or(0, Vec::len),
    );
    assert!(failures.is_empty(), "{} mismatch(es):\n{}", failures.len(), failures.join("\n"));
}

/// The handed step-up obligation as the service shapes it: a type's array
/// properties are arrays, a registered prefix is cut to the last segment.
#[test]
fn hands_a_step_up_in_the_services_shape() {
    let response = Response {
        decision: Decision::Permit,
        obligations: vec![Obligation {
            id: "urn:sts:xacml:authzen:obligation:step-up".into(),
            assignments: vec![
                Assignment { attribute_id: "urn:sts:xacml:authzen:acr_value".into(), category: None, issuer: None, data_type: STRING.into(), value: "urn:acr:loa2".into() },
                Assignment { attribute_id: "amr_values".into(), category: None, issuer: None, data_type: STRING.into(), value: "pwd".into() },
                Assignment { attribute_id: "amr_values".into(), category: None, issuer: None, data_type: STRING.into(), value: "otp".into() },
            ],
        }],
        advice: Vec::new(),
    };
    let got = outcome(&response, Some(&["step-up".to_string()]), true);
    assert!(got.decision && !got.fault);
    assert_eq!(
        got.handed[0].obligation,
        json!({ "id": "obligation-1", "type": "step-up", "properties": { "acr_value": "urn:acr:loa2", "amr_values": ["pwd", "otp"] } })
    );
    let refused = outcome(&response, Some(&["step-up".to_string()]), false);
    assert!(!refused.decision && refused.handed.is_empty());
    assert_eq!(refused.undischargeable, ["urn:sts:xacml:authzen:obligation:step-up"]);
}

/// The request in the builder's shape: category order, attribute order,
/// include_in_result, datatypes, and empty trusted facts left out.
#[test]
fn builds_the_request_the_container_builds() {
    let table = table();
    let rows: Vec<Row> = table["rows"].as_array().unwrap().iter().map(|v| Row::read(v).unwrap()).collect();
    let catalogue = Catalogue { rows, obligations_profile: false };
    let body = json!({
        "subject": { "type": "user", "id": "alice", "properties": { "clearance": 4 } },
        "action": { "name": "read" },
        "resource": { "type": "document", "id": "doc-1" },
        "context": { "application": "portal", "source_ip": "192.0.2.25" }
    });
    let mapped = map_evaluation(&body, &catalogue, &trusted()).unwrap();
    let request = &mapped.request;
    assert!(request.return_policy_id_list && !request.combined_decision);
    let order: Vec<(&str, Vec<&str>)> = request
        .categories
        .iter()
        .map(|c| (c.category.as_str(), c.attributes.iter().map(|a| a.attribute_id.as_str()).collect()))
        .collect();
    assert_eq!(
        order,
        vec![
            (
                "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject",
                vec!["urn:oasis:names:tc:xacml:1.0:subject:subject-id", "urn:sts:xacml:authzen:subject-type", "urn:example:clearance"]
            ),
            ("urn:oasis:names:tc:xacml:3.0:attribute-category:action", vec!["urn:oasis:names:tc:xacml:1.0:action:action-id"]),
            (
                "urn:oasis:names:tc:xacml:3.0:attribute-category:resource",
                vec!["urn:oasis:names:tc:xacml:1.0:resource:resource-id", "urn:sts:xacml:authzen:resource-type"]
            ),
            (
                "urn:oasis:names:tc:xacml:3.0:attribute-category:environment",
                vec![
                    "urn:sts:xacml:protocol",
                    "urn:sts:xacml:realm",
                    "urn:sts:xacml:authzen:caller",
                    "urn:sts:xacml:authzen:application",
                    SUPPLIED,
                    "urn:example:source-ip"
                ]
            ),
        ]
    );
    let all: Vec<_> = request.categories.iter().flat_map(|c| &c.attributes).collect();
    assert!(all.iter().all(|a| a.include_in_result && a.issuer.is_none()));
    let clearance = all.iter().find(|a| a.attribute_id == "urn:example:clearance").unwrap();
    assert_eq!(clearance.values[0].data_type, "http://www.w3.org/2001/XMLSchema#integer");
    assert_eq!(clearance.values[0].value, "4");

    let bare = Trusted { realm: String::new(), caller: "c".into(), application: String::new() };
    let body = json!({ "subject": { "type": "user", "id": "a" }, "action": { "name": "r" }, "resource": { "type": "d", "id": "1" } });
    let mapped = map_evaluation(&body, &catalogue, &bare).unwrap();
    let env = mapped.request.categories.iter().find(|c| c.category.ends_with(":environment")).unwrap();
    let realm = env.attributes.iter().find(|a| a.attribute_id == "urn:sts:xacml:realm").unwrap();
    assert!(realm.values.is_empty(), "an empty realm is an empty bag");

    // Another application than the bound one is outside this PEP's scope.
    let other = json!({ "subject": { "type": "user", "id": "a" }, "action": { "name": "r" },
                        "resource": { "type": "d", "id": "1" }, "context": { "application": "other" } });
    let refusal = map_evaluation(&other, &catalogue, &trusted()).unwrap_err();
    assert_eq!((refusal.status, refusal.code), (403, "STS-AUTHZEN-0025"));
}

/// A pulled catalogue keeps the first of two rows for one property, leaves
/// out a row its grammar refuses, and reads the profile switch.
#[test]
fn reads_a_pulled_catalogue() {
    let body = json!({
        "rows": [
            { "object": "resource", "property": "x", "attributeId": "u:1" },
            { "object": "resource", "property": "x", "attributeId": "u:2" },
            { "object": "subject", "property": "r", "attributeId": "urn:sts:xacml:role" }
        ],
        "settings": { "obligationsProfile": true }
    });
    let catalogue = Catalogue::from_pull(&body).unwrap();
    assert_eq!(catalogue.rows.len(), 1);
    assert_eq!(catalogue.rows[0].attribute_id, "u:1");
    assert!(catalogue.obligations_profile);
    assert!(!Catalogue::from_pull(&json!({ "rows": [] })).unwrap().obligations_profile);
    assert!(Catalogue::from_pull(&json!({})).is_err());
}
