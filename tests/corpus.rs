// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The pinned conformance corpus (rcbj/iya-sts#2024): every OASIS case must
//! get the reference engine's answer. `tests/corpus/README.md` is the format
//! and the comparison rules.
//!
//! Every mismatch is collected and the test fails once, listing them all.
//! Assignment values are compared by their canonical lexical form, which
//! the engine writes exactly as the reference engine does.

#![cfg(feature = "local")]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use iya_pep::engine::{
    Assignment, Attribute, AttributeValue, Category, Decision, NoResolver, Obligation, Policies, PolicyDocument,
    Request,
};
use serde_json::Value;

/// The corpus version and digest this crate pinned. Take a newer corpus
/// deliberately, by changing both.
const CORPUS_VERSION: u64 = 1;
const CORPUS_SHA256: &str = "d28672aefda0f4c4d6135afce21ac32030b66f4502043d5ebc6f17351d31cc91";

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

fn read_json(path: &Path) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{} is not JSON: {}", path.display(), e))
}

fn manifest() -> Value {
    read_json(&corpus().join("MANIFEST.json"))
}

fn case_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(corpus().join("oasis"))
        .expect("tests/corpus/oasis is readable")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    files.sort();
    files
}

/// `YYYY-MM-DDTHH:MM:SSZ`, the manifest's form of `now`.
fn instant(text: &str) -> SystemTime {
    let number = |range: std::ops::Range<usize>| -> i64 {
        text.get(range).and_then(|s| s.parse().ok()).unwrap_or_else(|| panic!("now is not a UTC instant: {}", text))
    };
    assert!(text.len() == 20 && text.ends_with('Z'), "now is not a UTC instant: {}", text);
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    let seconds = days * 86_400 + number(11..13) * 3600 + number(14..16) * 60 + number(17..19);
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).expect("now is after 1970"))
}

fn string(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or_else(|| panic!("missing string {}", key)).to_string()
}

fn optional(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

fn array<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v[key].as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn policies(case: &Value) -> Vec<PolicyDocument> {
    array(case, "policies")
        .iter()
        .map(|p| PolicyDocument {
            policy_id: string(p, "policyId"),
            kind: string(p, "kind"),
            version: string(p, "version"),
            is_root: p["isRoot"].as_bool().unwrap_or(false),
            document: string(p, "document"),
        })
        .collect()
}

fn request(case: &Value) -> Request {
    let r = &case["request"];
    Request {
        return_policy_id_list: r["returnPolicyIdList"].as_bool().unwrap_or(false),
        combined_decision: r["combinedDecision"].as_bool().unwrap_or(false),
        categories: array(r, "categories")
            .iter()
            .map(|c| Category {
                category: string(c, "category"),
                has_content: c["hasContent"].as_bool().unwrap_or(false),
                attributes: array(c, "attributes")
                    .iter()
                    .map(|a| Attribute {
                        attribute_id: string(a, "attributeId"),
                        issuer: optional(a, "issuer"),
                        include_in_result: a["includeInResult"].as_bool().unwrap_or(false),
                        values: array(a, "values")
                            .iter()
                            .map(|v| AttributeValue { data_type: string(v, "dataType"), value: string(v, "value") })
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn obligations(list: &[Value]) -> Vec<Obligation> {
    list.iter()
        .map(|o| Obligation {
            id: string(o, "id"),
            assignments: array(o, "assignments")
                .iter()
                .map(|a| Assignment {
                    attribute_id: string(a, "attributeId"),
                    category: optional(a, "category"),
                    issuer: optional(a, "issuer"),
                    data_type: string(a, "dataType"),
                    value: string(a, "value"),
                })
                .collect(),
        })
        .collect()
}

/// Equal as multisets under `same`.
fn same_multiset<T>(expected: &[T], got: &[T], same: impl Fn(&T, &T) -> bool) -> bool {
    if expected.len() != got.len() {
        return false;
    }
    let mut used = vec![false; got.len()];
    expected.iter().all(|e| match (0..got.len()).find(|&i| !used[i] && same(e, &got[i])) {
        Some(i) => {
            used[i] = true;
            true
        }
        None => false,
    })
}

/// Two obligations are equal when their ids are and their assignments are
/// as multisets. Every member of an assignment is compared, the value by
/// its canonical form.
fn same_obligation(a: &Obligation, b: &Obligation) -> bool {
    a.id == b.id && same_multiset(&a.assignments, &b.assignments, |x, y| x == y)
}

fn decision(text: &str) -> Decision {
    match text {
        "Permit" => Decision::Permit,
        "Deny" => Decision::Deny,
        "NotApplicable" => Decision::NotApplicable,
        "Indeterminate" => Decision::Indeterminate,
        other => panic!("not a decision: {}", other),
    }
}

#[test]
fn the_manifest_is_the_pinned_corpus() {
    let manifest = manifest();
    assert_eq!(manifest["version"].as_u64(), Some(CORPUS_VERSION), "the corpus version");
    assert_eq!(manifest["sha256"].as_str(), Some(CORPUS_SHA256), "the corpus digest");
}

#[test]
fn every_case_file_is_present() {
    let wanted = manifest()["cases"]["oasis"].as_u64().expect("cases.oasis");
    assert_eq!(case_files().len() as u64, wanted);
}

#[test]
fn every_oasis_case_gets_the_reference_answer() {
    let now = instant(manifest()["now"].as_str().expect("now"));
    let files = case_files();
    let mut mismatches = Vec::new();
    for path in &files {
        let case = read_json(path);
        let name = string(&case, "name");
        let compiled = match Policies::compile(&policies(&case)) {
            Ok(compiled) => compiled,
            Err(error) => {
                mismatches.push(format!("{}: does not compile: {}", name, error));
                continue;
            }
        };
        let response = compiled.evaluate(&request(&case), now, &NoResolver);
        let expected = &case["expected"];
        let want = decision(expected["decision"].as_str().unwrap_or(""));
        if response.decision != want {
            mismatches.push(format!("{}: decision {:?}, got {:?}", name, want, response.decision));
        }
        for (key, got) in [("obligations", &response.obligations), ("advice", &response.advice)] {
            let want = obligations(array(expected, key));
            if !same_multiset(&want, got, same_obligation) {
                mismatches.push(format!("{}: {} {:?}, got {:?}", name, key, want, got));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} cases differ from the reference:\n{}",
        mismatches.len(),
        files.len(),
        mismatches.join("\n")
    );
    println!("{} of {} corpus cases pass", files.len(), files.len());
}
