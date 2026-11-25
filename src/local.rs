// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! `local` mode (D3 (b)): the bound application's policies, pulled and
//! compiled, and the decision made in process.
//!
//! - **The pull** is `GET /xacml/pep/policies?scope=bound-application`
//!   (iya-sts#2027): the application's own policy and its reference
//!   closure, or the realm root when it has none. The realm's AuthZEN
//!   attribute catalogue is pulled beside it, because an evaluation reaches
//!   the policy only through the catalogue's rows. Each pull sends its
//!   token as `If-None-Match`, and `304` keeps what is held.
//! - **A set that doesn't compile keeps the one held**, and the error is on
//!   the PEP's status. Before the first good pull, every decision is
//!   `Unavailable`.
//! - **The PIP:** before evaluating, every access-subject designator the
//!   policy could ask for that the request doesn't carry is fetched in one
//!   `POST /xacml/pip`. A failure there is an empty bag, never an error,
//!   as in the container PEP.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use serde_json::Value;

use crate::authzen::{self, Catalogue, Trusted};
use crate::credential::{Audience, Credential};
use crate::decision::{obligation_from, Decision, Obligation};
use crate::engine::{self, AttributeValue, Designator, PolicyDocument, Policies, Resolver, ACCESS_SUBJECT};
use crate::error::PepError;
use crate::http::Body;

const PIP_NS: &str = "urn:sts:xacml:pip:1.0";
const XACML_NS: &str = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";
const SUBJECT_ID: &str = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
const SUBJECT_KIND: &str = "urn:sts:xacml:subject-kind";
/// The service refuses more designators than this in one PIP query.
pub const MAX_DESIGNATORS: usize = 50;

/// What a `local` PEP holds.
pub struct Held {
    pub policies: Arc<Policies>,
    pub catalogue: Catalogue,
    pub policy_token: String,
    pub catalogue_token: String,
    pub subject_designators: Vec<Designator>,
}

/// What one pull did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pulled {
    /// Both answered `304`.
    Unchanged,
    /// A new set (or catalogue) is held.
    Changed,
}

fn quoted(token: &str) -> String {
    format!("\"{token}\"")
}

fn unquote(etag: &str) -> String {
    etag.trim().trim_start_matches("W/").trim_matches('"').to_string()
}

/// Pulls the policies and the catalogue, and compiles. `held` is what is
/// held now, whose tokens are sent and whose parts are kept on `304`.
pub fn pull(credential: &Credential, base: &str, name: &str, held: Option<&Arc<Held>>) -> Result<(Pulled, Option<Held>), PepError> {
    let policies_url = format!("{base}/xacml/pep/policies?scope=bound-application&pep={}", url::form_urlencoded::byte_serialize(name.as_bytes()).collect::<String>());
    let catalogue_url = format!("{base}/xacml/pep/authzen-catalogue");
    let etag = |token: Option<&str>| token.filter(|t| !t.is_empty()).map(|t| vec![("If-None-Match", quoted(t))]).unwrap_or_default();

    let answer = credential.call(Audience::Pep, "GET", &policies_url, "application/json", &etag(held.map(|h| h.policy_token.as_str())), None)?;
    let policies = match answer.status {
        304 if held.is_some() => None,
        200 => {
            let json = answer.json().ok_or_else(|| PepError::new("policy", "the policy pull is not JSON"))?;
            let token = json["syncToken"].as_str().map(str::to_string).unwrap_or_else(|| unquote(&answer.etag));
            Some((rows(&json)?, token))
        }
        status => return Err(refusal("the policy pull", status, &answer.body)),
    };

    let answer = credential.call(Audience::Pep, "GET", &catalogue_url, "application/json", &etag(held.map(|h| h.catalogue_token.as_str())), None)?;
    let catalogue = match answer.status {
        304 if held.is_some() => None,
        200 => {
            let json = answer.json().ok_or_else(|| PepError::new("policy", "the catalogue pull is not JSON"))?;
            let token = json["syncToken"].as_str().map(str::to_string).unwrap_or_else(|| unquote(&answer.etag));
            let catalogue = Catalogue::from_pull(&json).map_err(|r| PepError::new("policy", format!("the catalogue was refused: {} {}", r.code, r.message)))?;
            Some((catalogue, token))
        }
        status => return Err(refusal("the catalogue pull", status, &answer.body)),
    };

    if policies.is_none() && catalogue.is_none() {
        return Ok((Pulled::Unchanged, None));
    }
    let (compiled, policy_token) = match policies {
        Some((rows, token)) => (Arc::new(Policies::compile(&rows).map_err(|e| PepError::new("policy", format!("the pulled set does not compile: {e}")))?), token),
        // Only the catalogue changed: the compiled set is kept as it is.
        None => {
            let h = held.expect("a 304 only with a held set");
            (h.policies.clone(), h.policy_token.clone())
        }
    };
    let (catalogue, catalogue_token) = match catalogue {
        Some(pair) => pair,
        None => {
            let h = held.expect("a 304 only with a held set");
            (h.catalogue.clone(), h.catalogue_token.clone())
        }
    };
    let subject_designators = compiled.designators(ACCESS_SUBJECT);
    Ok((Pulled::Changed, Some(Held { policies: compiled, catalogue, policy_token, catalogue_token, subject_designators })))
}

fn refusal(what: &str, status: u16, body: &str) -> PepError {
    let json: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let error = json["error"].as_str().unwrap_or("");
    let description = json["error_description"].as_str().unwrap_or("");
    PepError::new("refused", format!("{what} answered {status} {error} {description}").trim_end().to_string())
}

fn rows(json: &Value) -> Result<Vec<PolicyDocument>, PepError> {
    let list = json["policies"].as_array().ok_or_else(|| PepError::new("policy", "the policy pull has no policies array"))?;
    let rows: Vec<PolicyDocument> = list
        .iter()
        .map(|row| PolicyDocument {
            policy_id: row["policyId"].as_str().unwrap_or("").to_string(),
            kind: row["kind"].as_str().unwrap_or("").to_string(),
            version: row["version"].as_str().unwrap_or("").to_string(),
            is_root: row["isRoot"].as_bool().unwrap_or(false),
            document: row["document"].as_str().unwrap_or("").to_string(),
        })
        .collect();
    if rows.iter().filter(|r| r.is_root).count() != 1 {
        let note = json["rootNote"].as_str().unwrap_or("");
        return Err(PepError::new("policy", format!("the pulled set has no single root policy {note}").trim_end().to_string()));
    }
    Ok(rows)
}

/// What the PIP answered, by (category, attribute id, datatype).
#[derive(Default)]
pub struct PipAnswers {
    answers: HashMap<(String, String, String), Vec<AttributeValue>>,
}

impl Resolver for PipAnswers {
    fn resolve(&self, d: &Designator) -> Option<Vec<AttributeValue>> {
        self.answers.get(&(d.category.clone(), d.attribute_id.clone(), d.data_type.clone())).cloned()
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The PIP query: the subject, and what to resolve for it.
pub fn pip_query(subject_id: &str, application_subject: bool, designators: &[Designator]) -> String {
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PIPRequest xmlns=\"{PIP_NS}\">\n  <Request xmlns=\"{XACML_NS}\" CombinedDecision=\"false\" ReturnPolicyIdList=\"false\">\n    <Attributes Category=\"{ACCESS_SUBJECT}\">\n      <Attribute AttributeId=\"{SUBJECT_ID}\" IncludeInResult=\"true\">\n        <AttributeValue DataType=\"{}\">{}</AttributeValue>\n      </Attribute>\n",
        engine::STRING,
        escape(subject_id)
    );
    if application_subject {
        out.push_str(&format!("      <Attribute AttributeId=\"{SUBJECT_KIND}\" IncludeInResult=\"false\">\n        <AttributeValue DataType=\"{}\">application</AttributeValue>\n      </Attribute>\n", engine::STRING));
    }
    out.push_str("    </Attributes>\n  </Request>\n");
    for d in designators {
        out.push_str(&format!(
            "  <AttributeDesignator xmlns=\"{XACML_NS}\" Category=\"{}\" AttributeId=\"{}\" DataType=\"{}\" MustBePresent=\"false\"/>\n",
            escape(&d.category),
            escape(&d.attribute_id),
            escape(&d.data_type)
        ));
    }
    out.push_str("</PIPRequest>\n");
    out
}

/// Reads a `<PIPResponse>`. An answer that can't be read is no answers.
pub fn read_pip_answer(text: &str) -> PipAnswers {
    let mut out = PipAnswers::default();
    let Ok(doc) = roxmltree::Document::parse(text) else { return out };
    let root = doc.root_element();
    if root.tag_name().name() != "PIPResponse" {
        return out;
    }
    for attributes in root.descendants().filter(|n| n.is_element() && n.tag_name().name() == "Attributes") {
        let category = attributes.attribute("Category").unwrap_or("").to_string();
        for attribute in attributes.children().filter(|n| n.is_element() && n.tag_name().name() == "Attribute") {
            let id = attribute.attribute("AttributeId").unwrap_or("").to_string();
            for value in attribute.children().filter(|n| n.is_element() && n.tag_name().name() == "AttributeValue") {
                let data_type = value.attribute("DataType").unwrap_or(engine::STRING).to_string();
                let lexical: String = value.descendants().filter(|t| t.is_text()).filter_map(|t| t.text()).collect();
                out.answers
                    .entry((category.clone(), id.clone(), data_type.clone()))
                    .or_default()
                    .push(AttributeValue { data_type, value: lexical.trim().to_string() });
            }
        }
    }
    out
}

/// Asks the PIP for every subject designator the request doesn't carry.
fn resolve_subject(credential: &Credential, base: &str, held: &Held, request: &engine::Request, subject_id: &str, application_subject: bool) -> PipAnswers {
    let carried: Vec<(&str, &str)> = request
        .categories
        .iter()
        .filter(|c| c.category == ACCESS_SUBJECT)
        .flat_map(|c| c.attributes.iter().map(|a| (c.category.as_str(), a.attribute_id.as_str())))
        .collect();
    let wanted: Vec<Designator> = held
        .subject_designators
        .iter()
        .filter(|d| !carried.contains(&(d.category.as_str(), d.attribute_id.as_str())))
        .take(MAX_DESIGNATORS)
        .cloned()
        .collect();
    if wanted.is_empty() || subject_id.is_empty() {
        return PipAnswers::default();
    }
    let url = format!("{base}/xacml/pip");
    let query = pip_query(subject_id, application_subject, &wanted);
    match credential.call(Audience::Pep, "POST", &url, "application/xml", &[], Some(&Body::Xml(&query))) {
        Ok(answer) if answer.status == 200 => read_pip_answer(&answer.body),
        _ => PipAnswers::default(),
    }
}

/// What one local decision was, for the record.
pub struct Made {
    pub decision: Decision,
    pub outcome: Option<authzen::Outcome>,
}

/// Decides one evaluation body in process.
#[allow(clippy::too_many_arguments)]
pub fn decide(credential: &Credential, base: &str, held: &Held, body: &Value, trusted: &Trusted, subject_id: &str, application_subject: bool, now: SystemTime) -> Made {
    let mapped = match authzen::map_evaluation(body, &held.catalogue, trusted) {
        Ok(mapped) => mapped,
        Err(refusal) => {
            return Made { decision: Decision::Deny { why: format!("the evaluation was refused ({}): {}", refusal.code, refusal.message) }, outcome: None };
        }
    };
    let pip = resolve_subject(credential, base, held, &mapped.request, subject_id, application_subject);
    let response = held.policies.evaluate(&mapped.request, now, &pip);
    let outcome = authzen::outcome(&response, mapped.supported_obligations.as_deref(), held.catalogue.obligations_profile);
    let decision = if outcome.fault {
        Decision::Unavailable { why: outcome.why.clone() }
    } else if outcome.decision {
        Decision::Permit {
            obligations: outcome.handed.iter().filter_map(|h| obligation_from(&h.obligation)).collect(),
            advice: response.advice.iter().map(advice).collect(),
        }
    } else {
        Decision::Deny { why: outcome.why.clone() }
    };
    Made { decision, outcome: Some(outcome) }
}

fn advice(a: &engine::Obligation) -> Obligation {
    let mut properties = serde_json::Map::new();
    for assignment in &a.assignments {
        match properties.get_mut(&assignment.attribute_id) {
            Some(Value::Array(values)) => values.push(Value::String(assignment.value.clone())),
            Some(existing) => *existing = Value::Array(vec![existing.clone(), Value::String(assignment.value.clone())]),
            None => {
                properties.insert(assignment.attribute_id.clone(), Value::String(assignment.value.clone()));
            }
        }
    }
    Obligation { id: a.id.clone(), kind: a.id.clone(), properties }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pip_query_escapes_and_names_each_designator() {
        let d = Designator { category: ACCESS_SUBJECT.into(), attribute_id: "dept".into(), data_type: engine::STRING.into(), issuer: None };
        let q = pip_query("a<b", true, &[d]);
        assert!(q.contains("a&lt;b"));
        assert!(q.contains("subject-kind"));
        assert!(q.contains("AttributeId=\"dept\""));
        roxmltree::Document::parse(&q).unwrap();
    }

    #[test]
    fn a_pip_answer_is_read_by_designator_and_garbage_is_nothing() {
        let text = format!(
            "<PIPResponse xmlns=\"{PIP_NS}\"><Attributes xmlns=\"{XACML_NS}\" Category=\"{ACCESS_SUBJECT}\"><Attribute AttributeId=\"dept\" IncludeInResult=\"false\"><AttributeValue DataType=\"{}\">eng</AttributeValue><AttributeValue DataType=\"{}\">ops</AttributeValue></Attribute></Attributes></PIPResponse>",
            engine::STRING,
            engine::STRING
        );
        let a = read_pip_answer(&text);
        let d = Designator { category: ACCESS_SUBJECT.into(), attribute_id: "dept".into(), data_type: engine::STRING.into(), issuer: None };
        assert_eq!(a.resolve(&d).unwrap().len(), 2);
        assert!(read_pip_answer("<nope").resolve(&d).is_none());
    }
}
