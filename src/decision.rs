// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! What a host library hands the PEP, and what it gets back.

use serde_json::{json, Map, Value};

/// Who is asking: a claims map the host library builds from its own
/// sign-in (an OIDC `Login`, a SAML assertion's attributes, a WS-Fed
/// token's claims, a GNAP grant's subject). The crate reads no HTTP header.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Subject {
    /// The AuthZEN subject type: `user` for a person.
    pub kind: String,
    /// The subject's id: XACML's `subject-id`, and what the service's PIP
    /// resolves.
    pub id: String,
    /// The claims (`acr`, `amr`, `auth_time`, and the rest). They reach the
    /// policy only through the realm's AuthZEN attribute catalogue.
    pub properties: Map<String, Value>,
}

impl Subject {
    /// A person, with their claims.
    pub fn user(id: impl Into<String>, properties: Map<String, Value>) -> Self {
        Self { kind: "user".into(), id: id.into(), properties }
    }
}

/// What the subject wants to do, to what.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Access {
    /// The AuthZEN action name (`read`, `GET`, `documents.delete`, ...).
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub action_properties: Map<String, Value>,
    pub resource_properties: Map<String, Value>,
    /// Further AuthZEN context. `application` and `supported_obligations`
    /// are the PEP's and are overwritten.
    pub context: Map<String, Value>,
}

impl Access {
    pub fn new(action: impl Into<String>, resource_type: impl Into<String>, resource_id: impl Into<String>) -> Self {
        Self { action: action.into(), resource_type: resource_type.into(), resource_id: resource_id.into(), ..Self::default() }
    }
}

/// An obligation (or advice) the host application must act on.
#[derive(Debug, Clone, PartialEq)]
pub struct Obligation {
    pub id: String,
    /// The Obligations Profile type (`step-up`, `notification`, ...), or
    /// `custom`; for an XACML advice, its id.
    pub kind: String,
    pub properties: Map<String, Value>,
}

/// The decision.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Allowed. Every obligation is of a type the host declared it
    /// discharges (`supportedObligations`), and must be discharged before
    /// the access is given; advice may be ignored.
    Permit { obligations: Vec<Obligation>, advice: Vec<Obligation> },
    /// Refused by policy, or a request the service would refuse.
    Deny { why: String },
    /// No decision could be made: no policy held yet, or the service could
    /// not be reached. Fail closed.
    Unavailable { why: String },
}

impl Decision {
    /// `true` only for a Permit.
    pub fn is_permit(&self) -> bool {
        matches!(self, Decision::Permit { .. })
    }

    /// The HTTP status a host answers with: 200 for a Permit and 403 for
    /// everything else. A Deny and a decision that could not be made
    /// (`Unavailable`) are both 403: an enforcement point that cannot say
    /// yes says no, whatever went wrong, and never answers a failure with a
    /// 5xx a client might retry into a different answer. Whether the user
    /// was signed in at all (401) is the host's question, asked before the
    /// PEP is.
    pub fn http_status(&self) -> u16 {
        if self.is_permit() {
            200
        } else {
            403
        }
    }
}

/// The AuthZEN evaluation body both modes decide: `central` sends it, and
/// `local` maps it through the catalogue as the service would.
pub fn evaluation_body(subject: &Subject, access: &Access, application: &str, supported: &[String]) -> Value {
    let mut subject_json = json!({"type": subject.kind, "id": subject.id});
    if !subject.properties.is_empty() {
        subject_json["properties"] = Value::Object(subject.properties.clone());
    }
    let mut action = json!({"name": access.action});
    if !access.action_properties.is_empty() {
        action["properties"] = Value::Object(access.action_properties.clone());
    }
    let mut resource = json!({"type": access.resource_type, "id": access.resource_id});
    if !access.resource_properties.is_empty() {
        resource["properties"] = Value::Object(access.resource_properties.clone());
    }
    let mut context = access.context.clone();
    context.insert("application".into(), Value::String(application.to_string()));
    context.remove("supported_obligations");
    if !supported.is_empty() {
        context.insert("supported_obligations".into(), json!(supported));
    }
    json!({"subject": subject_json, "action": action, "resource": resource, "context": context})
}

/// An AuthZEN obligation object (`id`, `type`, `properties`) read back.
pub fn obligation_from(value: &Value) -> Option<Obligation> {
    Some(Obligation {
        id: value.get("id")?.as_str()?.to_string(),
        kind: value.get("type").and_then(Value::as_str).unwrap_or("custom").to_string(),
        properties: value.get("properties").and_then(Value::as_object).cloned().unwrap_or_default(),
    })
}

/// An advice as the service's AuthZEN `context.advice` carries it (`id`,
/// `attributes: [{id, value}]`), read into the shape `local` hands: the
/// kind is the id, each attribute a property named by its id, its value the
/// lexical form, and a repeated id an array, in order.
pub fn advice_from(value: &Value) -> Option<Obligation> {
    let id = value.get("id")?.as_str()?.to_string();
    let mut properties = serde_json::Map::new();
    for attribute in value.get("attributes").and_then(Value::as_array).into_iter().flatten() {
        let Some(name) = attribute.get("id").and_then(Value::as_str) else { continue };
        let text = match attribute.get("value") {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Null) | None => continue,
            Some(other) => other.to_string(),
        };
        match properties.get_mut(name) {
            Some(Value::Array(values)) => values.push(Value::String(text)),
            Some(existing) => *existing = Value::Array(vec![existing.clone(), Value::String(text)]),
            None => {
                properties.insert(name.to_string(), Value::String(text));
            }
        }
    }
    Some(Obligation { id: id.clone(), kind: id, properties })
}

/// `central`: pulls the catalogue and answers its token and the subject
/// properties it declares, or `None` on `304`.
pub(crate) fn pull_subject_roots(credential: &crate::credential::Credential, base: &str, token: &str) -> Result<Option<(String, std::collections::HashSet<String>)>, crate::error::PepError> {
    use crate::error::PepError;
    let url = format!("{base}/xacml/pep/authzen-catalogue");
    let extra = if token.is_empty() { Vec::new() } else { vec![("If-None-Match", format!("\"{token}\""))] };
    let answer = credential.call(crate::credential::Audience::Pep, "GET", &url, "application/json", &extra, None)?;
    match answer.status {
        304 if !token.is_empty() => Ok(None),
        200 => {
            let json = answer.json().ok_or_else(|| PepError::new("policy", "the catalogue pull is not JSON"))?;
            let rows = json["rows"].as_array().ok_or_else(|| PepError::new("policy", "the catalogue pull has no rows array"))?;
            let roots = rows
                .iter()
                .filter(|r| r["object"] == "subject")
                .filter_map(|r| r["property"].as_str())
                .map(crate::pep::root_of)
                .collect();
            let token = json["syncToken"].as_str().unwrap_or("").to_string();
            Ok(Some((token, roots)))
        }
        status => Err(PepError::new("refused", format!("the catalogue pull answered {status}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_permit_is_200_and_everything_else_403() {
        assert_eq!(Decision::Permit { obligations: vec![], advice: vec![] }.http_status(), 200);
        assert_eq!(Decision::Deny { why: "no".into() }.http_status(), 403);
        assert_eq!(Decision::Unavailable { why: "down".into() }.http_status(), 403);
    }

    #[test]
    fn the_body_carries_the_bound_application_and_no_empty_properties() {
        let mut access = Access::new("read", "document", "42");
        access.context.insert("application".into(), json!("someone-else"));
        access.context.insert("ip".into(), json!("10.0.0.1"));
        let body = evaluation_body(&Subject::user("alice", Map::new()), &access, "app-a", &["step-up".into()]);
        assert_eq!(body["context"]["application"], "app-a");
        assert_eq!(body["context"]["ip"], "10.0.0.1");
        assert_eq!(body["context"]["supported_obligations"], json!(["step-up"]));
        assert!(body["subject"].get("properties").is_none());
        assert_eq!(body["action"], json!({"name": "read"}));
    }
}
