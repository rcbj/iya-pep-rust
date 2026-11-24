// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! An AuthZEN access evaluation as an XACML request, and the decision back
//! (the `local` feature).
//!
//! In `local` mode the PEP decides in process what `central` mode asks the
//! service at `POST /access/v1/evaluation`. **The two must give the same
//! answer**, so an evaluation is mapped here exactly as the service's
//! `authzen/authzen_map.ts` and the container PEP's `authzen_map.rs` map it,
//! through the realm's attribute catalogue (`GET /xacml/pep/authzen-catalogue`),
//! and the outcome is fail-closed in the same way. `tests/authzen_cases.rs`
//! holds this file to the table the other two are held to.
//!
//! THIS MODULE'S PUBLIC ITEMS ARE THE CONTRACT with `src/local.rs`.
//!
//! **What is the contract and what is not.** The code, the HTTP status, the
//! order the checks are made in (so a request with two problems is refused
//! for the same one everywhere), the identifiers, the datatypes and the
//! request's shape are the contract. The sentences are this crate's own.
//!
//! **The catalogue.** Every row is read again here, never trusted because
//! the service sent it: a row onto a reserved identifier (this service's
//! `urn:sts:xacml:` namespace, subject-id, resource-id, action-id, the
//! current-time trio, a bare directory name in a subject category) would let
//! a caller forge a trusted fact, because a request-supplied attribute
//! suppresses the PIP. A pulled row this grammar refuses, and a second row
//! for one object and property, is left out, so that property is undeclared
//! here and a request naming it is refused.
//!
//! **The values.** The row's datatype wins: a string reaches every type and
//! must parse at it; a boolean reaches only a boolean; a number only an
//! integer (a whole one, read as JavaScript reads it) or a double. `null` is
//! refused, an array only reaches a `bag` row, a nested object reaches a
//! request only through declared dotted rows, and an undeclared property is
//! refused in every mode. The trusted `urn:sts:xacml:authzen:supplied` bag
//! keeps absent and empty apart.
//!
//! **The outcome is fail-closed.** `true` only on a Permit carrying nothing
//! this PEP cannot discharge. `urn:sts:xacml:obligation:log` is the one
//! obligation discharged here. Any other is handed to the caller only when
//! the realm's obligations profile is on and the caller declared, in
//! `context.supported_obligations`, every type the answer carries; otherwise
//! a Permit carrying one stays `false`. An Indeterminate from a processing or
//! syntax error is a fault, never an ordinary denial.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::engine;

/// A refusal of a catalogue row or of an evaluation: the HTTP status the
/// service would answer, its `STS-AUTHZEN-*` code, and the sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

/// One row of the attribute catalogue, read and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// `subject`, `resource`, `action` or `context`.
    pub object: String,
    /// A dotted path into the object's `properties` (or into `context`).
    pub property: String,
    pub attribute_id: String,
    /// The full category URI.
    pub category: String,
    /// The full datatype URI.
    pub data_type: String,
    /// `bag` rather than `single`.
    pub bag: bool,
}

// ---------------------------------------------------------------------------
// Vocabulary.
// ---------------------------------------------------------------------------

const RECIPIENT_SUBJECT: &str = "urn:oasis:names:tc:xacml:1.0:subject-category:recipient-subject";
const INTERMEDIARY_SUBJECT: &str = "urn:oasis:names:tc:xacml:1.0:subject-category:intermediary-subject";
const CODEBASE: &str = "urn:oasis:names:tc:xacml:1.0:subject-category:codebase";
const REQUESTING_MACHINE: &str = "urn:oasis:names:tc:xacml:1.0:subject-category:requesting-machine";

const SUBJECT_ID: &str = "urn:oasis:names:tc:xacml:1.0:subject:subject-id";
const RESOURCE_ID: &str = "urn:oasis:names:tc:xacml:1.0:resource:resource-id";
const ACTION_ID: &str = "urn:oasis:names:tc:xacml:1.0:action:action-id";
const CURRENT_TIME: &str = "urn:oasis:names:tc:xacml:1.0:environment:current-time";
const CURRENT_DATE: &str = "urn:oasis:names:tc:xacml:1.0:environment:current-date";
const CURRENT_DATETIME: &str = "urn:oasis:names:tc:xacml:1.0:environment:current-dateTime";

const BOOLEAN: &str = "http://www.w3.org/2001/XMLSchema#boolean";
const INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";
const DOUBLE: &str = "http://www.w3.org/2001/XMLSchema#double";
const TIME: &str = "http://www.w3.org/2001/XMLSchema#time";
const DATE: &str = "http://www.w3.org/2001/XMLSchema#date";
const DATETIME: &str = "http://www.w3.org/2001/XMLSchema#dateTime";
const DAYTIME_DURATION: &str = "http://www.w3.org/2001/XMLSchema#dayTimeDuration";
const YEARMONTH_DURATION: &str = "http://www.w3.org/2001/XMLSchema#yearMonthDuration";
const ANYURI: &str = "http://www.w3.org/2001/XMLSchema#anyURI";
const HEXBINARY: &str = "http://www.w3.org/2001/XMLSchema#hexBinary";
const BASE64BINARY: &str = "http://www.w3.org/2001/XMLSchema#base64Binary";
const RFC822NAME: &str = "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name";
const X500NAME: &str = "urn:oasis:names:tc:xacml:1.0:data-type:x500Name";
const DNSNAME: &str = "urn:oasis:names:tc:xacml:2.0:data-type:dnsName";
const IPADDRESS: &str = "urn:oasis:names:tc:xacml:2.0:data-type:ipAddress";

/// The facts this PEP writes itself, in `urn:sts:xacml:`.
const PROTOCOL: &str = "urn:sts:xacml:protocol";
const REALM: &str = "urn:sts:xacml:realm";
const AUTHZEN_SUBJECT_TYPE: &str = "urn:sts:xacml:authzen:subject-type";
const AUTHZEN_RESOURCE_TYPE: &str = "urn:sts:xacml:authzen:resource-type";
const AUTHZEN_CALLER: &str = "urn:sts:xacml:authzen:caller";
const AUTHZEN_APPLICATION: &str = "urn:sts:xacml:authzen:application";
const AUTHZEN_SUPPLIED: &str = "urn:sts:xacml:authzen:supplied";

/// The four objects a row may hang a property on, and the category each
/// defaults to.
const OBJECTS: [(&str, &str); 4] = [
    ("subject", engine::ACCESS_SUBJECT),
    ("resource", engine::RESOURCE),
    ("action", engine::ACTION),
    ("context", engine::ENVIRONMENT),
];

/// The members a row may carry.
const ROW_MEMBERS: [&str; 7] = ["object", "property", "attributeId", "category", "dataType", "multiplicity", "description"];

/// Category short names, in the service's order.
const CATEGORIES: [(&str, &str); 8] = [
    ("access-subject", engine::ACCESS_SUBJECT),
    ("recipient-subject", RECIPIENT_SUBJECT),
    ("intermediary-subject", INTERMEDIARY_SUBJECT),
    ("codebase", CODEBASE),
    ("requesting-machine", REQUESTING_MACHINE),
    ("resource", engine::RESOURCE),
    ("action", engine::ACTION),
    ("environment", engine::ENVIRONMENT),
];

/// Datatype short names: every engine type a JSON value can carry, so not
/// `xpathExpression`.
const DATATYPES: [(&str, &str); 16] = [
    ("string", engine::STRING),
    ("boolean", BOOLEAN),
    ("integer", INTEGER),
    ("double", DOUBLE),
    ("time", TIME),
    ("date", DATE),
    ("dateTime", DATETIME),
    ("dayTimeDuration", DAYTIME_DURATION),
    ("yearMonthDuration", YEARMONTH_DURATION),
    ("anyURI", ANYURI),
    ("hexBinary", HEXBINARY),
    ("base64Binary", BASE64BINARY),
    ("rfc822Name", RFC822NAME),
    ("x500Name", X500NAME),
    ("dnsName", DNSNAME),
    ("ipAddress", IPADDRESS),
];

/// The subject categories, where a bare name is a directory attribute the
/// PIP would otherwise resolve.
const SUBJECT_CATEGORIES: [&str; 5] = [engine::ACCESS_SUBJECT, RECIPIENT_SUBJECT, INTERMEDIARY_SUBJECT, CODEBASE, REQUESTING_MACHINE];

/// XACML identifiers filled from the evaluation's own members or by the PDP.
const ADAPTER_IDS: [&str; 6] = [SUBJECT_ID, RESOURCE_ID, ACTION_ID, CURRENT_TIME, CURRENT_DATE, CURRENT_DATETIME];

/// Context members the adapter reads itself, never a property.
const ADAPTER_CONTEXT: [&str; 3] = ["supported_obligations", "approval", "application"];

/// Context members the service's token-exchange binding reads by fixed
/// rules. A row may not name one; this PEP does not answer the binding.
const BINDING_CONTEXT: [&str; 11] = [
    "client_id",
    "acr",
    "amr",
    "auth_time",
    "cnf",
    "jti",
    "subject_token_type",
    "actor_token_type",
    "subject_token",
    "act",
    "may_act",
];

const RESERVED_NAMESPACE: &str = "urn:sts:xacml:";
const MAX_PATH_DEPTH: usize = 6;
const MAX_ATTRIBUTE_ID: usize = 512;
/// The longest a type, an id or a name may be.
const MAX_TEXT: usize = 1024;
/// The longest a string property's value may be.
const MAX_VALUE: usize = 8192;
/// The most values a bag may carry.
const MAX_BAG: usize = 256;
/// The deepest an undeclared branch is walked.
const MAX_NESTING: usize = 8;
/// The largest integer a JavaScript number holds exactly.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

const LOG_OBLIGATION: &str = "urn:sts:xacml:obligation:log";
/// The status of an Indeterminate that is an ordinary deny, not a fault.
const MISSING_ATTRIBUTE: &str = "urn:oasis:names:tc:xacml:1.0:status:missing-attribute";
const OBLIGATION_PREFIX: &str = "urn:sts:xacml:authzen:obligation:";

/// The Obligations Profile's registered types: name, the properties it may
/// not be handed without, and the properties that collect every assignment.
const OBLIGATION_TYPES: [(&str, &[&str], &[&str]); 3] = [
    ("step-up", &["acr_value"], &["amr_values"]),
    ("notification", &["to", "body"], &["to"]),
    ("session_termination", &["subject"], &[]),
];

// ---------------------------------------------------------------------------
// JavaScript's view of text, which the service's rules are written in.
// ---------------------------------------------------------------------------

fn is_js_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

fn js_trim(text: &str) -> &str {
    text.trim_matches(is_js_space)
}

/// Length in UTF-16 code units.
fn utf16_len(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
}

/// The first `limit` UTF-16 units, never splitting a character.
fn clip(text: &str, limit: usize) -> String {
    let mut used = 0;
    let mut out = String::new();
    for c in text.chars() {
        used += c.len_utf16();
        if used > limit {
            break;
        }
        out.push(c);
    }
    out
}

/// A member name JavaScript treats as an array index.
fn array_index(key: &str) -> Option<u64> {
    let canonical = !key.is_empty() && key.bytes().all(|b| b.is_ascii_digit()) && (key == "0" || !key.starts_with('0'));
    if !canonical {
        return None;
    }
    key.parse::<u64>().ok().filter(|n| *n < 4_294_967_295)
}

/// Members in `Object.keys()` order: index-like names ascending, then the
/// rest as inserted.
fn keys_in_js_order(map: &Map<String, Value>) -> Vec<&String> {
    let mut indexed: Vec<(u64, &String)> = map.keys().filter_map(|k| array_index(k).map(|n| (n, k))).collect();
    indexed.sort_by_key(|(n, _)| *n);
    let mut keys: Vec<&String> = indexed.into_iter().map(|(_, k)| k).collect();
    keys.extend(map.keys().filter(|k| array_index(k).is_none()));
    keys
}

/// `String(n)` for a finite JavaScript number.
fn number_text(n: f64) -> String {
    if n == 0.0 {
        return "0".into();
    }
    let sign = if n < 0.0 { "-" } else { "" };
    // Rust's `{:e}` prints the shortest digits that round-trip, which is
    // what ECMAScript's Number::toString chooses too.
    let sci = format!("{:e}", n.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let k = digits.len() as i64;
    let point = exp.parse::<i64>().unwrap_or(0) + 1;
    let body = if (k..=21).contains(&point) {
        format!("{}{}", digits, "0".repeat((point - k) as usize))
    } else if (1..=21).contains(&point) {
        let (whole, frac) = digits.split_at(point as usize);
        format!("{whole}.{frac}")
    } else if (-5..=0).contains(&point) {
        format!("0.{}{}", "0".repeat((-point) as usize), digits)
    } else {
        let e = point - 1;
        let e_text = if e < 0 { format!("-{}", -e) } else { format!("+{e}") };
        if k == 1 {
            format!("{digits}e{e_text}")
        } else {
            format!("{}.{}e{}", &digits[..1], &digits[1..], e_text)
        }
    };
    format!("{sign}{body}")
}

fn pattern(cell: &'static OnceLock<Option<Regex>>, source: &str) -> Option<&'static Regex> {
    cell.get_or_init(|| Regex::new(source).ok()).as_ref()
}

fn matches(cell: &'static OnceLock<Option<Regex>>, source: &str, text: &str) -> bool {
    pattern(cell, source).is_some_and(|re| re.is_match(text))
}

// ---------------------------------------------------------------------------
// The catalogue's grammar.
// ---------------------------------------------------------------------------

fn row_refused(code: &'static str, message: String) -> Refusal {
    Refusal { status: 400, code, message }
}

/// A bare LDAP-shaped name: what the PIP reads as a directory attribute.
fn is_bare_name(id: &str) -> bool {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    matches(&RE, r"^[A-Za-z][A-Za-z0-9;-]*$", id)
}

fn is_path_segment(segment: &str) -> bool {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    matches(&RE, r"^[A-Za-z0-9_$@:-]{1,64}$", segment)
}

/// Why an identifier may not be written by a row in `category`, with the
/// code, or `None`.
fn reserved(attribute_id: &str, category: &str) -> Option<Refusal> {
    if attribute_id.to_lowercase().starts_with(RESERVED_NAMESPACE) {
        return Some(row_refused(
            "STS-AUTHZEN-0011",
            format!(
                "\"{attribute_id}\" is in {RESERVED_NAMESPACE}, where the trusted facts live; a request-supplied \
                 value suppresses the PIP, so a row onto it would let a caller forge one"
            ),
        ));
    }
    if ADAPTER_IDS.contains(&attribute_id) {
        return Some(row_refused(
            "STS-AUTHZEN-0011",
            format!(
                "\"{attribute_id}\" is written from subject.id, action.name or resource.id, or supplied by the PDP, \
                 and from nothing else"
            ),
        ));
    }
    if SUBJECT_CATEGORIES.contains(&category) && is_bare_name(attribute_id) {
        return Some(row_refused(
            "STS-AUTHZEN-0012",
            format!(
                "\"{attribute_id}\" in a subject category names a directory attribute, which the directory answers; \
                 map the property onto an identifier of your own, such as urn:example:{attribute_id}"
            ),
        ));
    }
    None
}

impl Row {
    /// Reads one catalogue row, as the service reads a stored one: a JSON
    /// object, or a string holding one; short category and datatype names
    /// expanded; defaults applied.
    pub fn read(value: &Value) -> Result<Row, Refusal> {
        let bad = |message: String| Err(row_refused("STS-AUTHZEN-0010", message));
        let decoded;
        let value = match value {
            Value::String(text) => match serde_json::from_str::<Value>(text) {
                Ok(v) => {
                    decoded = v;
                    &decoded
                }
                Err(e) => return bad(format!("a catalogue row given as text must be JSON: {e}")),
            },
            other => other,
        };
        let Some(given) = value.as_object() else {
            return bad("a catalogue row is a JSON object: object, property, attributeId, and optionally \
                        category, dataType, multiplicity and description"
                .into());
        };
        let unknown: Vec<String> = keys_in_js_order(given)
            .into_iter()
            .filter(|k| !ROW_MEMBERS.contains(&k.as_str()))
            .map(|k| format!("\"{}\"", clip(k, 40)))
            .collect();
        if !unknown.is_empty() {
            return bad(format!("a catalogue row has no member {}; its members are {}", unknown.join(", "), ROW_MEMBERS.join(", ")));
        }
        let member = |name: &str| given.get(name).and_then(Value::as_str).map(|s| js_trim(s).to_string()).unwrap_or_default();

        let object = member("object");
        let Some(default_category) = OBJECTS.iter().find(|(o, _)| *o == object).map(|(_, c)| *c) else {
            let names: Vec<&str> = OBJECTS.iter().map(|(o, _)| *o).collect();
            return bad(format!("object is one of {}", names.join(", ")));
        };

        let property = member("property");
        let segments: Vec<&str> = if property.is_empty() { Vec::new() } else { property.split('.').collect() };
        if segments.is_empty() || segments.len() > MAX_PATH_DEPTH || !segments.iter().all(|s| is_path_segment(s)) {
            return bad(format!(
                "property is a member name or a dotted path of at most {MAX_PATH_DEPTH} names, each of letters, \
                 digits, _ $ @ : or -"
            ));
        }
        if object == "context" && ADAPTER_CONTEXT.contains(&segments[0]) {
            return Err(row_refused(
                "STS-AUTHZEN-0011",
                format!("context.{} is read by the adapter itself and is never a policy property", segments[0]),
            ));
        }
        if object == "context" && BINDING_CONTEXT.contains(&segments[0]) {
            return Err(row_refused(
                "STS-AUTHZEN-0011",
                format!(
                    "context.{} is read by the token-exchange binding's fixed rules, which a row may add to but \
                     never override",
                    segments[0]
                ),
            ));
        }

        let attribute_id = member("attributeId");
        if attribute_id.is_empty() || utf16_len(&attribute_id) > MAX_ATTRIBUTE_ID || attribute_id.chars().any(is_js_space) {
            return bad(format!("attributeId is a non-empty identifier without white space, of at most {MAX_ATTRIBUTE_ID} characters"));
        }

        let category_given = member("category");
        let category = if category_given.is_empty() {
            default_category
        } else {
            match CATEGORIES.iter().find(|(n, u)| *n == category_given || *u == category_given) {
                Some((_, uri)) => *uri,
                None => {
                    let names: Vec<&str> = CATEGORIES.iter().map(|(n, _)| *n).collect();
                    return bad(format!("category is one of {}, or its XACML URI", names.join(", ")));
                }
            }
        };

        let type_given = member("dataType");
        let type_given = if type_given.is_empty() { "string".to_string() } else { type_given };
        let Some(data_type) = DATATYPES.iter().find(|(n, u)| *n == type_given || *u == type_given).map(|(_, u)| *u) else {
            let names: Vec<&str> = DATATYPES.iter().map(|(n, _)| *n).collect();
            return bad(format!("dataType is one of {}, or its URI", names.join(", ")));
        };

        let bag = match member("multiplicity").as_str() {
            "" | "single" => false,
            "bag" => true,
            _ => return bad("multiplicity is single or bag".into()),
        };

        if let Some(refusal) = reserved(&attribute_id, category) {
            return Err(refusal);
        }

        Ok(Row {
            object,
            property: segments.join("."),
            attribute_id,
            category: category.to_string(),
            data_type: data_type.to_string(),
            bag,
        })
    }
}

/// The realm's catalogue as the PEP holds it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Catalogue {
    pub rows: Vec<Row>,
    /// The realm's `authzen.obligationsProfile`.
    pub obligations_profile: bool,
    /// `fgaApplications`: the applications that enforce fine-grained
    /// authorization. An evaluation about one of them carries two more facts
    /// (see [`Trusted::fga`]).
    pub fga_applications: Vec<String>,
}

impl Catalogue {
    /// Reads the catalogue pull's body (`AuthzenCatalogue`).
    ///
    /// Every row goes through [`Row::read`]. A row it refuses, and a second
    /// row for an object and property already held, is left out (the first
    /// is used), as the container PEP leaves them out: that property is then
    /// undeclared here, which refuses a request naming it. A body that is
    /// not a catalogue at all is refused whole, so the caller keeps the one
    /// it held. An absent `settings.obligationsProfile` is off.
    pub fn from_pull(body: &Value) -> Result<Catalogue, Refusal> {
        let Some(values) = body.get("rows").and_then(Value::as_array) else {
            return Err(Refusal {
                status: 500,
                code: "STS-AUTHZEN-0010",
                message: "The catalogue pull's answer is not an AuthZEN catalogue: it has no rows array.".into(),
            });
        };
        let mut rows: Vec<Row> = Vec::new();
        for value in values {
            if let Ok(row) = Row::read(value) {
                if !rows.iter().any(|r| r.object == row.object && r.property == row.property) {
                    rows.push(row);
                }
            }
        }
        let obligations_profile = body.pointer("/settings/obligationsProfile").and_then(Value::as_bool).unwrap_or(false);
        let fga_applications = body
            .get("fgaApplications")
            .and_then(Value::as_array)
            .map(|list| list.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        Ok(Catalogue { rows, obligations_profile, fga_applications })
    }
}

/// The two facts the service adds to an evaluation about an application
/// that enforces fine-grained authorization.
fn add_fga_access(request: &mut engine::Request, application: &str) {
    let include = request.categories.iter().flat_map(|c| c.attributes.iter()).map(|a| a.include_in_result).next().unwrap_or(true);
    let mut put = |category: &str, attribute_id: &str, value: &str| {
        let attribute = engine::Attribute {
            attribute_id: attribute_id.to_string(),
            issuer: None,
            include_in_result: include,
            values: if value.is_empty() { Vec::new() } else { vec![engine::AttributeValue::string(value)] },
        };
        match request.categories.iter_mut().find(|c| c.category == category) {
            Some(c) => c.attributes.push(attribute),
            None => request.categories.push(engine::Category { category: category.to_string(), has_content: false, attributes: vec![attribute] }),
        }
    };
    put(engine::RESOURCE, "urn:sts:xacml:fga:application", application);
    put(engine::ENVIRONMENT, "urn:sts:xacml:fga:stage", "access");
}

/// What the PEP knows about the call, written into the request as trusted
/// facts rather than read from the evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Trusted {
    /// The realm's id; empty for the default realm.
    pub realm: String,
    /// The caller: this PEP's name.
    pub caller: String,
    /// The bound application.
    pub application: String,
    /// The bound application enforces fine-grained authorization: the
    /// service decides it against its own policy, with two more facts, which
    /// the request then carries here too (`urn:sts:xacml:fga:application`
    /// in the resource, `urn:sts:xacml:fga:stage` = `access` in the
    /// environment), after every other attribute, as the service's builder
    /// writes them (`fgaAccess()`).
    pub fga: bool,
}

/// One evaluation, mapped.
#[derive(Debug, Clone, PartialEq)]
pub struct Mapped {
    pub request: engine::Request,
    /// `context.supported_obligations`, when the evaluation carried it.
    pub supported_obligations: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Reading an evaluation.
// ---------------------------------------------------------------------------

fn refused(code: &'static str, message: String) -> Refusal {
    Refusal { status: 400, code, message }
}

/// One catalogue row's values, as the request will carry them.
struct MappedAttribute<'a> {
    row: &'a Row,
    values: Vec<String>,
}

/// An evaluation read and checked, before it is built into a request.
struct Reading<'a> {
    /// subject.type, subject.id, action.name, resource.type, resource.id.
    required: [String; 5],
    application: String,
    supported_obligations: Option<Vec<String>>,
    supplied: Vec<String>,
    attributes: Vec<MappedAttribute<'a>>,
}

/// The entities AuthZEN requires, and the members each must carry.
const ENTITIES: [(&str, &[&str]); 3] = [("subject", &["type", "id"]), ("action", &["name"]), ("resource", &["type", "id"])];

fn read_evaluation<'a>(body: &Value, rows: &'a [Row]) -> Result<Reading<'a>, Refusal> {
    let Some(given) = body.as_object() else {
        return Err(refused(
            "STS-AUTHZEN-0001",
            "An access evaluation is a JSON object with subject, action, resource and, optionally, context.".into(),
        ));
    };
    // A member AuthZEN 1.0 does not define is ignored (section 10.1.1),
    // at the top and inside each entity.
    let mut required: Vec<String> = Vec::with_capacity(5);
    for (entity, members) in ENTITIES {
        let Some(object) = given.get(entity) else {
            let wanted: Vec<String> = members.iter().map(|m| format!("{entity}.{m}")).collect();
            return Err(refused(
                "STS-AUTHZEN-0002",
                format!("The request has no {entity}; AuthZEN requires {}.", wanted.join(" and ")),
            ));
        };
        let Some(object) = object.as_object() else {
            return Err(refused("STS-AUTHZEN-0003", format!("{entity} is a JSON object.")));
        };
        for member in members.iter() {
            match object.get(*member) {
                None | Some(Value::Null) => {
                    return Err(refused("STS-AUTHZEN-0002", format!("{entity}.{member} is required, as a non-empty string.")))
                }
                Some(Value::String(s)) if s.is_empty() => {
                    return Err(refused("STS-AUTHZEN-0002", format!("{entity}.{member} is required, as a non-empty string.")))
                }
                Some(Value::String(s)) if utf16_len(s) <= MAX_TEXT => required.push(s.clone()),
                Some(_) => {
                    return Err(refused(
                        "STS-AUTHZEN-0003",
                        format!("{entity}.{member} is a string of at most {MAX_TEXT} characters."),
                    ))
                }
            }
        }
        if object.get("properties").is_some_and(|p| !p.is_object()) {
            return Err(refused("STS-AUTHZEN-0003", format!("{entity}.properties is a JSON object.")));
        }
    }

    let no_context = Map::new();
    let context = match given.get("context") {
        None => &no_context,
        Some(Value::Object(map)) => map,
        Some(_) => return Err(refused("STS-AUTHZEN-0003", "context is a JSON object.".into())),
    };

    let application = match context.get("application") {
        None => String::new(),
        Some(Value::String(s)) if !s.is_empty() && utf16_len(s) <= MAX_TEXT => s.clone(),
        Some(_) => {
            return Err(refused(
                "STS-AUTHZEN-0003",
                "context.application is a non-empty string naming an application this caller may ask about.".into(),
            ))
        }
    };

    let supported_obligations = match context.get("supported_obligations") {
        None => None,
        Some(value) => Some(declared_obligations(value)?),
    };

    let approval = match context.get("approval") {
        None => false,
        Some(value) => {
            let well_formed = value
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| value.is_object() && !id.is_empty() && utf16_len(id) <= MAX_TEXT);
            if !well_formed {
                return Err(refused(
                    "STS-AUTHZEN-0003",
                    "context.approval is the approval object a completed access request returned, with its id.".into(),
                ));
            }
            true
        }
    };

    let mut supplied: Vec<String> =
        ["subject.type", "subject.id", "action.name", "resource.type", "resource.id"].iter().map(|s| s.to_string()).collect();
    if !application.is_empty() {
        supplied.push("context.application".into());
    }
    if supported_obligations.is_some() {
        supplied.push("context.supported_obligations".into());
    }
    if approval {
        supplied.push("context.approval".into());
    }

    let mut walker = Walker { rows, supplied, attributes: Vec::new() };
    for entity in ["subject", "action", "resource"] {
        if let Some(properties) = given.get(entity).and_then(|o| o.get("properties")).and_then(Value::as_object) {
            walker.walk(entity, &format!("{entity}.properties."), properties, "", 0)?;
        }
    }
    let mut rest = Map::new();
    for (key, value) in context {
        if !ADAPTER_CONTEXT.contains(&key.as_str()) {
            rest.insert(key.clone(), value.clone());
        }
    }
    walker.walk("context", "context.", &rest, "", 0)?;

    let mut parts = required.into_iter();
    let mut next = || parts.next().unwrap_or_default();
    Ok(Reading {
        required: [next(), next(), next(), next(), next()],
        application,
        supported_obligations,
        supplied: walker.supplied,
        attributes: walker.attributes,
    })
}

/// `context.supported_obligations`: at most 32 type names, each a string of
/// at most 64 characters.
fn declared_obligations(value: &Value) -> Result<Vec<String>, Refusal> {
    let refusal = || refused("STS-AUTHZEN-0003", "context.supported_obligations is an array of at most 32 obligation type names.".into());
    let list = value.as_array().filter(|l| l.len() <= 32).ok_or_else(refusal)?;
    list.iter()
        .map(|item| item.as_str().filter(|s| utf16_len(s) <= 64).map(str::to_string).ok_or_else(refusal))
        .collect()
}

struct Walker<'a> {
    rows: &'a [Row],
    supplied: Vec<String>,
    attributes: Vec<MappedAttribute<'a>>,
}

impl<'a> Walker<'a> {
    /// Maps each member of `members` (at `prefix` under `object`) through
    /// its row, descending into a declared branch, refusing the rest.
    fn walk(&mut self, object: &str, shown: &str, members: &Map<String, Value>, prefix: &str, depth: usize) -> Result<(), Refusal> {
        for key in keys_in_js_order(members) {
            let path = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
            let named = format!("{shown}{path}");
            let value = &members[key.as_str()];
            let rows = self.rows;
            let row = rows.iter().find(|r| r.object == object && r.property == path);
            let branch_prefix = format!("{path}.");
            let is_branch = row.is_none() && rows.iter().any(|r| r.object == object && r.property.starts_with(&branch_prefix));
            if row.is_none() && !(is_branch && value.is_object()) {
                return Err(refused(
                    "STS-AUTHZEN-0004",
                    format!(
                        "{} is not in this realm's AuthZEN attribute catalogue, and an undeclared property is \
                         refused in every mode.",
                        clip(&named, 200)
                    ),
                ));
            }
            if value.is_null() {
                return Err(refused(
                    "STS-AUTHZEN-0005",
                    format!("{} is null, which is neither absent nor empty: leave it out, or send a value.", clip(&named, 200)),
                ));
            }
            self.supplied.push(named.clone());
            match row {
                Some(row) => {
                    let values = row_values(row, value, &named)?;
                    self.attributes.push(MappedAttribute { row, values });
                }
                None => {
                    if depth + 1 > MAX_NESTING {
                        return Err(refused("STS-AUTHZEN-0008", format!("{} is nested too deeply.", clip(&named, 200))));
                    }
                    if let Some(inner) = value.as_object() {
                        self.walk(object, shown, inner, &path, depth + 1)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn type_label(uri: &str) -> &str {
    DATATYPES.iter().find(|(_, u)| *u == uri).map(|(n, _)| *n).unwrap_or(uri)
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        _ => "object",
    }
}

/// One member's lexical values at its row.
fn row_values(row: &Row, value: &Value, named: &str) -> Result<Vec<String>, Refusal> {
    let shown = clip(named, 200);
    if value.is_object() {
        return Err(refused(
            "STS-AUTHZEN-0008",
            format!("{shown} is an object, which reaches a request only through rows for its own members ({shown}.<member>)."),
        ));
    }
    if value.is_array() && !row.bag {
        return Err(refused("STS-AUTHZEN-0007", format!("{shown} is an array, and its row sends a single value.")));
    }
    let items: Vec<&Value> = match value {
        Value::Array(items) => items.iter().collect(),
        one => vec![one],
    };
    if items.len() > MAX_BAG {
        return Err(refused("STS-AUTHZEN-0007", format!("{shown} carries more than {MAX_BAG} values.")));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if item.is_null() {
            return Err(refused("STS-AUTHZEN-0005", format!("{shown} holds a null, which is not a value.")));
        }
        if item.is_object() || item.is_array() {
            return Err(refused("STS-AUTHZEN-0008", format!("{shown} holds an object or an array; a bag holds scalars.")));
        }
        let Some(text) = lexical(&row.data_type, item) else {
            return Err(refused(
                "STS-AUTHZEN-0006",
                format!("{shown} is a JSON {}, which does not reach its row's {}.", json_kind(item), type_label(&row.data_type)),
            ));
        };
        if !lexically_valid(&row.data_type, &text) {
            return Err(refused("STS-AUTHZEN-0006", format!("{shown} is not a valid {}.", type_label(&row.data_type))));
        }
        out.push(text);
    }
    Ok(out)
}

/// The lexical form of a JSON scalar at a datatype, or `None` when that
/// JSON type may not reach it.
fn lexical(data_type: &str, value: &Value) -> Option<String> {
    match value {
        Value::String(s) => (utf16_len(s) <= MAX_VALUE).then(|| s.clone()),
        Value::Bool(b) => (data_type == BOOLEAN).then(|| b.to_string()),
        Value::Number(n) => {
            let n = n.as_f64().filter(|n| n.is_finite())?;
            match data_type {
                INTEGER => (n.fract() == 0.0 && n.abs() <= MAX_SAFE_INTEGER).then(|| number_text(n)),
                DOUBLE => Some(number_text(n)),
                _ => None,
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Whether a lexical form parses at its datatype, by the engine's rules.
// ---------------------------------------------------------------------------

fn lexically_valid(data_type: &str, text: &str) -> bool {
    match data_type {
        BOOLEAN => matches!(text.trim(), "true" | "false" | "1" | "0"),
        INTEGER => {
            static RE: OnceLock<Option<Regex>> = OnceLock::new();
            matches(&RE, r"^[+-]?[0-9]+$", text.trim())
        }
        DOUBLE => valid_double(text.trim()),
        DATE => {
            static RE: OnceLock<Option<Regex>> = OnceLock::new();
            temporal(&RE, r"^(-?[0-9]{4,})-([0-9]{2})-([0-9]{2})(?:Z|[+-][0-9]{2}:[0-9]{2})?$", text, true, false)
        }
        TIME => {
            static RE: OnceLock<Option<Regex>> = OnceLock::new();
            temporal(&RE, r"^([0-9]{2}):([0-9]{2}):([0-9]{2}(?:\.[0-9]+)?)(?:Z|[+-][0-9]{2}:[0-9]{2})?$", text, false, true)
        }
        DATETIME => {
            static RE: OnceLock<Option<Regex>> = OnceLock::new();
            temporal(
                &RE,
                r"^(-?[0-9]{4,})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2}(?:\.[0-9]+)?)(?:Z|[+-][0-9]{2}:[0-9]{2})?$",
                text,
                true,
                true,
            )
        }
        YEARMONTH_DURATION => valid_year_month(text.trim()),
        DAYTIME_DURATION => valid_day_time(text.trim()),
        HEXBINARY => {
            let t = text.trim();
            t.len().is_multiple_of(2) && t.chars().all(|c| c.is_ascii_hexdigit())
        }
        BASE64BINARY => valid_base64(text),
        RFC822NAME => valid_rfc822(text.trim()),
        X500NAME => valid_x500(text.trim()),
        DNSNAME => valid_dns(text.trim()),
        IPADDRESS => valid_ip(text.trim()),
        // string and anyURI take any text.
        _ => true,
    }
}

fn valid_double(t: &str) -> bool {
    if matches!(t, "INF" | "+INF" | "-INF" | "NaN") {
        return true;
    }
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    matches(&RE, r"^[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)([eE][+-]?[0-9]+)?$", t) && t.parse::<f64>().is_ok()
}

/// A date, a time or a dateTime: the shape, then each field in range. The
/// captures are year, month, day (when `dated`), then hour, minute, second
/// (when `timed`).
fn temporal(cell: &'static OnceLock<Option<Regex>>, source: &str, text: &str, dated: bool, timed: bool) -> bool {
    let Some(caps) = pattern(cell, source).and_then(|re| re.captures(text.trim())) else {
        return false;
    };
    let int = |i: usize| caps.get(i).and_then(|m| m.as_str().parse::<i64>().ok());
    let mut next = 1;
    if dated {
        let (Some(_year), Some(month), Some(day)) = (int(1), int(2), int(3)) else {
            return false;
        };
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return false;
        }
        next = 4;
    }
    if timed {
        let (Some(hour), Some(minute)) = (int(next), int(next + 1)) else {
            return false;
        };
        let Some(second) = caps.get(next + 2).and_then(|m| m.as_str().parse::<f64>().ok()) else {
            return false;
        };
        if hour > 24 || minute > 59 || second >= 61.0 {
            return false;
        }
    }
    true
}

fn valid_year_month(t: &str) -> bool {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(caps) = pattern(&RE, r"^-?P(?:([0-9]+)Y)?(?:([0-9]+)M)?$").and_then(|re| re.captures(t)) else {
        return false;
    };
    let parts: Vec<_> = [1, 2].iter().filter_map(|i| caps.get(*i)).collect();
    !parts.is_empty() && parts.iter().all(|m| m.as_str().parse::<i64>().is_ok())
}

fn valid_day_time(t: &str) -> bool {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    let source = r"^-?P(?:([0-9]+)D)?(?:T(?:([0-9]+)H)?(?:([0-9]+)M)?(?:([0-9]+(?:\.[0-9]+)?)S)?)?$";
    let Some(caps) = pattern(&RE, source).and_then(|re| re.captures(t)) else {
        return false;
    };
    if t.ends_with('T') || (1..=4).all(|i| caps.get(i).is_none()) {
        return false;
    }
    (1..=3).filter_map(|i| caps.get(i)).all(|m| m.as_str().parse::<i64>().is_ok())
}

fn valid_base64(text: &str) -> bool {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let body = compact.trim_end_matches('=');
    compact.len().is_multiple_of(4) && compact.len() - body.len() <= 2 && body.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
}

fn valid_rfc822(t: &str) -> bool {
    let Some(at) = t.rfind('@') else {
        return false;
    };
    let (local, domain) = (&t[..at], &t[at + 1..]);
    let clean = |s: &str| !s.chars().any(|c| c.is_whitespace() || c == '@');
    !local.is_empty() && !domain.is_empty() && clean(local) && clean(domain)
}

fn valid_x500(t: &str) -> bool {
    if t.is_empty() {
        return false;
    }
    let mut pieces = vec![String::new()];
    let (mut escaped, mut quoted) = (false, false);
    for c in t.chars() {
        let current = pieces.last_mut().expect("never empty");
        if escaped {
            escaped = false;
            current.push(c);
        } else if c == '\\' {
            escaped = true;
            current.push(c);
        } else if c == '"' {
            quoted = !quoted;
            current.push(c);
        } else if c == ',' && !quoted {
            pieces.push(String::new());
        } else {
            current.push(c);
        }
    }
    pieces.iter().all(|p| p.trim().find('=').is_some_and(|i| i > 0))
}

/// The port part of a dnsName or ipAddress: empty, a number, or a range
/// whose ends may be empty.
fn valid_ports(ports: &str) -> bool {
    if ports.is_empty() || ports.contains('-') {
        return true;
    }
    // JavaScript's parseInt: leading digits after an optional sign.
    let t = ports.trim_start();
    let t = t.strip_prefix(['-', '+']).unwrap_or(t);
    let digits: String = t.chars().take_while(char::is_ascii_digit).collect();
    !digits.is_empty() && digits.parse::<i64>().is_ok()
}

fn valid_dns(t: &str) -> bool {
    let (host, ports) = t.split_once(':').unwrap_or((t, ""));
    !host.is_empty() && !host.chars().any(char::is_whitespace) && valid_ports(ports)
}

fn valid_ip(t: &str) -> bool {
    if t.is_empty() {
        return false;
    }
    let rest = if let Some(inner) = t.strip_prefix('[') {
        match inner.find(']') {
            Some(close) => &inner[close + 1..],
            None => return false,
        }
    } else {
        t.find(':').map_or("", |i| &t[i..])
    };
    valid_ports(rest.strip_prefix(':').unwrap_or(""))
}

// ---------------------------------------------------------------------------
// Building the request.
// ---------------------------------------------------------------------------

/// Categories in the order first named, every attribute asking to be
/// returned with the result: the shape `sts-xacml`'s builder makes.
#[derive(Default)]
struct Builder {
    categories: Vec<engine::Category>,
}

impl Builder {
    fn add(&mut self, category: &str, attribute_id: &str, values: Vec<String>, data_type: &str) {
        let index = match self.categories.iter().position(|c| c.category == category) {
            Some(i) => i,
            None => {
                self.categories.push(engine::Category { category: category.to_string(), has_content: false, attributes: Vec::new() });
                self.categories.len() - 1
            }
        };
        self.categories[index].attributes.push(engine::Attribute {
            attribute_id: attribute_id.to_string(),
            issuer: None,
            include_in_result: true,
            values: values.into_iter().map(|value| engine::AttributeValue { data_type: data_type.to_string(), value }).collect(),
        });
    }

    fn text(&mut self, category: &str, attribute_id: &str, values: Vec<String>) {
        self.add(category, attribute_id, values, engine::STRING);
    }

    fn build(self) -> engine::Request {
        engine::Request { return_policy_id_list: true, combined_decision: false, categories: self.categories }
    }
}

/// An empty fact is no value at all.
fn one(value: &str) -> Vec<String> {
    if value.is_empty() {
        Vec::new()
    } else {
        vec![value.to_string()]
    }
}

fn build_request(reading: &Reading, trusted: &Trusted) -> engine::Request {
    let [subject_type, subject_id, action_name, resource_type, resource_id] = &reading.required;
    let mut b = Builder::default();
    b.text(engine::ACCESS_SUBJECT, SUBJECT_ID, vec![subject_id.clone()]);
    b.text(engine::ACCESS_SUBJECT, AUTHZEN_SUBJECT_TYPE, one(subject_type));
    b.text(engine::ACTION, ACTION_ID, vec![action_name.clone()]);
    b.text(engine::RESOURCE, RESOURCE_ID, vec![resource_id.clone()]);
    b.text(engine::RESOURCE, AUTHZEN_RESOURCE_TYPE, one(resource_type));
    b.text(engine::ENVIRONMENT, PROTOCOL, vec!["authzen".into()]);
    b.text(engine::ENVIRONMENT, REALM, one(&trusted.realm));
    b.text(engine::ENVIRONMENT, AUTHZEN_CALLER, one(&trusted.caller));
    b.text(engine::ENVIRONMENT, AUTHZEN_APPLICATION, one(&trusted.application));
    b.text(engine::ENVIRONMENT, AUTHZEN_SUPPLIED, reading.supplied.clone());
    for mapped in &reading.attributes {
        b.add(&mapped.row.category, &mapped.row.attribute_id, mapped.values.clone(), &mapped.row.data_type);
    }
    b.build()
}

/// Maps one evaluation body (`subject`, `action`, `resource`, `context`)
/// through `catalogue` into the request the engine evaluates.
///
/// The caller and the application written into the request are the
/// trusted ones. An embedded PEP is bound to one application, so its scope
/// is that application alone: a `context.application` naming another is
/// refused as the service refuses an application outside a caller's scope
/// (403, `STS-AUTHZEN-0025`).
pub fn map_evaluation(body: &Value, catalogue: &Catalogue, trusted: &Trusted) -> Result<Mapped, Refusal> {
    let reading = read_evaluation(body, &catalogue.rows)?;
    if !reading.application.is_empty() && reading.application != trusted.application {
        return Err(Refusal {
            status: 403,
            code: "STS-AUTHZEN-0025",
            message: format!("context.application \"{}\" is not an application this PEP may ask about.", clip(&reading.application, 120)),
        });
    }
    let mut request = build_request(&reading, trusted);
    if trusted.fga {
        add_fga_access(&mut request, &trusted.application);
    }
    Ok(Mapped { request, supported_obligations: reading.supported_obligations })
}

// ---------------------------------------------------------------------------
// The decision back.
// ---------------------------------------------------------------------------

/// An obligation handed to the caller under the Obligations Profile.
#[derive(Debug, Clone, PartialEq)]
pub struct Handed {
    /// The registered type (`step-up`, ...) or `custom`.
    pub kind: String,
    /// The AuthZEN obligation object, as the service would hand it.
    pub obligation: Value,
}

/// A decision mapped back, fail-closed.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// `true` only on a Permit carrying nothing that can't be discharged
    /// or handed.
    pub decision: bool,
    /// An Indeterminate from a processing or syntax error: not a denial.
    pub fault: bool,
    /// The XACML decision, for the record.
    pub xacml_decision: engine::Decision,
    /// Why, in a sentence.
    pub why: String,
    /// `urn:sts:xacml:obligation:log` and the like: discharged here.
    pub discharged: Vec<String>,
    /// Obligation ids that stopped a Permit.
    pub undischargeable: Vec<String>,
    /// Handed to the caller (the Obligations Profile).
    pub handed: Vec<Handed>,
    /// Why an obligation could not be built for the Obligations Profile (a
    /// registered type without a property it requires). Any one means
    /// nothing is handed. Empty unless the profile is on and the caller
    /// declared its types.
    pub obligation_problems: Vec<String>,
}

/// The engine's answer mapped back, under the realm's obligations profile
/// and what the caller declared it supports.
///
/// The engine folds an Indeterminate's status away, so this cannot tell an
/// Indeterminate over a missing attribute (an ordinary `false` at the
/// service) from one over a processing or syntax error (a fault). It reads
/// every Indeterminate as a fault: `decision` is `false` either way, and a
/// processing error is never reported as a denial. A caller that knows the
/// status uses [`outcome_with_fault`].
pub fn outcome(response: &engine::Response, supported: Option<&[String]>, profile: bool) -> Outcome {
    // An Indeterminate over a missing attribute is an ordinary false, as at
    // the service; one over a processing or syntax error is a fault.
    let fault = response.decision == engine::Decision::Indeterminate && response.status_code != MISSING_ATTRIBUTE;
    outcome_with_fault(response, fault, supported, profile)
}

/// [`outcome`], with the caller saying whether the answer is a fault: an
/// Indeterminate over a processing or syntax error, or a root policy that
/// would not load.
pub fn outcome_with_fault(response: &engine::Response, fault: bool, supported: Option<&[String]>, profile: bool) -> Outcome {
    let mut discharged = Vec::new();
    let mut undischargeable = Vec::new();
    for obligation in &response.obligations {
        if obligation.id == LOG_OBLIGATION {
            discharged.push(obligation.id.clone());
        } else {
            undischargeable.push(obligation.id.clone());
        }
    }
    let permit = response.decision == engine::Decision::Permit;
    let mut decision = !fault && permit && undischargeable.is_empty();
    let mut why = if fault {
        format!("The PDP could not evaluate the request (it said {}).", response.decision.as_str())
    } else if !permit {
        format!(
            "The policy said {}, and anything that is not Permit is a refusal.",
            response.decision.as_str()
        )
    } else if undischargeable.is_empty() {
        "The policy said Permit.".to_string()
    } else {
        format!(
            "The policy said Permit, but the decision carries obligation(s) this PEP cannot discharge ({}); a PEP \
             that cannot fulfil an obligation must not grant the access.",
            undischargeable.join(", ")
        )
    };

    let mut handed = Vec::new();
    let mut obligation_problems = Vec::new();
    // The Obligations Profile: handed only when it is on and the caller
    // declared every type the answer carries. A caller that never heard of
    // the profile would read `true` and grant without carrying them out.
    if let (false, true, Some(supported)) = (fault, profile, supported) {
        let (converted, problems) = profile_obligations(response);
        obligation_problems = problems;
        let all_declared = !converted.is_empty()
            && obligation_problems.is_empty()
            && converted.iter().all(|h| supported.contains(&h.kind));
        if all_declared {
            handed = converted;
            undischargeable.clear();
            if permit {
                decision = true;
                why = "The policy said Permit, with obligations the caller declared it carries out.".into();
            }
        }
    }

    Outcome {
        decision,
        fault,
        xacml_decision: response.decision,
        why,
        discharged,
        undischargeable,
        handed,
        obligation_problems,
    }
}

/// The answer's obligations as the Obligations Profile's, skipping the log
/// obligation: `urn:sts:xacml:authzen:obligation:<type>` is that registered
/// type and anything else is `custom` (its XACML id kept as
/// `xacml_obligation`); each assignment is a property named by the last
/// `:`-segment of its attribute id, repeated names collected into an
/// array, and a type's array properties always one.
fn profile_obligations(response: &engine::Response) -> (Vec<Handed>, Vec<String>) {
    let mut handed: Vec<Handed> = Vec::new();
    let mut problems = Vec::new();
    for obligation in &response.obligations {
        if obligation.id == LOG_OBLIGATION {
            continue;
        }
        let named = obligation.id.strip_prefix(OBLIGATION_PREFIX).unwrap_or("");
        let registered = OBLIGATION_TYPES.iter().find(|(name, _, _)| *name == named);
        let (kind, required, arrays): (&str, &[&str], &[&str]) = match registered {
            Some((name, required, arrays)) => (name, required, arrays),
            None => ("custom", &[], &[]),
        };
        let mut properties = Map::new();
        if kind == "custom" {
            properties.insert("xacml_obligation".into(), Value::String(obligation.id.clone()));
        }
        for assignment in &obligation.assignments {
            let name = assignment.attribute_id.rsplit(':').next().unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let value = Value::String(assignment.value.clone());
            match properties.get_mut(name) {
                None if arrays.contains(&name) => {
                    properties.insert(name.to_string(), Value::Array(vec![value]));
                }
                None => {
                    properties.insert(name.to_string(), value);
                }
                Some(Value::Array(items)) => items.push(value),
                Some(held) => {
                    let first = held.take();
                    *held = Value::Array(vec![first, value]);
                }
            }
        }
        let missing: Vec<&str> =
            required.iter().copied().filter(|name| properties.get(*name).is_none_or(|v| v.as_str() == Some(""))).collect();
        if !missing.is_empty() {
            problems.push(format!("{} is a {} obligation without {}", obligation.id, kind, missing.join(", ")));
            continue;
        }
        let obligation = json!({
            "id": format!("obligation-{}", handed.len() + 1),
            "type": kind,
            "properties": Value::Object(properties),
        });
        handed.push(Handed { kind: kind.to_string(), obligation });
    }
    (handed, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_read_as_javascript_writes_them() {
        assert_eq!(number_text(1.0), "1");
        assert_eq!(number_text(1.5), "1.5");
        assert_eq!(number_text(-0.25), "-0.25");
        assert_eq!(number_text(1e21), "1e+21");
        assert_eq!(number_text(1e20), "100000000000000000000");
        assert_eq!(number_text(1.5e-7), "1.5e-7");
        assert_eq!(number_text(0.000001), "0.000001");
        assert_eq!(number_text(123.456), "123.456");
        assert_eq!(lexical(INTEGER, &json!(3.0)).as_deref(), Some("3"));
        assert!(lexical(INTEGER, &json!(1.5)).is_none());
        assert!(lexical(INTEGER, &json!(9007199254740993u64)).is_none());
        assert!(lexical(engine::STRING, &json!(3)).is_none());
        assert_eq!(lexical(BOOLEAN, &json!(true)).as_deref(), Some("true"));
    }

    #[test]
    fn keys_follow_object_keys_order() {
        let value = json!({ "b": 1, "10": 1, "a": 1, "2": 1, "01": 1 });
        let keys: Vec<&str> = keys_in_js_order(value.as_object().unwrap()).into_iter().map(String::as_str).collect();
        assert_eq!(keys, ["2", "10", "b", "a", "01"]);
    }

    #[test]
    fn lexical_forms_parse_by_the_engines_rules() {
        assert!(lexically_valid(DATETIME, "2026-01-02T03:04:05Z"));
        assert!(!lexically_valid(DATETIME, "2026-13-02T03:04:05Z"));
        assert!(lexically_valid(DAYTIME_DURATION, "P1DT2H"));
        assert!(!lexically_valid(DAYTIME_DURATION, "P1DT"));
        assert!(lexically_valid(YEARMONTH_DURATION, "-P1Y2M"));
        assert!(!lexically_valid(YEARMONTH_DURATION, "P"));
        assert!(lexically_valid(BASE64BINARY, "AAA="));
        assert!(!lexically_valid(BASE64BINARY, "A==="));
        assert!(lexically_valid(IPADDRESS, "[::1]:443"));
        assert!(!lexically_valid(IPADDRESS, "[::1"));
        assert!(lexically_valid(X500NAME, "cn=a\\,b,o=x"));
        assert!(!lexically_valid(X500NAME, "=a"));
        assert!(lexically_valid(RFC822NAME, "a@example.com"));
        assert!(!lexically_valid(RFC822NAME, "a@"));
    }
}
