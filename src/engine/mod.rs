// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The local PDP (the `local` feature): a lightweight XACML 3.0 engine.
//!
//! It evaluates what iya-sts sends a PEP and nothing more (rcbj/iya-sts#1206,
//! D2). It is a new implementation, not a port of `sts-xacml`, which stays
//! the reference: `tests/corpus.rs` holds every decision to the pinned
//! corpus.
//!
//! - **Compiled once per pull.** [`Policies::compile`] parses each Policy and
//!   PolicySet into a compiled form: interned attribute ids, pre-built
//!   regexes, resolved references, and an index from target to policies.
//! - **Left out:** static validation (the service validates at deploy), the
//!   policy builder and ALFA, the response XML, request XML, XPath, any I/O,
//!   and any clock: `now` is handed in.
//!
//! THIS MODULE'S PUBLIC TYPES ARE THE CONTRACT with the rest of the crate.
//! Change them only together with `src/local.rs`.

use std::time::SystemTime;

/// The canonical XACML 3.0 category of the access subject.
pub const ACCESS_SUBJECT: &str = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
/// The resource category.
pub const RESOURCE: &str = "urn:oasis:names:tc:xacml:3.0:attribute-category:resource";
/// The action category.
pub const ACTION: &str = "urn:oasis:names:tc:xacml:3.0:attribute-category:action";
/// The environment category.
pub const ENVIRONMENT: &str = "urn:oasis:names:tc:xacml:3.0:attribute-category:environment";
/// `http://www.w3.org/2001/XMLSchema#string`.
pub const STRING: &str = "http://www.w3.org/2001/XMLSchema#string";

/// One policy row of a pull (`PolicyRow` of `GET /xacml/pep/policies`), and
/// of a corpus case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDocument {
    pub policy_id: String,
    /// `Policy` or `PolicySet`.
    pub kind: String,
    pub version: String,
    /// Exactly one row of a set is the root, and it is the one evaluated.
    pub is_root: bool,
    /// The XACML 3.0 Policy or PolicySet, as XML.
    pub document: String,
}

/// A typed value as a request carries it: the datatype URI and its lexical
/// form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttributeValue {
    pub data_type: String,
    pub value: String,
}

impl AttributeValue {
    /// An `xs:string` value.
    pub fn string(value: impl Into<String>) -> Self {
        Self { data_type: STRING.to_string(), value: value.into() }
    }
}

/// One attribute of a request category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub attribute_id: String,
    pub issuer: Option<String>,
    pub include_in_result: bool,
    pub values: Vec<AttributeValue>,
}

/// One category of a request. A category may appear more than once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    pub category: String,
    /// The category carried a `<Content>` element. No XPath is evaluated
    /// over it.
    pub has_content: bool,
    pub attributes: Vec<Attribute>,
}

/// A request, built in code.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Request {
    pub return_policy_id_list: bool,
    pub combined_decision: bool,
    pub categories: Vec<Category>,
}

/// What an attribute designator asks for, for the PIP.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Designator {
    pub category: String,
    pub attribute_id: String,
    pub data_type: String,
    pub issuer: Option<String>,
}

/// The decision. Extended Indeterminates are folded into `Indeterminate`,
/// as in a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Permit,
    Deny,
    NotApplicable,
    Indeterminate,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Permit => "Permit",
            Decision::Deny => "Deny",
            Decision::NotApplicable => "NotApplicable",
            Decision::Indeterminate => "Indeterminate",
        }
    }
}

/// One attribute assignment of an obligation or advice. `value` is in the
/// datatype's canonical lexical form (the corpus README, *How a package
/// compares its answer*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub attribute_id: String,
    pub category: Option<String>,
    pub issuer: Option<String>,
    pub data_type: String,
    pub value: String,
}

/// An obligation or an advice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obligation {
    pub id: String,
    pub assignments: Vec<Assignment>,
}

/// The answer to one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub decision: Decision,
    pub obligations: Vec<Obligation>,
    pub advice: Vec<Obligation>,
}

/// Why a set of policies could not be compiled. The PEP keeps the set it
/// held before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub policy_id: String,
    pub message: String,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "policy {}: {}", self.policy_id, self.message)
    }
}

impl std::error::Error for CompileError {}

/// Answers a designator the request does not satisfy. `None` is an empty
/// bag. The PEP fetches every access-subject designator before evaluation
/// (one `POST /xacml/pip`), so this is synchronous.
pub trait Resolver {
    fn resolve(&self, designator: &Designator) -> Option<Vec<AttributeValue>>;
}

/// No resolver: every designator the request does not satisfy is an empty
/// bag.
pub struct NoResolver;

impl Resolver for NoResolver {
    fn resolve(&self, _designator: &Designator) -> Option<Vec<AttributeValue>> {
        None
    }
}

/// A compiled set of policies: the root and everything it references.
pub struct Policies {
    _private: (),
}

impl Policies {
    /// Parses and compiles a pulled set. Exactly one row is the root; a
    /// reference resolves to another row of the set by `policyId`.
    pub fn compile(rows: &[PolicyDocument]) -> Result<Policies, CompileError> {
        let _ = rows;
        Err(CompileError { policy_id: String::new(), message: "the engine is not implemented yet".into() })
    }

    /// Evaluates the root against `request`, with `now` as the instant
    /// `current-time`, `current-date` and `current-dateTime` come from.
    pub fn evaluate(&self, request: &Request, now: SystemTime, resolver: &dyn Resolver) -> Response {
        let _ = (request, now, resolver);
        Response { decision: Decision::Indeterminate, obligations: Vec::new(), advice: Vec::new() }
    }

    /// Every designator in `category` the compiled set could ask for, found
    /// statically (targets, conditions, variables, obligation and advice
    /// expressions, referenced policies). Over-fetches; never misses one.
    pub fn designators(&self, category: &str) -> Vec<Designator> {
        let _ = category;
        Vec::new()
    }

    /// How many Policy and PolicySet documents were compiled.
    pub fn len(&self) -> usize {
        0
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
