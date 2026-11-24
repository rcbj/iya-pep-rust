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

use serde_json::Value;

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

impl Row {
    /// Reads one catalogue row, as the service reads a stored one: a JSON
    /// object, or a string holding one; short category and datatype names
    /// expanded; defaults applied.
    pub fn read(value: &Value) -> Result<Row, Refusal> {
        let _ = value;
        Err(Refusal { status: 500, code: "STS-AUTHZEN-0010", message: "not implemented yet".into() })
    }
}

/// The realm's catalogue as the PEP holds it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Catalogue {
    pub rows: Vec<Row>,
    /// The realm's `authzen.obligationsProfile`.
    pub obligations_profile: bool,
}

impl Catalogue {
    /// Reads the catalogue pull's body (`AuthzenCatalogue`).
    pub fn from_pull(body: &Value) -> Result<Catalogue, Refusal> {
        let _ = body;
        Err(Refusal { status: 500, code: "STS-AUTHZEN-0010", message: "not implemented yet".into() })
    }
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
}

/// One evaluation, mapped.
#[derive(Debug, Clone, PartialEq)]
pub struct Mapped {
    pub request: engine::Request,
    /// `context.supported_obligations`, when the evaluation carried it.
    pub supported_obligations: Option<Vec<String>>,
}

/// Maps one evaluation body (`subject`, `action`, `resource`, `context`)
/// through `catalogue` into the request the engine evaluates.
pub fn map_evaluation(body: &Value, catalogue: &Catalogue, trusted: &Trusted) -> Result<Mapped, Refusal> {
    let _ = (body, catalogue, trusted);
    Err(Refusal { status: 500, code: "STS-AUTHZEN-0001", message: "not implemented yet".into() })
}

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
}

/// The engine's answer mapped back, under the realm's obligations profile
/// and what the caller declared it supports.
pub fn outcome(response: &engine::Response, supported: Option<&[String]>, profile: bool) -> Outcome {
    let _ = (supported, profile);
    Outcome {
        decision: false,
        fault: true,
        xacml_decision: response.decision,
        why: "not implemented yet".into(),
        discharged: Vec::new(),
        undischargeable: Vec::new(),
        handed: Vec::new(),
    }
}
