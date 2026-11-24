// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! XACML 3.0 Policy and PolicySet XML into the compiled tree.
//!
//! Everything a request cannot change is settled here, once per pull:
//!
//! - every Policy and PolicySet becomes a node of one arena, and a
//!   `PolicyIdReference` or `PolicySetIdReference` becomes the index of the
//!   row it names, so evaluation follows an index, never an identifier;
//! - designators are interned (one table, one cache slot per request);
//! - literals are parsed (a bad one stays, to be Indeterminate when it is
//!   evaluated, as the reference engine has it);
//! - functions and combining algorithms are resolved to enums, and a
//!   regexp-match's literal pattern is compiled;
//! - variable references become indices.
//!
//! A malformed document, an unknown function or algorithm, an unresolvable
//! reference or variable, and a cycle are compile errors. Nothing else is
//! validated: the service validates at deploy.

use std::collections::HashMap;

use roxmltree::{Document, Node as XmlNode};

use super::function::{self, Bag, Func, Pattern};
use super::index::TargetIndex;
use super::value::{self, canonical_uri, Type, Value};
use super::xsd_regex;
use super::{CompileError, Designator, PolicyDocument};

/// How deep an expression, a target or a policy tree may nest. Evaluation
/// recurses, so the depth is bounded here rather than left to the stack.
const MAX_DEPTH: usize = 200;

/// How deep a document's elements may nest. roxmltree's parser recurses
/// once per level with no limit of its own, so a deeper document is refused
/// before it is parsed: thousands of levels would overflow the stack.
const MAX_XML_DEPTH: usize = 256;

#[derive(Debug, Clone)]
pub(crate) enum Expr {
    Literal(Bag),
    /// A literal whose lexical form does not parse at its type.
    BadLiteral,
    Designator {
        id: u32,
        must_be_present: bool,
    },
    /// An AttributeSelector: no XPath is evaluated, so it is Indeterminate.
    Selector,
    Variable(u32),
    Apply {
        func: Func,
        args: Box<[Expr]>,
    },
    /// A function as an argument of a higher-order function.
    Function(Func),
}

#[derive(Debug)]
pub(crate) struct Match {
    pub(crate) func: Func,
    pub(crate) literal: Expr,
    pub(crate) attribute: Expr,
}

/// `AnyOf`s, all of which must match; each a list of `AllOf`s, one of which
/// must; each a list of `Match`es, all of which must. Empty matches all.
pub(crate) type Target = Vec<Vec<Vec<Match>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Effect {
    Permit,
    Deny,
}

impl Effect {
    fn parse(text: &str) -> Option<Effect> {
        match text {
            "Permit" => Some(Effect::Permit),
            "Deny" => Some(Effect::Deny),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AssignmentExpr {
    pub(crate) attribute_id: String,
    pub(crate) category: Option<String>,
    pub(crate) issuer: Option<String>,
    pub(crate) expr: Expr,
}

/// An ObligationExpression or AdviceExpression.
#[derive(Debug)]
pub(crate) struct Holder {
    pub(crate) id: String,
    /// FulfillOn or AppliesTo; `None` (neither Permit nor Deny) never fires.
    pub(crate) on: Option<Effect>,
    pub(crate) assignments: Vec<AssignmentExpr>,
}

#[derive(Debug)]
pub(crate) struct Rule {
    pub(crate) effect: Effect,
    pub(crate) target: Target,
    pub(crate) condition: Option<Expr>,
    pub(crate) obligations: Vec<Holder>,
    pub(crate) advice: Vec<Holder>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Alg {
    DenyOverrides,
    PermitOverrides,
    DenyUnlessPermit,
    PermitUnlessDeny,
    FirstApplicable,
    OnlyOneApplicable,
    /// The 1.0 rule-combining overrides; the effect is the overriding one.
    LegacyRuleOverrides(Effect),
    /// The 1.0 policy-combining overrides.
    LegacyPolicyOverrides(Effect),
}

#[derive(Debug)]
pub(crate) enum Body {
    Rules(Vec<Rule>),
    /// Arena indices: inline children and resolved references alike.
    Children(Vec<u32>),
}

/// A Policy or PolicySet.
#[derive(Debug)]
pub(crate) struct Node {
    pub(crate) id: String,
    pub(crate) target: Target,
    pub(crate) alg: Alg,
    pub(crate) body: Body,
    /// Skips children whose target cannot match; built when it would help.
    pub(crate) index: Option<TargetIndex>,
    pub(crate) obligations: Vec<Holder>,
    pub(crate) advice: Vec<Holder>,
}

/// The compiled set.
#[derive(Debug)]
pub(crate) struct Tree {
    pub(crate) nodes: Vec<Node>,
    pub(crate) root: u32,
    /// Every variable definition of every policy, by global index.
    pub(crate) variables: Vec<Expr>,
    /// The interned designators, and each one's type.
    pub(crate) designators: Vec<Designator>,
    pub(crate) designator_types: Vec<Type>,
}

type Res<T> = Result<T, String>;

/// A reference waiting for every row to be read.
struct PendingReference {
    node: u32,
    slot: usize,
    target: String,
    row: usize,
}

struct Compiler {
    nodes: Vec<Node>,
    variables: Vec<Expr>,
    designators: Vec<Designator>,
    designator_types: Vec<Type>,
    interned: HashMap<Designator, u32>,
    pending: Vec<PendingReference>,
    /// The row being compiled.
    row: usize,
}

pub(crate) fn compile(rows: &[PolicyDocument]) -> Result<Tree, CompileError> {
    let fail = |policy_id: &str, message: String| CompileError { policy_id: policy_id.to_string(), message };
    let roots: Vec<&PolicyDocument> = rows.iter().filter(|r| r.is_root).collect();
    if roots.len() != 1 {
        let ids: Vec<&str> = roots.iter().map(|r| r.policy_id.as_str()).collect();
        return Err(fail(
            &ids.join(", "),
            format!("a set needs exactly one root row, and this one has {}", roots.len()),
        ));
    }
    let mut compiler = Compiler {
        nodes: Vec::new(),
        variables: Vec::new(),
        designators: Vec::new(),
        designator_types: Vec::new(),
        interned: HashMap::new(),
        pending: Vec::new(),
        row: 0,
    };
    let mut by_id: HashMap<&str, u32> = HashMap::new();
    let mut root = 0;
    for (i, row) in rows.iter().enumerate() {
        compiler.row = i;
        let node = compiler.document(&row.document).map_err(|m| fail(&row.policy_id, m))?;
        if by_id.insert(row.policy_id.as_str(), node).is_some() {
            return Err(fail(&row.policy_id, "two rows of the set carry this policy id".into()));
        }
        if row.is_root {
            root = node;
        }
    }
    for reference in std::mem::take(&mut compiler.pending) {
        let row = &rows[reference.row];
        let target = *by_id.get(reference.target.as_str()).ok_or_else(|| {
            fail(&row.policy_id, format!("the reference to \"{}\" names no row of the set", reference.target))
        })?;
        if let Body::Children(children) = &mut compiler.nodes[reference.node as usize].body {
            children[reference.slot] = target;
        }
    }
    let mut tree = Tree {
        nodes: compiler.nodes,
        root,
        variables: compiler.variables,
        designators: compiler.designators,
        designator_types: compiler.designator_types,
    };
    check_acyclic(&tree).map_err(|node| {
        fail(&tree.nodes[node as usize].id, "the policy references itself, directly or through others".into())
    })?;
    if let Some(node) = too_deep(&tree) {
        let row = by_id.iter().find(|(_, &n)| n == node).map(|(id, _)| id.to_string());
        let id = row.unwrap_or_else(|| tree.nodes[node as usize].id.clone());
        return Err(fail(&id, format!("policies nest more than {} deep", MAX_DEPTH)));
    }
    build_indexes(&mut tree);
    Ok(tree)
}

/// A cycle through references, found by depth-first search; the node where
/// it closes.
fn check_acyclic(tree: &Tree) -> Result<(), u32> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        New,
        Open,
        Done,
    }
    let mut marks = vec![Mark::New; tree.nodes.len()];
    for start in 0..tree.nodes.len() as u32 {
        if marks[start as usize] != Mark::New {
            continue;
        }
        // An explicit stack: a long chain of references must not overflow.
        let mut stack = vec![(start, 0usize)];
        marks[start as usize] = Mark::Open;
        while let Some((node, next)) = stack.pop() {
            let children = match &tree.nodes[node as usize].body {
                Body::Children(c) => c.as_slice(),
                Body::Rules(_) => &[],
            };
            if let Some(&child) = children.get(next) {
                stack.push((node, next + 1));
                match marks[child as usize] {
                    Mark::Open => return Err(node),
                    Mark::New => {
                        marks[child as usize] = Mark::Open;
                        stack.push((child, 0));
                    }
                    Mark::Done => {}
                }
            } else {
                marks[node as usize] = Mark::Done;
            }
        }
    }
    Ok(())
}

/// A node from which the tree is more than [`MAX_DEPTH`] deep.
fn too_deep(tree: &Tree) -> Option<u32> {
    // Children have higher arena indices than inline parents, but a
    // reference may point anywhere; the graph is acyclic, so iterate to a
    // fixed point (bounded by the depth limit).
    let mut depth = vec![1usize; tree.nodes.len()];
    for _ in 0..=MAX_DEPTH {
        let mut changed = false;
        for (i, node) in tree.nodes.iter().enumerate() {
            if let Body::Children(children) = &node.body {
                let deepest = children.iter().map(|&c| depth[c as usize]).max().unwrap_or(0) + 1;
                if deepest > depth[i] {
                    depth[i] = deepest;
                    changed = true;
                }
                if depth[i] > MAX_DEPTH {
                    return Some(i as u32);
                }
            }
        }
        if !changed {
            return None;
        }
    }
    None
}

fn build_indexes(tree: &mut Tree) {
    for i in 0..tree.nodes.len() {
        let index = {
            let node = &tree.nodes[i];
            match &node.body {
                Body::Rules(rules) => TargetIndex::build(rules.iter().map(|r| &r.target)),
                Body::Children(children) => {
                    TargetIndex::build(children.iter().map(|&c| &tree.nodes[c as usize].target))
                }
            }
        };
        tree.nodes[i].index = index;
    }
}

/// Whether a document's elements nest deeper than `limit`, by a linear scan
/// that over-counts rather than under-counts: every `<` that does not open
/// a comment, CDATA section, processing instruction, declaration or end
/// tag counts as an element. roxmltree stops at the first malformed token,
/// so it never recurses deeper than this count.
fn nests_deeper_than(xml: &str, limit: usize) -> bool {
    let bytes = xml.as_bytes();
    let skip_past = |from: usize, end: &[u8]| -> usize {
        bytes[from..].windows(end.len()).position(|w| w == end).map_or(bytes.len(), |at| from + at + end.len())
    };
    let (mut i, mut depth) = (0, 0usize);
    while let Some(at) = bytes[i..].iter().position(|&b| b == b'<') {
        i += at;
        let rest = &bytes[i..];
        if rest.starts_with(b"<!--") {
            i = skip_past(i, b"-->");
        } else if rest.starts_with(b"<![CDATA[") {
            i = skip_past(i, b"]]>");
        } else if rest.starts_with(b"<?") {
            i = skip_past(i, b"?>");
        } else if rest.starts_with(b"<!") {
            i = skip_past(i, b">");
        } else if rest.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            i = skip_past(i, b">");
        } else {
            // A start tag: to its `>`, past quoted attribute values.
            let mut quote = None;
            let mut j = i + 1;
            while j < bytes.len() {
                match (quote, bytes[j]) {
                    (None, b'"' | b'\'') => quote = Some(bytes[j]),
                    (Some(q), b) if b == q => quote = None,
                    (None, b'>') => break,
                    _ => {}
                }
                j += 1;
            }
            if bytes.get(j.wrapping_sub(1)) != Some(&b'/') || j == i + 1 {
                depth += 1;
                if depth > limit {
                    return true;
                }
            }
            i = j.saturating_add(1).min(bytes.len());
        }
    }
    false
}

// ---------------------------------------------------------------------------
// DOM helpers, all by local name.
// ---------------------------------------------------------------------------

fn elements<'a, 'i>(node: XmlNode<'a, 'i>) -> impl Iterator<Item = XmlNode<'a, 'i>> {
    node.children().filter(XmlNode::is_element)
}

fn named<'a, 'i>(node: XmlNode<'a, 'i>, name: &'static str) -> impl Iterator<Item = XmlNode<'a, 'i>> {
    elements(node).filter(move |c| c.tag_name().name() == name)
}

fn first<'a, 'i>(node: XmlNode<'a, 'i>, name: &'static str) -> Option<XmlNode<'a, 'i>> {
    named(node, name).next()
}

/// An attribute; an empty one counts as absent.
fn attribute(node: XmlNode<'_, '_>, name: &str) -> Option<String> {
    node.attribute(name).filter(|v| !v.is_empty()).map(str::to_string)
}

fn required(node: XmlNode<'_, '_>, name: &str) -> Res<String> {
    attribute(node, name).ok_or_else(|| format!("<{}> lacks its {} attribute", node.tag_name().name(), name))
}

fn flag(node: XmlNode<'_, '_>, name: &str) -> bool {
    matches!(node.attribute(name), Some("true" | "1"))
}

fn text_of(node: XmlNode<'_, '_>) -> String {
    node.descendants().filter(XmlNode::is_text).filter_map(|n| n.text()).collect()
}

/// The one expression element a Condition, VariableDefinition or
/// AttributeAssignmentExpression holds.
fn only_child<'a, 'i>(node: XmlNode<'a, 'i>) -> Res<XmlNode<'a, 'i>> {
    let mut children = elements(node);
    match (children.next(), children.next()) {
        (Some(child), None) => Ok(child),
        _ => Err(format!("<{}> must hold exactly one expression", node.tag_name().name())),
    }
}

fn algorithm(uri: &str, in_policy_set: bool) -> Option<Alg> {
    let rest = uri.strip_prefix("urn:oasis:names:tc:xacml:")?;
    let (version, rest) = rest.split_once(':')?;
    let name = if in_policy_set {
        rest.strip_prefix("policy-combining-algorithm:")
    } else {
        rest.strip_prefix("rule-combining-algorithm:")
    };
    // The reference accepts either level's identifiers at either level.
    let name = name
        .or_else(|| rest.strip_prefix("policy-combining-algorithm:"))
        .or_else(|| rest.strip_prefix("rule-combining-algorithm:"))?;
    let policy_level = rest.starts_with("policy-");
    let legacy =
        |effect| if policy_level { Alg::LegacyPolicyOverrides(effect) } else { Alg::LegacyRuleOverrides(effect) };
    Some(match (version, name) {
        ("3.0", "deny-overrides" | "ordered-deny-overrides") => Alg::DenyOverrides,
        ("3.0", "permit-overrides" | "ordered-permit-overrides") => Alg::PermitOverrides,
        ("3.0", "deny-unless-permit") => Alg::DenyUnlessPermit,
        ("3.0", "permit-unless-deny") => Alg::PermitUnlessDeny,
        ("1.0", "first-applicable") => Alg::FirstApplicable,
        ("1.0", "only-one-applicable") if policy_level && in_policy_set => Alg::OnlyOneApplicable,
        ("1.0", "deny-overrides") | ("1.1", "ordered-deny-overrides") => legacy(Effect::Deny),
        ("1.0", "permit-overrides") | ("1.1", "ordered-permit-overrides") => legacy(Effect::Permit),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// The walk.
// ---------------------------------------------------------------------------

impl Compiler {
    fn document(&mut self, xml: &str) -> Res<u32> {
        if nests_deeper_than(xml, MAX_XML_DEPTH) {
            return Err(format!("the document's elements nest more than {} deep", MAX_XML_DEPTH));
        }
        let document = Document::parse(xml).map_err(|e| format!("the document is not well-formed XML: {}", e))?;
        let root = document.root_element();
        match root.tag_name().name() {
            "Policy" => self.policy(root, 1),
            "PolicySet" => self.policy_set(root, 1),
            other => Err(format!("a policy document's root must be <Policy> or <PolicySet>, not <{}>", other)),
        }
    }

    fn push(&mut self, node: Node) -> u32 {
        self.nodes.push(node);
        (self.nodes.len() - 1) as u32
    }

    fn policy_set(&mut self, node: XmlNode<'_, '_>, depth: usize) -> Res<u32> {
        if depth > MAX_DEPTH {
            return Err(format!("policies nest more than {} deep", MAX_DEPTH));
        }
        let id = required(node, "PolicySetId")?;
        let alg_id = required(node, "PolicyCombiningAlgId")?;
        let alg =
            algorithm(&alg_id, true).ok_or_else(|| format!("unknown policy-combining algorithm \"{}\"", alg_id))?;
        let target = self.target(first(node, "Target"))?;
        let mut children = Vec::new();
        let mut references = Vec::new();
        for child in elements(node) {
            match child.tag_name().name() {
                "Policy" => children.push(self.policy(child, depth + 1)?),
                "PolicySet" => children.push(self.policy_set(child, depth + 1)?),
                "PolicyIdReference" | "PolicySetIdReference" => {
                    references.push((children.len(), text_of(child).trim().to_string()));
                    children.push(u32::MAX);
                }
                _ => {}
            }
        }
        let obligations =
            self.holders(node, "ObligationExpressions", "ObligationExpression", "ObligationId", "FulfillOn", None)?;
        let advice = self.holders(node, "AdviceExpressions", "AdviceExpression", "AdviceId", "AppliesTo", None)?;
        let index =
            self.push(Node { id, target, alg, body: Body::Children(children), index: None, obligations, advice });
        for (slot, target) in references {
            self.pending.push(PendingReference { node: index, slot, target, row: self.row });
        }
        Ok(index)
    }

    fn policy(&mut self, node: XmlNode<'_, '_>, depth: usize) -> Res<u32> {
        if depth > MAX_DEPTH {
            return Err(format!("policies nest more than {} deep", MAX_DEPTH));
        }
        let id = required(node, "PolicyId")?;
        let alg_id = required(node, "RuleCombiningAlgId")?;
        let alg =
            algorithm(&alg_id, false).ok_or_else(|| format!("unknown rule-combining algorithm \"{}\"", alg_id))?;

        // Variables first, so a reference may name a later definition.
        let mut scope: HashMap<String, u32> = HashMap::new();
        let definitions: Vec<_> = named(node, "VariableDefinition").collect();
        let base = self.variables.len() as u32;
        for (i, definition) in definitions.iter().enumerate() {
            let variable = required(*definition, "VariableId")?;
            if scope.insert(variable.clone(), base + i as u32).is_some() {
                return Err(format!("VariableId \"{}\" is defined twice", variable));
            }
            self.variables.push(Expr::BadLiteral);
        }
        for (i, definition) in definitions.iter().enumerate() {
            let expr = self.expression(only_child(*definition)?, Some(&scope), 0)?;
            self.variables[base as usize + i] = expr;
        }
        self.check_variables(base, definitions.len())?;

        let target = self.target(first(node, "Target"))?;
        let mut rules = Vec::new();
        let mut rule_ids = std::collections::HashSet::new();
        for rule in named(node, "Rule") {
            let rule_id = required(rule, "RuleId")?;
            if !rule_ids.insert(rule_id.clone()) {
                return Err(format!("RuleId \"{}\" appears twice", rule_id));
            }
            rules.push(self.rule(rule, &scope)?);
        }
        let obligations = self.holders(
            node,
            "ObligationExpressions",
            "ObligationExpression",
            "ObligationId",
            "FulfillOn",
            Some(&scope),
        )?;
        let advice =
            self.holders(node, "AdviceExpressions", "AdviceExpression", "AdviceId", "AppliesTo", Some(&scope))?;
        Ok(self.push(Node { id, target, alg, body: Body::Rules(rules), index: None, obligations, advice }))
    }

    /// A variable that depends on itself, directly or not, is refused.
    fn check_variables(&self, base: u32, count: usize) -> Res<()> {
        fn references(expr: &Expr, out: &mut Vec<u32>) {
            match expr {
                Expr::Variable(v) => out.push(*v),
                Expr::Apply { args, .. } => args.iter().for_each(|a| references(a, out)),
                _ => {}
            }
        }
        let depends: Vec<Vec<usize>> = (0..count)
            .map(|i| {
                let mut found = Vec::new();
                references(&self.variables[base as usize + i], &mut found);
                found.into_iter().map(|v| (v - base) as usize).collect()
            })
            .collect();
        // Depth-first, with an explicit stack: 0 new, 1 open, 2 done.
        let mut marks = vec![0u8; count];
        for start in 0..count {
            if marks[start] != 0 {
                continue;
            }
            marks[start] = 1;
            let mut stack = vec![(start, 0usize)];
            while let Some((v, next)) = stack.pop() {
                match depends[v].get(next) {
                    Some(&w) => {
                        stack.push((v, next + 1));
                        match marks[w] {
                            1 => {
                                return Err("a VariableDefinition refers to itself, directly or through another".into())
                            }
                            0 => {
                                marks[w] = 1;
                                stack.push((w, 0));
                            }
                            _ => {}
                        }
                    }
                    None => marks[v] = 2,
                }
            }
        }
        Ok(())
    }

    fn rule(&mut self, node: XmlNode<'_, '_>, scope: &HashMap<String, u32>) -> Res<Rule> {
        let effect_text = required(node, "Effect")?;
        let effect =
            Effect::parse(&effect_text).ok_or_else(|| format!("a Rule's Effect cannot be \"{}\"", effect_text))?;
        let condition = match first(node, "Condition") {
            Some(condition) => Some(self.expression(only_child(condition)?, Some(scope), 0)?),
            None => None,
        };
        Ok(Rule {
            effect,
            target: self.target(first(node, "Target"))?,
            condition,
            obligations: self.holders(
                node,
                "ObligationExpressions",
                "ObligationExpression",
                "ObligationId",
                "FulfillOn",
                Some(scope),
            )?,
            advice: self.holders(
                node,
                "AdviceExpressions",
                "AdviceExpression",
                "AdviceId",
                "AppliesTo",
                Some(scope),
            )?,
        })
    }

    fn holders(
        &mut self,
        parent: XmlNode<'_, '_>,
        wrapper: &'static str,
        item: &'static str,
        id_attribute: &str,
        on_attribute: &str,
        scope: Option<&HashMap<String, u32>>,
    ) -> Res<Vec<Holder>> {
        let Some(container) = first(parent, wrapper) else {
            return Ok(Vec::new());
        };
        let mut holders = Vec::new();
        for node in named(container, item) {
            let mut assignments = Vec::new();
            for assignment in named(node, "AttributeAssignmentExpression") {
                assignments.push(AssignmentExpr {
                    attribute_id: required(assignment, "AttributeId")?,
                    category: attribute(assignment, "Category"),
                    issuer: attribute(assignment, "Issuer"),
                    expr: self.expression(only_child(assignment)?, scope, 0)?,
                });
            }
            holders.push(Holder {
                id: required(node, id_attribute)?,
                on: Effect::parse(&required(node, on_attribute)?),
                assignments,
            });
        }
        Ok(holders)
    }

    fn target(&mut self, node: Option<XmlNode<'_, '_>>) -> Res<Target> {
        let Some(node) = node else {
            return Ok(Vec::new());
        };
        let mut target = Vec::new();
        for any_of in named(node, "AnyOf") {
            let mut alls = Vec::new();
            for all_of in named(any_of, "AllOf") {
                let matches = named(all_of, "Match").map(|m| self.match_element(m)).collect::<Res<Vec<_>>>()?;
                if matches.is_empty() {
                    return Err("<AllOf> must hold at least one <Match>".into());
                }
                alls.push(matches);
            }
            if alls.is_empty() {
                return Err("<AnyOf> must hold at least one <AllOf>".into());
            }
            target.push(alls);
        }
        Ok(target)
    }

    fn match_element(&mut self, node: XmlNode<'_, '_>) -> Res<Match> {
        let match_id = required(node, "MatchId")?;
        let func = function::lookup(&match_id).ok_or_else(|| format!("unknown function \"{}\"", match_id))?;
        let literal = first(node, "AttributeValue").ok_or("<Match> must hold an <AttributeValue>")?;
        let attribute = first(node, "AttributeDesignator")
            .or_else(|| first(node, "AttributeSelector"))
            .ok_or("<Match> must hold an <AttributeDesignator> or an <AttributeSelector>")?;
        let literal = self.expression(literal, None, 0)?;
        let func = precompile(func, Some(&literal));
        Ok(Match { func, literal, attribute: self.expression(attribute, None, 0)? })
    }

    fn intern(&mut self, designator: Designator) -> u32 {
        if let Some(&id) = self.interned.get(&designator) {
            return id;
        }
        let id = self.designators.len() as u32;
        self.designator_types.push(Type::from_uri(&designator.data_type));
        self.designators.push(designator.clone());
        self.interned.insert(designator, id);
        id
    }

    fn expression(&mut self, node: XmlNode<'_, '_>, scope: Option<&HashMap<String, u32>>, depth: usize) -> Res<Expr> {
        if depth > MAX_DEPTH {
            return Err(format!("an expression nests more than {} deep", MAX_DEPTH));
        }
        match node.tag_name().name() {
            "AttributeValue" => {
                let ty = Type::from_uri(&required(node, "DataType")?);
                Ok(match value::parse(ty, &text_of(node)) {
                    Some(v) => Expr::Literal(Bag::one(ty, v)),
                    None => Expr::BadLiteral,
                })
            }
            "AttributeDesignator" => {
                let designator = Designator {
                    category: required(node, "Category")?,
                    attribute_id: required(node, "AttributeId")?,
                    data_type: canonical_uri(&required(node, "DataType")?).to_string(),
                    issuer: attribute(node, "Issuer"),
                };
                Ok(Expr::Designator { id: self.intern(designator), must_be_present: flag(node, "MustBePresent") })
            }
            "AttributeSelector" => {
                for name in ["Category", "Path", "DataType"] {
                    required(node, name)?;
                }
                Ok(Expr::Selector)
            }
            "Apply" => {
                let function_id = required(node, "FunctionId")?;
                let func =
                    function::lookup(&function_id).ok_or_else(|| format!("unknown function \"{}\"", function_id))?;
                let args = elements(node)
                    .filter(|c| c.tag_name().name() != "Description")
                    .map(|c| self.expression(c, scope, depth + 1))
                    .collect::<Res<Vec<_>>>()?;
                let func = precompile(func, args.first());
                Ok(Expr::Apply { func, args: args.into_boxed_slice() })
            }
            "Function" => {
                let function_id = required(node, "FunctionId")?;
                Ok(Expr::Function(
                    function::lookup(&function_id).ok_or_else(|| format!("unknown function \"{}\"", function_id))?,
                ))
            }
            "VariableReference" => {
                let variable = required(node, "VariableId")?;
                scope.and_then(|s| s.get(&variable)).map(|&v| Expr::Variable(v)).ok_or_else(|| {
                    format!(
                        "VariableReference names \"{}\", which no VariableDefinition of the Policy defines",
                        variable
                    )
                })
            }
            other => Err(format!("<{}> is not a XACML expression", other)),
        }
    }
}

/// A regexp-match whose pattern is a literal string gets it compiled now.
fn precompile(func: Func, first_argument: Option<&Expr>) -> Func {
    match (func, first_argument) {
        (Func::RegexpMatch(ty, Pattern::Dynamic), Some(Expr::Literal(bag))) => {
            let pattern = match bag.values() {
                [Value::String(source)] => match xsd_regex::compile(source) {
                    Some(re) => Pattern::Ready(re),
                    None => Pattern::Invalid,
                },
                _ => Pattern::Dynamic,
            };
            Func::RegexpMatch(ty, pattern)
        }
        (func, _) => func,
    }
}
