// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! Evaluation of one request against the compiled tree.
//!
//! The rules that decide the corpus, each as the reference engine has them:
//!
//! - **Seven decisions inside, four outside.** Indeterminate{D}, {P} and
//!   {DP} drive the combining algorithms and are folded once, at the end.
//! - **A missing attribute is an empty bag.** Only MustBePresent (and the
//!   function it reaches) makes it an error.
//! - **A Target's Indeterminate is not a No-match**: the rule under it is
//!   Indeterminate in its effect's direction, a policy Indeterminate{DP}.
//! - **A combiner controls evaluation**: it stops where the algorithm says,
//!   and only the children it evaluated contribute obligations, those whose
//!   decision is the combined one, then the node's own.
//! - **An obligation that cannot be evaluated** makes its rule
//!   Indeterminate; on a Policy or PolicySet it makes the whole request
//!   Indeterminate (the reference engine's failure escapes the tree there).
//!
//! Per request there are two allocations of note: the designator cache and
//! (only when the set has variables) the variable cache. A bag of one value
//! is held inline, and strings are shared, not copied.

use std::cell::RefCell;

use super::compile::{AssignmentExpr, Body, Effect, Expr, Holder, Match, Node, Rule, Target, Tree};
use super::function::{self, Bag, Indet, Status, R};
use super::value::{self, canonical_uri, Shape, Type, Value};
use super::{Assignment, Decision, Obligation, Request, Resolver, Response, ENVIRONMENT};

const CURRENT_TIME: &str = "urn:oasis:names:tc:xacml:1.0:environment:current-time";
const CURRENT_DATE: &str = "urn:oasis:names:tc:xacml:1.0:environment:current-date";
const CURRENT_DATETIME: &str = "urn:oasis:names:tc:xacml:1.0:environment:current-dateTime";

/// The seven decisions. A plain Indeterminate behaves as {DP} everywhere
/// the reference engine distinguishes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ext {
    Permit,
    Deny,
    NotApplicable,
    IndD,
    IndP,
    IndDP,
}

impl Ext {
    fn is_indeterminate(self) -> bool {
        matches!(self, Ext::IndD | Ext::IndP | Ext::IndDP)
    }

    fn of(effect: Effect) -> Ext {
        match effect {
            Effect::Permit => Ext::Permit,
            Effect::Deny => Ext::Deny,
        }
    }

    /// A rule that cannot be evaluated could only have produced its effect.
    fn failed(effect: Effect) -> Ext {
        match effect {
            Effect::Permit => Ext::IndP,
            Effect::Deny => Ext::IndD,
        }
    }
}

/// One node's result on the way up.
#[derive(Debug)]
struct Outcome {
    decision: Ext,
    /// The first failure behind this result, as the reference engine
    /// carries it: it may ride on a decision that is not Indeterminate.
    status: Option<Status>,
    obligations: Vec<Obligation>,
    advice: Vec<Obligation>,
}

impl Outcome {
    fn of(decision: Ext) -> Outcome {
        Outcome { decision, status: None, obligations: Vec::new(), advice: Vec::new() }
    }

    fn failed(decision: Ext, error: Indet) -> Outcome {
        Outcome { status: Some(error.status), ..Outcome::of(decision) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchResult {
    Match,
    NoMatch,
    Indeterminate,
}

/// One request's state.
pub(crate) struct Context<'a> {
    tree: &'a Tree,
    request: &'a Request,
    resolver: &'a dyn Resolver,
    now: i64,
    bags: RefCell<Vec<Option<R<Bag>>>>,
    variables: RefCell<Vec<Option<R<Bag>>>>,
}

pub(crate) fn evaluate(tree: &Tree, request: &Request, now: i64, resolver: &dyn Resolver) -> Response {
    let context = Context {
        tree,
        request,
        resolver,
        now,
        bags: RefCell::new(vec![None; tree.designators.len()]),
        variables: RefCell::new(vec![None; tree.variables.len()]),
    };
    let outcome = context.node(tree.root).unwrap_or_else(|error| Outcome::failed(Ext::IndDP, error));
    let decision = match outcome.decision {
        Ext::Permit => Decision::Permit,
        Ext::Deny => Decision::Deny,
        Ext::NotApplicable => Decision::NotApplicable,
        Ext::IndD | Ext::IndP | Ext::IndDP => Decision::Indeterminate,
    };
    let status_code = match (decision, outcome.status) {
        (Decision::Indeterminate, Some(status)) => status.uri(),
        _ => super::STATUS_OK,
    };
    Response {
        decision,
        obligations: outcome.obligations,
        advice: outcome.advice,
        status_code: status_code.to_string(),
    }
}

impl Context<'_> {
    // -----------------------------------------------------------------------
    // Attributes: the request, then the resolver, then (for the three
    // current-* attributes) `now`.
    // -----------------------------------------------------------------------

    fn designator(&self, id: u32) -> R<Bag> {
        let cached = self.bags.borrow().get(id as usize).cloned().flatten();
        if let Some(result) = cached {
            return result;
        }
        let result = self.resolve(id);
        if let Some(slot) = self.bags.borrow_mut().get_mut(id as usize) {
            *slot = Some(result.clone());
        }
        result
    }

    fn resolve(&self, id: u32) -> R<Bag> {
        let designator = &self.tree.designators[id as usize];
        let ty = self.tree.designator_types[id as usize];
        let mut values = Collector::default();
        let parse = |data_type: &str, lexical: &str| -> R<Option<Value>> {
            if canonical_uri(data_type) != designator.data_type {
                return Ok(None);
            }
            value::parse(ty, lexical)
                .map(Some)
                .ok_or(Indet::syntax("a request value is not a valid lexical form of its type"))
        };
        for category in self.request.categories.iter().filter(|c| c.category == designator.category) {
            for attribute in &category.attributes {
                // The issuer filters only when the designator names one.
                if attribute.attribute_id != designator.attribute_id
                    || (designator.issuer.is_some() && attribute.issuer != designator.issuer)
                {
                    continue;
                }
                for v in &attribute.values {
                    if let Some(parsed) = parse(&v.data_type, &v.value)? {
                        values.push(parsed);
                    }
                }
            }
        }
        if values.is_empty() {
            for v in self.resolver.resolve(designator).unwrap_or_default() {
                if let Some(parsed) = parse(&v.data_type, &v.value)? {
                    values.push(parsed);
                }
            }
        }
        if values.is_empty() && designator.category == ENVIRONMENT {
            let shape = match (designator.attribute_id.as_str(), ty) {
                (CURRENT_DATETIME, Type::DateTime) => Some(Shape::DateTime),
                (CURRENT_DATE, Type::Date) => Some(Shape::Date),
                (CURRENT_TIME, Type::Time) => Some(Shape::Time),
                _ => None,
            };
            if let Some(shape) = shape {
                values.push(Value::Temporal(value::now_temporal(self.now, shape)));
            }
        }
        Ok(values.into_bag(ty))
    }

    fn variable(&self, index: u32) -> R<Bag> {
        let cached = self.variables.borrow().get(index as usize).cloned().flatten();
        if let Some(result) = cached {
            return result;
        }
        // Compile refused cycles, so this recursion ends.
        let result = match self.tree.variables.get(index as usize) {
            Some(expr) => self.expr(expr),
            None => Err(Indet::syntax("an unknown variable")),
        };
        if let Some(slot) = self.variables.borrow_mut().get_mut(index as usize) {
            *slot = Some(result.clone());
        }
        result
    }

    // -----------------------------------------------------------------------
    // Expressions.
    // -----------------------------------------------------------------------

    fn expr(&self, expr: &Expr) -> R<Bag> {
        match expr {
            Expr::Literal(bag) => Ok(bag.clone()),
            Expr::BadLiteral => Err(Indet::syntax("a literal is not a valid lexical form of its type")),
            Expr::Designator { id, must_be_present } => {
                let bag = self.designator(*id)?;
                if *must_be_present && bag.len() == 0 {
                    return Err(Indet::missing("a MustBePresent attribute is absent"));
                }
                Ok(bag)
            }
            Expr::Selector => {
                Err(Indet::processing("AttributeSelector needs XPath, which this engine does not evaluate"))
            }
            Expr::Variable(index) => self.variable(*index),
            Expr::Function(_) => Err(Indet::syntax("a <Function> is only an argument of a higher-order function")),
            Expr::Apply { func, args } => {
                if func.is_lazy() {
                    return function::call_lazy(func, args, &mut |arg| self.expr(arg));
                }
                // Up to four arguments on the stack; more is rare.
                if args.len() <= 4 {
                    let mut bags: [Bag; 4] = Default::default();
                    for (slot, arg) in bags.iter_mut().zip(args.iter()) {
                        *slot = self.expr(arg)?;
                    }
                    function::call(func, &bags[..args.len()])
                } else {
                    let bags = args.iter().map(|a| self.expr(a)).collect::<R<Vec<_>>>()?;
                    function::call(func, &bags)
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Targets. The quantifier flips at each level; a No-match settles a
    // level whatever errors came before it.
    // -----------------------------------------------------------------------

    fn matches(&self, m: &Match) -> R<bool> {
        let bag = self.expr(&m.attribute)?;
        let literal = self.expr(&m.literal)?;
        // One value failing does not sink the Match; its error counts only
        // when no other value matched.
        let mut first_error = None;
        for v in bag.values() {
            match function::call(&m.func, &[literal.clone(), Bag::one(bag.ty, v.clone())]) {
                Ok(result) if matches!(result.values(), [Value::Boolean(true)]) => return Ok(true),
                Ok(_) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(false), Err)
    }

    fn target(&self, target: &Target) -> (MatchResult, Option<Indet>) {
        let mut error = None;
        for any_of in target {
            let mut any_error = None;
            let mut indeterminate = false;
            let mut matched = false;
            for all_of in any_of {
                let mut all_error = None;
                let mut no_match = false;
                for m in all_of {
                    match self.matches(m) {
                        Ok(true) => {}
                        Ok(false) => {
                            no_match = true;
                            break;
                        }
                        Err(e) => {
                            all_error.get_or_insert(e);
                        }
                    }
                }
                if no_match {
                    continue;
                }
                match all_error {
                    None => {
                        matched = true;
                        break;
                    }
                    Some(e) => {
                        indeterminate = true;
                        any_error.get_or_insert(e);
                    }
                }
            }
            if matched {
                continue;
            }
            if !indeterminate {
                return (MatchResult::NoMatch, None);
            }
            error.get_or_insert(any_error.unwrap_or(Indet::processing("a Target could not be evaluated")));
        }
        match error {
            Some(e) => (MatchResult::Indeterminate, Some(e)),
            None => (MatchResult::Match, None),
        }
    }

    // -----------------------------------------------------------------------
    // Rules.
    // -----------------------------------------------------------------------

    fn rule(&self, rule: &Rule) -> Outcome {
        let failed = Ext::failed(rule.effect);
        match self.target(&rule.target) {
            (MatchResult::NoMatch, _) => return Outcome::of(Ext::NotApplicable),
            (MatchResult::Indeterminate, error) => {
                return Outcome::failed(failed, error.unwrap_or(Indet::processing("a Target could not be evaluated")))
            }
            (MatchResult::Match, _) => {}
        }
        if let Some(condition) = &rule.condition {
            let holds = self.expr(condition).and_then(|bag| {
                bag.as_boolean().map_err(|_| Indet::processing("a Condition must evaluate to exactly one boolean"))
            });
            match holds {
                Ok(true) => {}
                Ok(false) => return Outcome::of(Ext::NotApplicable),
                Err(error) => return Outcome::failed(failed, error),
            }
        }
        let decision = Ext::of(rule.effect);
        let resolved = self
            .collect(&rule.obligations, decision)
            .and_then(|obligations| Ok((obligations, self.collect(&rule.advice, decision)?)));
        match resolved {
            Ok((obligations, advice)) => Outcome { decision, status: None, obligations, advice },
            Err(error) => Outcome::failed(failed, error),
        }
    }

    // -----------------------------------------------------------------------
    // Policies and policy sets.
    // -----------------------------------------------------------------------

    fn node(&self, index: u32) -> R<Outcome> {
        let node = &self.tree.nodes[index as usize];
        match self.target(&node.target) {
            (MatchResult::NoMatch, _) => return Ok(Outcome::of(Ext::NotApplicable)),
            (MatchResult::Indeterminate, error) => {
                return Ok(Outcome::failed(
                    Ext::IndDP,
                    error.unwrap_or(Indet::processing("a Target could not be evaluated")),
                ))
            }
            (MatchResult::Match, _) => {}
        }
        let candidates = node.index.as_ref().map(|index| index.candidates(&mut |d| self.designator(d)));
        let skip = |i: usize| candidates.as_ref().is_some_and(|c| !c.contains(i));
        let combined = match &node.body {
            Body::Rules(rules) => combine(node, rules.len(), &mut |i| {
                Ok(if skip(i) { Outcome::of(Ext::NotApplicable) } else { self.rule(&rules[i]) })
            })?,
            Body::Children(children) if node.alg == super::compile::Alg::OnlyOneApplicable => {
                match self.only_one_applicable(children, &skip)? {
                    Ok(outcome) => outcome,
                    Err(refusal) => return Ok(refusal),
                }
            }
            Body::Children(children) => combine(node, children.len(), &mut |i| {
                if skip(i) {
                    Ok(Outcome::of(Ext::NotApplicable))
                } else {
                    self.node(children[i])
                }
            })?,
        };
        self.attach(node, combined)
    }

    /// only-one-applicable: which children apply is settled before any is
    /// evaluated, because two applying is itself the error.
    fn only_one_applicable(&self, children: &[u32], skip: &dyn Fn(usize) -> bool) -> R<Result<Outcome, Outcome>> {
        let mut selected = None;
        for (i, &child) in children.iter().enumerate() {
            if skip(i) {
                continue;
            }
            match self.target(&self.tree.nodes[child as usize].target) {
                (MatchResult::Indeterminate, error) => {
                    let error = error.unwrap_or(Indet::processing("a Target could not be evaluated"));
                    return Ok(Err(Outcome::failed(Ext::IndDP, error)));
                }
                (MatchResult::Match, _) if selected.is_some() => {
                    let error = Indet::processing("more than one policy of an only-one-applicable set applies");
                    return Ok(Err(Outcome::failed(Ext::IndDP, error)));
                }
                (MatchResult::Match, _) => selected = Some(child),
                (MatchResult::NoMatch, _) => {}
            }
        }
        match selected {
            Some(child) => Ok(Ok(self.node(child)?)),
            None => Ok(Ok(Outcome::of(Ext::NotApplicable))),
        }
    }

    /// The node's own obligations and advice, when the decision is Permit
    /// or Deny.
    fn attach(&self, node: &Node, mut outcome: Outcome) -> R<Outcome> {
        if matches!(outcome.decision, Ext::Permit | Ext::Deny) {
            outcome.obligations.extend(self.collect(&node.obligations, outcome.decision)?);
            outcome.advice.extend(self.collect(&node.advice, outcome.decision)?);
        }
        Ok(outcome)
    }

    fn collect(&self, holders: &[Holder], decision: Ext) -> R<Vec<Obligation>> {
        let mut resolved = Vec::new();
        for holder in holders {
            if holder.on.map(Ext::of) != Some(decision) {
                continue;
            }
            let mut assignments = Vec::new();
            for assignment in &holder.assignments {
                self.assign(assignment, &mut assignments)?;
            }
            resolved.push(Obligation { id: holder.id.clone(), assignments });
        }
        Ok(resolved)
    }

    /// One AttributeAssignmentExpression: an assignment per value of its bag.
    fn assign(&self, assignment: &AssignmentExpr, out: &mut Vec<Assignment>) -> R<()> {
        let bag = self.expr(&assignment.expr)?;
        let data_type = bag.ty.uri().ok_or(Indet::syntax("an assignment's datatype is unknown"))?;
        for v in bag.values() {
            out.push(Assignment {
                attribute_id: assignment.attribute_id.clone(),
                category: assignment.category.clone(),
                issuer: assignment.issuer.clone(),
                data_type: data_type.to_string(),
                value: value::write(bag.ty, v).ok_or(Indet::syntax("an assignment's value cannot be written"))?,
            });
        }
        Ok(())
    }
}

/// Collects a bag's values with no allocation for zero or one of them.
#[derive(Default)]
struct Collector {
    first: Option<Value>,
    rest: Vec<Value>,
}

impl Collector {
    fn push(&mut self, v: Value) {
        if self.first.is_none() {
            self.first = Some(v);
        } else {
            self.rest.push(v);
        }
    }

    fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    fn into_bag(self, ty: Type) -> Bag {
        match self.first {
            None => Bag::empty(ty),
            Some(first) if self.rest.is_empty() => Bag::one(ty, first),
            Some(first) => {
                let mut all = Vec::with_capacity(self.rest.len() + 1);
                all.push(first);
                all.extend(self.rest);
                Bag::from_vec(ty, all)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The combining algorithms (Appendix C), evaluating children on demand.
// ---------------------------------------------------------------------------

/// What the children of one node produced so far: the obligations and
/// advice of the Permits and of the Denies, and the first status.
#[derive(Default)]
struct Gathered {
    status: Option<Status>,
    permit: (Vec<Obligation>, Vec<Obligation>),
    deny: (Vec<Obligation>, Vec<Obligation>),
}

impl Gathered {
    fn add(&mut self, outcome: Outcome) -> Ext {
        if self.status.is_none() {
            self.status = outcome.status;
        }
        let into = match outcome.decision {
            Ext::Permit => &mut self.permit,
            Ext::Deny => &mut self.deny,
            other => return other,
        };
        into.0.extend(outcome.obligations);
        into.1.extend(outcome.advice);
        outcome.decision
    }

    fn finish(self, decision: Ext) -> Outcome {
        let (obligations, advice) = match decision {
            Ext::Permit => self.permit,
            Ext::Deny => self.deny,
            _ => Default::default(),
        };
        Outcome { decision, status: self.status, obligations, advice }
    }
}

/// The extended Indeterminates the 3.0 overrides algorithms track.
#[derive(Default)]
struct Seen {
    d: bool,
    p: bool,
    dp: bool,
}

impl Seen {
    fn note(&mut self, decision: Ext) {
        match decision {
            Ext::IndD => self.d = true,
            Ext::IndP => self.p = true,
            Ext::IndDP => self.dp = true,
            _ => {}
        }
    }
}

fn combine(node: &Node, count: usize, child: &mut dyn FnMut(usize) -> R<Outcome>) -> R<Outcome> {
    use super::compile::Alg;
    let mut gathered = Gathered::default();
    let decision = match node.alg {
        Alg::DenyOverrides | Alg::PermitOverrides => {
            let (wins, loses) =
                if node.alg == Alg::DenyOverrides { (Ext::Deny, Ext::Permit) } else { (Ext::Permit, Ext::Deny) };
            let mut seen = Seen::default();
            let mut saw_loser = false;
            for i in 0..count {
                let decision = gathered.add(child(i)?);
                if decision == wins {
                    return Ok(gathered.finish(wins));
                }
                if decision == loses {
                    saw_loser = true;
                }
                seen.note(decision);
            }
            // The order of these tests is the algorithm. `win_ind` is an
            // Indeterminate that could have been the overriding decision.
            let (win_ind, lose_ind, win_ext, lose_ext) = if wins == Ext::Deny {
                (seen.d, seen.p, Ext::IndD, Ext::IndP)
            } else {
                (seen.p, seen.d, Ext::IndP, Ext::IndD)
            };
            if seen.dp || (win_ind && (lose_ind || saw_loser)) {
                Ext::IndDP
            } else if win_ind {
                win_ext
            } else if saw_loser {
                loses
            } else if lose_ind {
                lose_ext
            } else {
                Ext::NotApplicable
            }
        }
        Alg::DenyUnlessPermit | Alg::PermitUnlessDeny => {
            let (wins, otherwise) =
                if node.alg == Alg::DenyUnlessPermit { (Ext::Permit, Ext::Deny) } else { (Ext::Deny, Ext::Permit) };
            for i in 0..count {
                if gathered.add(child(i)?) == wins {
                    return Ok(gathered.finish(wins));
                }
            }
            otherwise
        }
        Alg::FirstApplicable => {
            for i in 0..count {
                match gathered.add(child(i)?) {
                    Ext::NotApplicable => continue,
                    d if d.is_indeterminate() => return Ok(gathered.finish(Ext::IndDP)),
                    d => return Ok(gathered.finish(d)),
                }
            }
            Ext::NotApplicable
        }
        Alg::LegacyRuleOverrides(effect) | Alg::LegacyPolicyOverrides(effect) => {
            let overriding = Ext::of(effect);
            let (other, could_override) =
                if effect == Effect::Deny { (Ext::Permit, Ext::IndD) } else { (Ext::Deny, Ext::IndP) };
            let (mut error, mut potential, mut saw_other) = (false, false, false);
            for i in 0..count {
                let decision = gathered.add(child(i)?);
                if decision == overriding {
                    return Ok(gathered.finish(overriding));
                }
                if decision == other {
                    saw_other = true;
                } else if decision.is_indeterminate() {
                    error = true;
                    potential |= decision == could_override || decision == Ext::IndDP;
                }
            }
            match node.alg {
                // 1.0 rules: a possible win for the overriding side is
                // Indeterminate.
                Alg::LegacyRuleOverrides(_) if potential => Ext::IndDP,
                Alg::LegacyRuleOverrides(_) if saw_other => other,
                Alg::LegacyRuleOverrides(_) if error => Ext::IndDP,
                Alg::LegacyRuleOverrides(_) => Ext::NotApplicable,
                // 1.0 policies: any error and the overriding decision wins.
                _ if error => overriding,
                _ if saw_other => other,
                _ => Ext::NotApplicable,
            }
        }
        Alg::OnlyOneApplicable => return Err(Indet::syntax("only-one-applicable combines policies, not rules")),
    };
    Ok(gathered.finish(decision))
}
