// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The function library, resolved from its identifier ONCE, at compile
//! time, to a [`Func`]. Evaluation matches on the enum; no identifier is
//! looked up per request.
//!
//! **Every value is a bag.** A parameter is either one value (the bag must
//! hold exactly one, or the call is Indeterminate) or a whole bag.
//!
//! **Ten functions are lazy**: `and`, `or` and `n-of` stop early (so
//! `and(false, <missing>)` is false), and the six higher-order functions and
//! `map` take a function as their first argument. They receive their
//! argument expressions and an evaluator ([`call_lazy`]).
//!
//! The identifiers' version segments are the reference engine's: the
//! duration families, the `-from-string` conversions, the string predicates
//! and three higher-order functions are `3.0`; four regexp-matches are
//! `2.0`; the rest are `1.0`.

use std::cmp::Ordering;
use std::sync::Arc;

use regex::Regex;

use super::compile::Expr;
use super::value::{self, Type, Value, FAMILY};
use super::xsd_regex;

/// Why an Indeterminate is one: the XACML status code it reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    MissingAttribute,
    SyntaxError,
    ProcessingError,
}

impl Status {
    pub(crate) fn uri(self) -> &'static str {
        match self {
            Status::MissingAttribute => "urn:oasis:names:tc:xacml:1.0:status:missing-attribute",
            Status::SyntaxError => "urn:oasis:names:tc:xacml:1.0:status:syntax-error",
            Status::ProcessingError => "urn:oasis:names:tc:xacml:1.0:status:processing-error",
        }
    }
}

/// An evaluation failure: the expression is Indeterminate. The status is
/// the reference engine's for the same failure; the message is for a
/// debugger and nothing compares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Indet {
    pub(crate) status: Status,
    pub(crate) message: &'static str,
}

impl Indet {
    pub(crate) fn processing(message: &'static str) -> Indet {
        Indet { status: Status::ProcessingError, message }
    }

    pub(crate) fn syntax(message: &'static str) -> Indet {
        Indet { status: Status::SyntaxError, message }
    }

    pub(crate) fn missing(message: &'static str) -> Indet {
        Indet { status: Status::MissingAttribute, message }
    }
}

pub(crate) type R<T> = Result<T, Indet>;

/// A bag: its type and its values. A bag of one (every literal and most
/// function results) holds its value inline.
#[derive(Debug, Clone)]
pub(crate) struct Bag {
    pub(crate) ty: Type,
    values: Values,
}

#[derive(Debug, Clone)]
enum Values {
    Empty,
    One(Value),
    Many(Arc<[Value]>),
}

impl Default for Bag {
    fn default() -> Bag {
        Bag::empty(Type::Other)
    }
}

impl Bag {
    pub(crate) fn empty(ty: Type) -> Bag {
        Bag { ty, values: Values::Empty }
    }

    pub(crate) fn one(ty: Type, value: Value) -> Bag {
        Bag { ty, values: Values::One(value) }
    }

    pub(crate) fn boolean(b: bool) -> Bag {
        Bag::one(Type::Boolean, Value::Boolean(b))
    }

    pub(crate) fn from_vec(ty: Type, mut values: Vec<Value>) -> Bag {
        match values.len() {
            0 => Bag::empty(ty),
            1 => Bag::one(ty, values.pop().unwrap_or(Value::Boolean(false))),
            _ => Bag { ty, values: Values::Many(values.into()) },
        }
    }

    pub(crate) fn values(&self) -> &[Value] {
        match &self.values {
            Values::Empty => &[],
            Values::One(v) => std::slice::from_ref(v),
            Values::Many(vs) => vs,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.values().len()
    }

    /// The bag's one value, or Indeterminate.
    pub(crate) fn single(&self) -> R<&Value> {
        match self.values() {
            [v] => Ok(v),
            _ => Err(Indet::processing("a single-value argument was given a bag of zero or several")),
        }
    }

    /// Exactly one boolean, as `and`, `or`, `n-of`, a Condition and the
    /// higher-order functions insist.
    pub(crate) fn as_boolean(&self) -> R<bool> {
        match (self.ty, self.values()) {
            (Type::Boolean, [Value::Boolean(b)]) => Ok(*b),
            _ => Err(Indet::processing("expected exactly one boolean")),
        }
    }
}

/// A regexp-match's pattern: compiled at compile time when it is a literal.
#[derive(Debug, Clone)]
pub(crate) enum Pattern {
    Dynamic,
    Ready(Regex),
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cmp {
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arith {
    Add,
    Subtract,
    Multiply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextTest {
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HigherOrder {
    AnyOf,
    AllOf,
    AnyOfAny,
    AllOfAll,
    AllOfAny,
    AnyOfAll,
}

/// A standard function, resolved.
#[derive(Debug, Clone)]
pub(crate) enum Func {
    Equal(Type),
    Compare(Cmp),
    MakeBag(Type),
    BagSize,
    OneAndOnly(Type),
    IsIn,
    Intersection(Type),
    Union(Type),
    AtLeastOneMemberOf,
    Subset,
    SetEquals,
    And,
    Or,
    Not,
    NOf,
    IntegerArith(Arith),
    IntegerAbs,
    IntegerDivide,
    IntegerMod,
    DoubleArith(Arith),
    DoubleAbs,
    DoubleDivide,
    Round,
    Floor,
    DoubleToInteger,
    IntegerToDouble,
    /// A string needle in a string or anyURI haystack.
    Text(TextTest),
    Substring,
    NormalizeSpace,
    NormalizeToLowerCase,
    Concatenate,
    StringFrom(Type),
    FromString(Type),
    /// A date or dateTime plus (`sign` 1) or minus (-1) a duration.
    TemporalArith {
        subject: Type,
        sign: i8,
    },
    RegexpMatch(Type, Pattern),
    Rfc822NameMatch,
    X500NameMatch,
    HigherOrder(HigherOrder),
    Map,
    XPathNodeCount,
}

const PREFIX: &str = "urn:oasis:names:tc:xacml:";

/// The function an identifier names, or `None`.
pub(crate) fn lookup(uri: &str) -> Option<Func> {
    let rest = uri.strip_prefix(PREFIX)?;
    let (version, name) = rest.split_once(":function:")?;
    let (func, wanted) = by_name(name)?;
    (version == wanted).then_some(func)
}

/// A function by its short name, with the version segment it carries.
fn by_name(name: &str) -> Option<(Func, &'static str)> {
    use Func::*;
    let fixed = match name {
        "and" => Some((And, "1.0")),
        "or" => Some((Or, "1.0")),
        "not" => Some((Not, "1.0")),
        "n-of" => Some((NOf, "1.0")),
        "integer-add" => Some((IntegerArith(Arith::Add), "1.0")),
        "integer-subtract" => Some((IntegerArith(Arith::Subtract), "1.0")),
        "integer-multiply" => Some((IntegerArith(Arith::Multiply), "1.0")),
        "integer-abs" => Some((IntegerAbs, "1.0")),
        "integer-divide" => Some((IntegerDivide, "1.0")),
        "integer-mod" => Some((IntegerMod, "1.0")),
        "double-add" => Some((DoubleArith(Arith::Add), "1.0")),
        "double-subtract" => Some((DoubleArith(Arith::Subtract), "1.0")),
        "double-multiply" => Some((DoubleArith(Arith::Multiply), "1.0")),
        "double-abs" => Some((DoubleAbs, "1.0")),
        "double-divide" => Some((DoubleDivide, "1.0")),
        "round" => Some((Round, "1.0")),
        "floor" => Some((Floor, "1.0")),
        "double-to-integer" => Some((DoubleToInteger, "1.0")),
        "integer-to-double" => Some((IntegerToDouble, "1.0")),
        "string-contains" => Some((Text(TextTest::Contains), "3.0")),
        "string-starts-with" => Some((Text(TextTest::StartsWith), "3.0")),
        "string-ends-with" => Some((Text(TextTest::EndsWith), "3.0")),
        "anyURI-contains" => Some((Text(TextTest::Contains), "3.0")),
        "anyURI-starts-with" => Some((Text(TextTest::StartsWith), "3.0")),
        "anyURI-ends-with" => Some((Text(TextTest::EndsWith), "3.0")),
        "string-substring" => Some((Substring, "3.0")),
        "anyURI-substring" => Some((Substring, "3.0")),
        "string-normalize-space" => Some((NormalizeSpace, "1.0")),
        "string-normalize-to-lower-case" => Some((NormalizeToLowerCase, "1.0")),
        "string-concatenate" => Some((Concatenate, "3.0")),
        "dateTime-add-dayTimeDuration" | "dateTime-add-yearMonthDuration" => {
            Some((TemporalArith { subject: Type::DateTime, sign: 1 }, "3.0"))
        }
        "dateTime-subtract-dayTimeDuration" | "dateTime-subtract-yearMonthDuration" => {
            Some((TemporalArith { subject: Type::DateTime, sign: -1 }, "3.0"))
        }
        "date-add-yearMonthDuration" => Some((TemporalArith { subject: Type::Date, sign: 1 }, "3.0")),
        "date-subtract-yearMonthDuration" => Some((TemporalArith { subject: Type::Date, sign: -1 }, "3.0")),
        "rfc822Name-match" => Some((Rfc822NameMatch, "1.0")),
        "x500Name-match" => Some((X500NameMatch, "1.0")),
        "any-of" => Some((HigherOrder(self::HigherOrder::AnyOf), "3.0")),
        "all-of" => Some((HigherOrder(self::HigherOrder::AllOf), "3.0")),
        "any-of-any" => Some((HigherOrder(self::HigherOrder::AnyOfAny), "3.0")),
        "all-of-all" => Some((HigherOrder(self::HigherOrder::AllOfAll), "1.0")),
        "all-of-any" => Some((HigherOrder(self::HigherOrder::AllOfAny), "1.0")),
        "any-of-all" => Some((HigherOrder(self::HigherOrder::AnyOfAll), "1.0")),
        "map" => Some((Map, "3.0")),
        "xpath-node-count" => Some((XPathNodeCount, "3.0")),
        _ => None,
    };
    if fixed.is_some() {
        return fixed;
    }
    if let Some(ty) = name.strip_prefix("string-from-").and_then(family_type) {
        return Some((StringFrom(ty), "3.0"));
    }
    FAMILY.iter().find_map(|&ty| {
        let suffix = name.strip_prefix(ty.name())?.strip_prefix('-')?;
        let family_version = match ty {
            Type::DayTimeDuration | Type::YearMonthDuration => "3.0",
            _ => "1.0",
        };
        let func = match suffix {
            "from-string" => return Some((FromString(ty), "3.0")),
            "regexp-match" => {
                return match ty {
                    Type::String => Some((RegexpMatch(ty, Pattern::Dynamic), "1.0")),
                    Type::AnyUri | Type::Rfc822Name | Type::X500Name | Type::DnsName | Type::IpAddress => {
                        Some((RegexpMatch(ty, Pattern::Dynamic), "2.0"))
                    }
                    _ => None,
                }
            }
            "equal" => Equal(ty),
            "greater-than" if ty.is_ordered() => Compare(Cmp::Gt),
            "greater-than-or-equal" if ty.is_ordered() => Compare(Cmp::Ge),
            "less-than" if ty.is_ordered() => Compare(Cmp::Lt),
            "less-than-or-equal" if ty.is_ordered() => Compare(Cmp::Le),
            "bag" => MakeBag(ty),
            "bag-size" => BagSize,
            "one-and-only" => OneAndOnly(ty),
            "is-in" => IsIn,
            "intersection" => Intersection(ty),
            "union" => Union(ty),
            "at-least-one-member-of" => AtLeastOneMemberOf,
            "subset" => Subset,
            "set-equals" => SetEquals,
            _ => return None,
        };
        Some((func, family_version))
    })
}

fn family_type(name: &str) -> Option<Type> {
    FAMILY.iter().copied().find(|ty| ty.name() == name)
}

impl Func {
    /// Whether the function takes its argument expressions unevaluated.
    pub(crate) fn is_lazy(&self) -> bool {
        matches!(self, Func::And | Func::Or | Func::NOf | Func::HigherOrder(_) | Func::Map)
    }

    /// The type of the bag the function returns; `None` for `map`, whose
    /// result is its argument function's.
    pub(crate) fn returns(&self) -> Option<Type> {
        use Func::*;
        Some(match self {
            Equal(_) | Compare(_) | IsIn | AtLeastOneMemberOf | Subset | SetEquals => Type::Boolean,
            And | Or | Not | NOf | Text(..) | RegexpMatch(..) | Rfc822NameMatch | X500NameMatch => Type::Boolean,
            HigherOrder(_) => Type::Boolean,
            MakeBag(t) | OneAndOnly(t) | Intersection(t) | Union(t) | FromString(t) => *t,
            BagSize | IntegerArith(_) | IntegerAbs | IntegerDivide | IntegerMod | DoubleToInteger => Type::Integer,
            XPathNodeCount => Type::Integer,
            DoubleArith(_) | DoubleAbs | DoubleDivide | Round | Floor | IntegerToDouble => Type::Double,
            Substring | NormalizeSpace | NormalizeToLowerCase | Concatenate | StringFrom(_) => Type::String,
            TemporalArith { subject, .. } => *subject,
            Map => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// Strict functions: evaluated argument bags in, a bag out.
// ---------------------------------------------------------------------------

fn arity(args: &[Bag], n: usize) -> R<()> {
    if args.len() == n {
        Ok(())
    } else {
        Err(Indet::processing("a function was given the wrong number of arguments"))
    }
}

fn integer(v: &Value) -> R<i128> {
    match v {
        Value::Integer(i) => Ok(*i),
        _ => Err(Indet::processing("expected an integer")),
    }
}

fn double(v: &Value) -> R<f64> {
    match v {
        Value::Double(d) => Ok(*d),
        _ => Err(Indet::processing("expected a double")),
    }
}

fn text(v: &Value) -> R<&str> {
    v.text().ok_or(Indet::processing("expected a string"))
}

fn overflow() -> Indet {
    Indet::processing("integer arithmetic overflowed 128 bits")
}

fn contains(values: &[Value], candidate: &Value) -> bool {
    values.iter().any(|v| value::equal(v, candidate))
}

fn subset(left: &[Value], right: &[Value]) -> bool {
    left.iter().all(|v| contains(right, v))
}

fn string_bag(s: String) -> Bag {
    Bag::one(Type::String, Value::String(Arc::from(s)))
}

/// Applies a strict function to evaluated argument bags.
pub(crate) fn call(func: &Func, args: &[Bag]) -> R<Bag> {
    use Func::*;
    match func {
        Equal(_) => {
            arity(args, 2)?;
            let (a, b) = (args[0].single()?, args[1].single()?);
            Ok(Bag::boolean(value::equal(a, b)))
        }
        Compare(cmp) => {
            arity(args, 2)?;
            let order = value::compare(args[0].single()?, args[1].single()?)
                .ok_or(Indet::processing("the two values are not comparable"))?;
            Ok(Bag::boolean(match cmp {
                Cmp::Gt => order == Ordering::Greater,
                Cmp::Ge => order != Ordering::Less,
                Cmp::Lt => order == Ordering::Less,
                Cmp::Le => order != Ordering::Greater,
            }))
        }
        MakeBag(ty) => {
            let values = args.iter().map(|a| a.single().cloned()).collect::<R<Vec<_>>>()?;
            Ok(Bag::from_vec(*ty, values))
        }
        BagSize => {
            arity(args, 1)?;
            Ok(Bag::one(Type::Integer, Value::Integer(args[0].len() as i128)))
        }
        OneAndOnly(ty) => {
            arity(args, 1)?;
            // Nothing there and too much there are different failures.
            if args[0].len() == 0 {
                return Err(Indet::missing("one-and-only was given an empty bag"));
            }
            Ok(Bag::one(*ty, args[0].single()?.clone()))
        }
        IsIn => {
            arity(args, 2)?;
            let candidate = args[0].single()?;
            Ok(Bag::boolean(contains(args[1].values(), candidate)))
        }
        Intersection(ty) => {
            arity(args, 2)?;
            let mut out: Vec<Value> = Vec::new();
            for v in args[0].values() {
                if contains(args[1].values(), v) && !contains(&out, v) {
                    out.push(v.clone());
                }
            }
            Ok(Bag::from_vec(*ty, out))
        }
        Union(ty) => {
            arity(args, 2)?;
            let mut out: Vec<Value> = Vec::new();
            for v in args.iter().flat_map(|a| a.values()) {
                if !contains(&out, v) {
                    out.push(v.clone());
                }
            }
            Ok(Bag::from_vec(*ty, out))
        }
        AtLeastOneMemberOf => {
            arity(args, 2)?;
            Ok(Bag::boolean(args[0].values().iter().any(|v| contains(args[1].values(), v))))
        }
        Subset => {
            arity(args, 2)?;
            Ok(Bag::boolean(subset(args[0].values(), args[1].values())))
        }
        SetEquals => {
            arity(args, 2)?;
            let (a, b) = (args[0].values(), args[1].values());
            Ok(Bag::boolean(subset(a, b) && subset(b, a)))
        }
        Not => {
            arity(args, 1)?;
            match args[0].single()? {
                Value::Boolean(b) => Ok(Bag::boolean(!b)),
                _ => Err(Indet::processing("not expects a boolean")),
            }
        }
        IntegerArith(op) => {
            arity(args, 2)?;
            let (a, b) = (integer(args[0].single()?)?, integer(args[1].single()?)?);
            let result = match op {
                Arith::Add => a.checked_add(b),
                Arith::Subtract => a.checked_sub(b),
                Arith::Multiply => a.checked_mul(b),
            };
            Ok(Bag::one(Type::Integer, Value::Integer(result.ok_or_else(overflow)?)))
        }
        IntegerAbs => {
            arity(args, 1)?;
            let a = integer(args[0].single()?)?;
            Ok(Bag::one(Type::Integer, Value::Integer(a.checked_abs().ok_or_else(overflow)?)))
        }
        IntegerDivide | IntegerMod => {
            arity(args, 2)?;
            let (a, b) = (integer(args[0].single()?)?, integer(args[1].single()?)?);
            if b == 0 {
                return Err(Indet::processing("division by zero"));
            }
            // Truncation toward zero, and a remainder with the dividend's sign.
            let result = if matches!(func, IntegerDivide) { a.checked_div(b) } else { a.checked_rem(b) };
            Ok(Bag::one(Type::Integer, Value::Integer(result.ok_or_else(overflow)?)))
        }
        DoubleArith(op) => {
            arity(args, 2)?;
            let (a, b) = (double(args[0].single()?)?, double(args[1].single()?)?);
            let result = match op {
                Arith::Add => a + b,
                Arith::Subtract => a - b,
                Arith::Multiply => a * b,
            };
            Ok(Bag::one(Type::Double, Value::Double(result)))
        }
        DoubleAbs | Round | Floor => {
            arity(args, 1)?;
            let a = double(args[0].single()?)?;
            let result = match func {
                DoubleAbs => a.abs(),
                Floor => a.floor(),
                // Round half to even.
                _ if !a.is_finite() => a,
                _ => {
                    let floor = a.floor();
                    let difference = a - floor;
                    if difference > 0.5 || (difference == 0.5 && floor % 2.0 != 0.0) {
                        floor + 1.0
                    } else {
                        floor
                    }
                }
            };
            Ok(Bag::one(Type::Double, Value::Double(result)))
        }
        DoubleDivide => {
            arity(args, 2)?;
            let (a, b) = (double(args[0].single()?)?, double(args[1].single()?)?);
            if b == 0.0 {
                return Err(Indet::processing("division by zero"));
            }
            Ok(Bag::one(Type::Double, Value::Double(a / b)))
        }
        DoubleToInteger => {
            arity(args, 1)?;
            let t = double(args[0].single()?)?.trunc();
            if !t.is_finite() || t.abs() >= 1.7e38 {
                return Err(Indet::processing("double-to-integer cannot convert this value"));
            }
            Ok(Bag::one(Type::Integer, Value::Integer(t as i128)))
        }
        IntegerToDouble => {
            arity(args, 1)?;
            Ok(Bag::one(Type::Double, Value::Double(integer(args[0].single()?)? as f64)))
        }
        Text(test) => {
            arity(args, 2)?;
            let (needle, haystack) = (text(args[0].single()?)?, text(args[1].single()?)?);
            Ok(Bag::boolean(match test {
                TextTest::Contains => haystack.contains(needle),
                TextTest::StartsWith => haystack.starts_with(needle),
                TextTest::EndsWith => haystack.ends_with(needle),
            }))
        }
        Substring => {
            arity(args, 3)?;
            let subject = text(args[0].single()?)?;
            let from = integer(args[1].single()?)?;
            let to = integer(args[2].single()?)?;
            substring(subject, from, to).map(string_bag)
        }
        NormalizeSpace | NormalizeToLowerCase => {
            arity(args, 1)?;
            let s = text(args[0].single()?)?;
            Ok(string_bag(if matches!(func, NormalizeSpace) { s.trim().to_string() } else { s.to_lowercase() }))
        }
        Concatenate => {
            let mut out = String::new();
            for arg in args {
                out.push_str(text(arg.single()?)?);
            }
            Ok(string_bag(out))
        }
        StringFrom(ty) => {
            arity(args, 1)?;
            let written =
                value::write(*ty, args[0].single()?).ok_or(Indet::processing("the value is not of the type"))?;
            Ok(string_bag(written))
        }
        FromString(ty) => {
            arity(args, 1)?;
            let parsed =
                value::parse(*ty, text(args[0].single()?)?).ok_or(Indet::syntax("not a valid lexical form"))?;
            Ok(Bag::one(*ty, parsed))
        }
        TemporalArith { subject, sign } => {
            arity(args, 2)?;
            let Value::Temporal(t) = args[0].single()? else {
                return Err(Indet::processing("expected a date or dateTime"));
            };
            let result = match args[1].single()? {
                Value::YearMonth(m) => m.checked_mul(i64::from(*sign)).and_then(|m| value::add_months(t, m)),
                Value::DayTime(s) => value::add_seconds(t, f64::from(*sign) * s),
                _ => return Err(Indet::processing("expected a duration")),
            };
            Ok(Bag::one(*subject, Value::Temporal(result.ok_or(Indet::processing("the date is out of range"))?)))
        }
        RegexpMatch(ty, pattern) => {
            arity(args, 2)?;
            let source = text(args[0].single()?)?;
            let subject =
                value::write(*ty, args[1].single()?).ok_or(Indet::processing("the value is not of the type"))?;
            let matched = match pattern {
                Pattern::Ready(re) => re.is_match(&subject),
                Pattern::Invalid => return Err(Indet::processing("the regular expression is refused or invalid")),
                Pattern::Dynamic => xsd_regex::compile(source)
                    .ok_or(Indet::processing("the regular expression is refused or invalid"))?
                    .is_match(&subject),
            };
            Ok(Bag::boolean(matched))
        }
        Rfc822NameMatch => {
            arity(args, 2)?;
            let pattern = text(args[0].single()?)?;
            let Value::Rfc822(name) = args[1].single()? else {
                return Err(Indet::processing("expected an rfc822Name"));
            };
            let (local, domain) = (&name.0, &name.1);
            let matched = if let Some(at) = pattern.rfind('@') {
                pattern[..at] == **local && pattern[at + 1..].to_lowercase() == *domain
            } else if pattern.starts_with('.') {
                domain.ends_with(&pattern.to_lowercase())
            } else {
                *domain == pattern.to_lowercase()
            };
            Ok(Bag::boolean(matched))
        }
        X500NameMatch => {
            arity(args, 2)?;
            let (Value::X500(pattern), Value::X500(subject)) = (args[0].single()?, args[1].single()?) else {
                return Err(Indet::processing("expected two x500Names"));
            };
            // The first is a terminal sequence of the second.
            let matched =
                pattern.len() <= subject.len() && value::x500_equal(pattern, &subject[subject.len() - pattern.len()..]);
            Ok(Bag::boolean(matched))
        }
        XPathNodeCount => Err(Indet::processing("XPath is not evaluated by this engine")),
        And | Or | NOf | HigherOrder(_) | Map => Err(Indet::processing("a lazy function cannot be applied to values")),
    }
}

/// Zero-based UTF-16 indices; `to` -1 is the end; anything out of range is
/// an error rather than a clamped slice.
fn substring(subject: &str, from: i128, to: i128) -> R<String> {
    let units: Vec<u16> = subject.encode_utf16().collect();
    let len = units.len() as i128;
    let end = if to == -1 { len } else { to };
    if from < 0 || from > len || end > len || (to != -1 && to < from) {
        return Err(Indet::processing("substring indices out of range"));
    }
    Ok(String::from_utf16_lossy(&units[from as usize..end.max(from) as usize]))
}

// ---------------------------------------------------------------------------
// Lazy functions.
// ---------------------------------------------------------------------------

/// Applies a lazy function: `eval` evaluates one argument expression.
pub(crate) fn call_lazy(func: &Func, args: &[Expr], eval: &mut dyn FnMut(&Expr) -> R<Bag>) -> R<Bag> {
    match func {
        Func::And => {
            for arg in args {
                if !eval(arg)?.as_boolean()? {
                    return Ok(Bag::boolean(false));
                }
            }
            Ok(Bag::boolean(true))
        }
        Func::Or => {
            for arg in args {
                if eval(arg)?.as_boolean()? {
                    return Ok(Bag::boolean(true));
                }
            }
            Ok(Bag::boolean(false))
        }
        Func::NOf => {
            let (first, rest) = args.split_first().ok_or(Indet::processing("n-of needs its count"))?;
            let count = eval(first)?;
            let needed = match (count.ty, count.values()) {
                (Type::Integer, [Value::Integer(n)]) => *n,
                _ => return Err(Indet::processing("n-of's count must be one integer")),
            };
            if needed < 0 || needed > rest.len() as i128 {
                return Err(Indet::processing("n-of's count cannot be satisfied"));
            }
            let mut found = 0;
            for arg in rest {
                if found >= needed {
                    break;
                }
                if eval(arg)?.as_boolean()? {
                    found += 1;
                }
            }
            Ok(Bag::boolean(found >= needed))
        }
        Func::HigherOrder(kind) => {
            let applied = function_argument(args)?;
            if args.len() != 3 {
                return Err(Indet::processing("a higher-order function takes a function and two arguments"));
            }
            let (a, b) = (eval(&args[1])?, eval(&args[2])?);
            Ok(Bag::boolean(quantify(*kind, applied, &a, &b)?))
        }
        Func::Map => {
            let applied = function_argument(args)?;
            let mut bags = args[1..].iter().map(&mut *eval).collect::<R<Vec<Bag>>>()?;
            let target = bags.pop().ok_or(Indet::processing("map takes a function and a bag"))?;
            let mut result_type = None;
            let mut values = Vec::with_capacity(target.len());
            for candidate in target.values() {
                bags.push(Bag::one(target.ty, candidate.clone()));
                let produced = call(applied, &bags)?;
                bags.pop();
                values.push(produced.single()?.clone());
                result_type = Some(produced.ty);
            }
            let ty = result_type.or_else(|| applied.returns()).unwrap_or(target.ty);
            Ok(Bag::from_vec(ty, values))
        }
        _ => Err(Indet::processing("not a lazy function")),
    }
}

fn function_argument(args: &[Expr]) -> R<&Func> {
    match args.first() {
        Some(Expr::Function(f)) => Ok(f),
        _ => Err(Indet::processing("a higher-order function needs a <Function> first")),
    }
}

/// Applies a function to two single values, insisting on one boolean.
fn apply_pair(func: &Func, left: (Type, &Value), right: (Type, &Value)) -> R<bool> {
    if func.is_lazy() {
        return Err(Indet::processing("a lazy function cannot be applied to values"));
    }
    call(func, &[Bag::one(left.0, left.1.clone()), Bag::one(right.0, right.1.clone())])?.as_boolean()
}

fn any_of<T>(items: &[T], mut test: impl FnMut(&T) -> R<bool>) -> R<bool> {
    for item in items {
        if test(item)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn all_of<T>(items: &[T], mut test: impl FnMut(&T) -> R<bool>) -> R<bool> {
    for item in items {
        if !test(item)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The six higher-order functions. `all-of-any` quantifies ALL over the
/// first bag and `any-of-all` ALL over the second.
fn quantify(kind: HigherOrder, func: &Func, a: &Bag, b: &Bag) -> R<bool> {
    let pair = |x: &Value, y: &Value| apply_pair(func, (a.ty, x), (b.ty, y));
    match kind {
        HigherOrder::AnyOf | HigherOrder::AllOf => {
            // One value against a bag, either way round. Every member is
            // applied before quantifying, so an error anywhere is the result.
            let value_first = a.len() == 1 && b.len() != 1;
            let (single, many) = if value_first { (a, b) } else { (b, a) };
            let one =
                single.values().first().ok_or(Indet::processing("any-of and all-of need one value against a bag"))?;
            let mut any = false;
            let mut all = true;
            for candidate in many.values() {
                let result = if value_first {
                    apply_pair(func, (single.ty, one), (many.ty, candidate))?
                } else {
                    apply_pair(func, (many.ty, candidate), (single.ty, one))?
                };
                any |= result;
                all &= result;
            }
            Ok(if kind == HigherOrder::AnyOf { any } else { all })
        }
        HigherOrder::AnyOfAny => any_of(a.values(), |x| any_of(b.values(), |y| pair(x, y))),
        HigherOrder::AllOfAll => all_of(a.values(), |x| all_of(b.values(), |y| pair(x, y))),
        HigherOrder::AllOfAny => all_of(a.values(), |x| any_of(b.values(), |y| pair(x, y))),
        HigherOrder::AnyOfAll => all_of(b.values(), |y| any_of(a.values(), |x| pair(x, y))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_resolve_with_their_versions() {
        assert!(matches!(
            lookup("urn:oasis:names:tc:xacml:1.0:function:string-equal"),
            Some(Func::Equal(Type::String))
        ));
        assert!(matches!(lookup("urn:oasis:names:tc:xacml:3.0:function:dayTimeDuration-equal"), Some(Func::Equal(_))));
        assert!(lookup("urn:oasis:names:tc:xacml:1.0:function:dayTimeDuration-equal").is_none());
        assert!(lookup("urn:oasis:names:tc:xacml:1.0:function:boolean-greater-than").is_none());
        assert!(matches!(
            lookup("urn:oasis:names:tc:xacml:3.0:function:string-from-dateTime"),
            Some(Func::StringFrom(Type::DateTime))
        ));
        assert!(matches!(
            lookup("urn:oasis:names:tc:xacml:3.0:function:dateTime-from-string"),
            Some(Func::FromString(Type::DateTime))
        ));
        assert!(matches!(
            lookup("urn:oasis:names:tc:xacml:2.0:function:ipAddress-regexp-match"),
            Some(Func::RegexpMatch(..))
        ));
        assert!(lookup("urn:oasis:names:tc:xacml:1.0:function:no-such-thing").is_none());
    }

    #[test]
    fn primitives_insist_on_one_value() {
        let two = Bag::from_vec(Type::Integer, vec![Value::Integer(1), Value::Integer(2)]);
        let one = Bag::one(Type::Integer, Value::Integer(1));
        assert!(call(&Func::Equal(Type::Integer), &[one.clone(), two]).is_err());
        assert!(call(&Func::IntegerDivide, &[one.clone(), Bag::one(Type::Integer, Value::Integer(0))]).is_err());
        let max = Bag::one(Type::Integer, Value::Integer(i128::MAX));
        assert!(call(&Func::IntegerArith(Arith::Add), &[max, one]).is_err());
    }
}
