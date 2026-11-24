// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! An index from target to children, so a request skips the rules and
//! policies whose target cannot match.
//!
//! A child is KEYED when one `AnyOf` of its target is made only of `AllOf`s
//! that each hold an equality `Match` of a literal against the same
//! designator (string, anyURI, integer or boolean, not MustBePresent):
//! "resource-id is A, or B, or C". That `AnyOf` is No-match exactly when the
//! designator's bag resolves and holds none of the literals, and a target
//! with a No-match `AnyOf` is No-match whatever else it holds, so the child
//! is NotApplicable without being looked at. Skipping a NotApplicable child
//! changes no combining algorithm's answer and collects no obligation.
//!
//! The index maps each designator's literals to the children that name
//! them. A request looks up the values it holds, and evaluates only the
//! children found and the children that are not keyed. A bag that fails to
//! resolve skips nothing.

use std::collections::HashMap;
use std::sync::Arc;

use super::compile::{Expr, Target};
use super::function::{Bag, Func, R};
use super::value::{Type, Value};

/// A value as an index key: exactly the values whose equality is structural.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    String(Arc<str>),
    AnyUri(Arc<str>),
    Integer(i128),
    Boolean(bool),
}

impl Key {
    fn of(value: &Value) -> Option<Key> {
        Some(match value {
            Value::String(s) => Key::String(s.clone()),
            Value::AnyUri(s) => Key::AnyUri(s.clone()),
            Value::Integer(i) => Key::Integer(*i),
            Value::Boolean(b) => Key::Boolean(*b),
            _ => None?,
        })
    }
}

/// The children keyed on one designator.
#[derive(Debug)]
struct Group {
    designator: u32,
    by_key: HashMap<Key, Vec<u32>>,
    members: Vec<u32>,
}

#[derive(Debug)]
pub(crate) struct TargetIndex {
    groups: Vec<Group>,
    /// Children no group holds: always evaluated.
    unkeyed: Vec<u32>,
    len: usize,
}

/// The designator and literal keys of a target's keyable `AnyOf`, if any.
fn keys_of(target: &Target) -> Option<(u32, Vec<Key>)> {
    target.iter().find_map(|any_of| {
        let mut designator = None;
        let mut keys = Vec::with_capacity(any_of.len());
        for all_of in any_of {
            let (id, key) = all_of.iter().find_map(|m| {
                let Func::Equal(ty) = m.func else { return None };
                if !matches!(ty, Type::String | Type::AnyUri | Type::Integer | Type::Boolean) {
                    return None;
                }
                let Expr::Designator { id, must_be_present: false } = m.attribute else { return None };
                let Expr::Literal(bag) = &m.literal else { return None };
                Some((id, Key::of(bag.values().first()?)?))
            })?;
            if *designator.get_or_insert(id) != id {
                return None;
            }
            keys.push(key);
        }
        Some((designator?, keys))
    })
}

impl TargetIndex {
    /// An index over children's targets, or `None` when fewer than two
    /// children are keyed and it would not pay for itself.
    pub(crate) fn build<'a>(targets: impl Iterator<Item = &'a Target>) -> Option<TargetIndex> {
        let mut groups: Vec<Group> = Vec::new();
        let mut unkeyed = Vec::new();
        let mut len = 0;
        for (child, target) in targets.enumerate() {
            len += 1;
            let child = child as u32;
            let Some((designator, keys)) = keys_of(target) else {
                unkeyed.push(child);
                continue;
            };
            let at = match groups.iter().position(|g| g.designator == designator) {
                Some(at) => at,
                None => {
                    groups.push(Group { designator, by_key: HashMap::new(), members: Vec::new() });
                    groups.len() - 1
                }
            };
            let group = &mut groups[at];
            group.members.push(child);
            for key in keys {
                let children = group.by_key.entry(key).or_default();
                if children.last() != Some(&child) {
                    children.push(child);
                }
            }
        }
        let keyed: usize = groups.iter().map(|g| g.members.len()).sum();
        (keyed >= 2).then_some(TargetIndex { groups, unkeyed, len })
    }

    /// The children a request must evaluate; `bag` resolves a designator.
    pub(crate) fn candidates(&self, bag: &mut dyn FnMut(u32) -> R<Bag>) -> Candidates {
        let mut set = Candidates::new(self.len);
        for &child in &self.unkeyed {
            set.insert(child);
        }
        for group in &self.groups {
            match bag(group.designator) {
                Ok(bag) => {
                    for key in bag.values().iter().filter_map(Key::of) {
                        for &child in group.by_key.get(&key).map_or(&[][..], Vec::as_slice) {
                            set.insert(child);
                        }
                    }
                }
                Err(_) => group.members.iter().for_each(|&c| set.insert(c)),
            }
        }
        set
    }
}

/// A set of child positions; on the stack up to 128 children.
pub(crate) enum Candidates {
    Small(u128),
    Large(Vec<bool>),
}

impl Candidates {
    fn new(len: usize) -> Candidates {
        if len <= 128 {
            Candidates::Small(0)
        } else {
            Candidates::Large(vec![false; len])
        }
    }

    fn insert(&mut self, child: u32) {
        match self {
            Candidates::Small(bits) => *bits |= 1 << child,
            Candidates::Large(flags) => flags[child as usize] = true,
        }
    }

    pub(crate) fn contains(&self, child: usize) -> bool {
        match self {
            Candidates::Small(bits) => child < 128 && bits & (1 << child) != 0,
            Candidates::Large(flags) => flags.get(child).copied().unwrap_or(false),
        }
    }
}
