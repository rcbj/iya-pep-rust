// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! XML Schema regular expressions, translated for the `regex` crate.
//!
//! - **An XML Schema regex is anchored**: `bc` matches `bc` and not `abcd`.
//!   The pattern is wrapped as `^(?:…)$`, so a top-level alternation cannot
//!   escape the anchors.
//! - `\i`, `\I`, `\c` and `\C` (XML name characters) become ASCII classes,
//!   as in the reference engine.
//! - Character class subtraction (`[a-z-[aeiou]]`) is refused rather than
//!   approximated: a regex that matches almost the right things is worse
//!   than one that fails, and a failure is an Indeterminate.

use regex::Regex;

/// Translates and compiles; `None` when the pattern is refused or invalid.
pub(crate) fn compile(pattern: &str) -> Option<Regex> {
    if has_class_subtraction(pattern) {
        return None;
    }
    let mut translated = String::with_capacity(pattern.len() + 16);
    translated.push_str("^(?:");
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            translated.push(c);
            continue;
        }
        match chars.next() {
            Some('i') => translated.push_str("[A-Za-z_:]"),
            Some('I') => translated.push_str("[^A-Za-z_:]"),
            Some('c') => translated.push_str(r"[A-Za-z0-9_:.\-]"),
            Some('C') => translated.push_str(r"[^A-Za-z0-9_:.\-]"),
            Some(other) => {
                translated.push('\\');
                translated.push(other);
            }
            None => translated.push('\\'),
        }
    }
    translated.push_str(")$");
    Regex::new(&translated).ok()
}

/// An opening bracket, anything but a closing one, then `-[`.
fn has_class_subtraction(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    (0..bytes.len()).filter(|&i| bytes[i] == b'[').any(|start| {
        let body = &bytes[start + 1..];
        let end = body.iter().position(|&b| b == b']').unwrap_or(body.len());
        body[..end].windows(2).any(|pair| pair == b"-[")
    })
}

#[cfg(test)]
mod tests {
    use super::compile;

    #[test]
    fn anchored_and_translated() {
        let re = compile("bc").unwrap();
        assert!(re.is_match("bc") && !re.is_match("abcd"));
        assert!(!compile("a|b").unwrap().is_match("ab"));
        assert!(compile(r"\i\c*").unwrap().is_match("x-1"));
        assert!(compile("[a-z-[aeiou]]").is_none());
    }
}
