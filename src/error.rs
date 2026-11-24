// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::fmt;

/// An error the crate reports. `code` is a short, stable category:
///
/// - `config`: the configuration or the assertion key can't be used
/// - `transport`: the service could not be reached, or answered nonsense
/// - `refused`: the service refused the PEP (its status and `error` are in
///   the message)
/// - `policy`: a pulled policy set or catalogue could not be used
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PepError {
    pub code: &'static str,
    pub message: String,
}

impl PepError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl fmt::Display for PepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PepError {}
