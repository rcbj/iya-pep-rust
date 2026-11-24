// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The iya-sts remote PEP, embedded in an application (rcbj/iya-sts#1206).
//!
//! One package per language, shared by that language's authentication
//! libraries (`oidc-caep-risc`, `saml2-sp`, `wsfed-caep`, `gnap-caep-risc`).
//! It knows nothing about OIDC, SAML, WS-Federation or GNAP: a library hands
//! it a subject (a claims map), its `pep` configuration, and the verified
//! `pep-policies-changed` events from its Shared Signals stream.

#[cfg(feature = "local")]
pub mod engine;
