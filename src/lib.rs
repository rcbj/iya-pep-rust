// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The iya-sts remote PEP, embedded in an application (rcbj/iya-sts#1206).
//!
//! One package per language, shared by that language's authentication
//! libraries (`oidc-caep-risc`, `saml2-sp`, `wsfed-caep`, `gnap-caep-risc`).
//! It knows nothing about OIDC, SAML, WS-Federation or GNAP: a library hands
//! it a subject (a claims map), its `pep` configuration, and the verified
//! `pep-policies-changed` events from its Shared Signals stream.
//!
//! ```no_run
//! use iya_pep::{Access, Mode, Pep, PepConfig, Subject};
//!
//! let config = PepConfig::new("pep-orders", Mode::Central, "/etc/app/pep-key.pem",
//!     "https://sts.example/realm/shop", "orders");
//! let pep = Pep::new(config)?;
//! pep.start()?;
//! let subject = Subject::user("alice", serde_json::Map::new());
//! if pep.decide(&subject, &Access::new("read", "order", "42")).is_permit() {
//!     // serve it
//! }
//! # Ok::<(), iya_pep::PepError>(())
//! ```

#[cfg(feature = "local")]
pub mod authzen;
pub mod config;
pub mod credential;
pub mod decision;
#[cfg(feature = "local")]
pub mod engine;
pub mod error;
pub mod http;
pub mod key;
#[cfg(feature = "local")]
pub mod local;
pub mod pep;
pub mod records;

pub use config::{Mode, PepConfig};
pub use decision::{Access, Decision, Obligation, Subject};
pub use error::PepError;
pub use key::{jwk_thumbprint, pem_thumbprint};
pub use pep::{EventStream, Pep, Status, POLICIES_CHANGED_EVENT, PROTOCOL_VERSION};
