// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! `tlsCa` under whichever TLS backend this build has (`native-tls`, the
//! default, or `rustls`): a real trust anchor is taken, text that is not a
//! certificate is refused at construction, before anything is dialled.
//! `tests/data/isrg-root-x1.pem` is Let's Encrypt's public ISRG Root X1.

mod support;

use iya_pep::{Mode, Pep, PepConfig};

fn config(ca: &str) -> PepConfig {
    let mut c = PepConfig::new("pep-tls", Mode::Central, &support::key_file("tls"), "https://pdp.invalid", "app");
    c.tls_ca = ca.to_string();
    c
}

#[test]
fn a_real_trust_anchor_is_taken_and_two_are_too() {
    let root = include_str!("data/isrg-root-x1.pem");
    assert!(Pep::new(config(root)).is_ok(), "one anchor");
    assert!(Pep::new(config(&format!("{root}\n{root}"))).is_ok(), "two blocks in one file");
    assert!(Pep::new(config("")).is_ok(), "no tlsCa: the backend's own roots");
}

#[test]
fn what_is_not_a_certificate_is_refused_before_anything_is_dialled() {
    let no_block = Pep::new(config("not a certificate")).err().expect("refused");
    assert!(no_block.message.contains("tlsCa"), "{}", no_block.message);
    let broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    let bad = Pep::new(config(broken)).err().expect("refused");
    assert!(bad.message.contains("tlsCa"), "{}", bad.message);
}
