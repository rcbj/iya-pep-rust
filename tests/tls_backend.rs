// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! `tlsCa` under whichever TLS backend this build has (`native-tls`, the
//! default, or `rustls`): a real trust anchor is taken, text that is not a
//! certificate is refused at construction, before anything is dialled.
//! `tests/data/isrg-root-x1.pem` and `isrg-root-x2.pem` are Let's Encrypt's
//! public ISRG Root X1 and X2.

mod support;

use iya_pep::{Mode, Pep, PepConfig};

fn config(ca: &str) -> PepConfig {
    // A key file of its own per call: the tests run on parallel threads,
    // and one file rewritten while another test read it made them flaky.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let tag = format!("tls-{}", NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let mut c = PepConfig::new("pep-tls", Mode::Central, &support::key_file(&tag), "https://pdp.invalid", "app");
    c.tls_ca = ca.to_string();
    c
}

#[test]
fn a_real_trust_anchor_is_taken_and_two_are_too() {
    let root = include_str!("data/isrg-root-x1.pem");
    assert!(Pep::new(config(root)).is_ok(), "one anchor");
    let other = include_str!("data/isrg-root-x2.pem");
    assert!(Pep::new(config(&format!("{root}\n{other}"))).is_ok(), "two anchors in one file");
    assert!(Pep::new(config(&format!("{root}\n{root}"))).is_ok(), "a repeated anchor is taken once, not refused");
    assert!(Pep::new(config("")).is_ok(), "no tlsCa: the backend's own roots");
}

#[test]
fn what_is_not_a_certificate_is_refused_before_anything_is_dialled() {
    let Err(no_block) = Pep::new(config("not a certificate")) else { panic!("refused") };
    assert!(no_block.message.contains("tlsCa"), "{}", no_block.message);
    let broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    let Err(bad) = Pep::new(config(broken)) else { panic!("refused") };
    assert!(bad.message.contains("tlsCa"), "{}", bad.message);
}
