// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! `central` mode and the control plane, against the stub PDP: the token
//! grant, DPoP and its nonces, registration, the heartbeat, the evaluation,
//! a token replaced once, the Permit cache and the event, and failing closed.

mod support;

use std::time::Duration;

use iya_pep::{jwk_thumbprint, Access, Decision, Mode, Pep, PepConfig, Subject};
use serde_json::{json, Map, Value};
use support::{claims, key_file, Stub, APP, NAME};

fn config(stub: &Stub, tag: &str) -> PepConfig {
    let mut c = PepConfig::new(NAME, Mode::Central, &key_file(tag), &stub.base, APP);
    c.heartbeat_interval_ms = 1000;
    c
}

fn alice() -> Subject {
    let mut claims = Map::new();
    claims.insert("acr".into(), json!("urn:example:mfa"));
    Subject::user("alice", claims)
}

fn read_42() -> Access {
    Access::new("read", "order", "42")
}

#[test]
fn the_grant_is_a_dpop_bound_self_assertion_per_audience_with_one_nonce_retry() {
    let stub = Stub::start();
    stub.script.lock().unwrap().token_nonce_first = true;
    let pep = Pep::new(config(&stub, "grant")).unwrap();
    assert!(pep.decide(&alice(), &read_42()).is_permit());

    let grants = stub.seen("/oauth2/token");
    assert_eq!(grants.len(), 2, "one refusal asking for a nonce, then the grant");
    assert!(grants[0].proof().get("nonce").is_none());
    assert_eq!(grants[1].proof()["nonce"], "n-token", "the retry carries the nonce handed");
    let g = &grants[1];
    assert_eq!(g.form("grant_type").as_deref(), Some("urn:ietf:params:oauth:grant-type:jwt-bearer"));
    assert_eq!(g.form("client_id").as_deref(), Some("sts-remote-pep"));
    assert_eq!(g.form("scope").as_deref(), Some("authzen:evaluate"));
    assert_eq!(g.form("resource"), Some(format!("{}/access/v1", stub.base)));
    let assertion = claims(&g.form("assertion").unwrap());
    assert_eq!(assertion["iss"], NAME);
    assert_eq!(assertion["sub"], NAME);
    assert_eq!(assertion["aud"], format!("{}/oauth2/token", stub.base));
    assert!(assertion["exp"].as_u64().unwrap() > assertion["iat"].as_u64().unwrap());

    // The proof's key is the PEP's key, whose thumbprint the host compares.
    let jwk = grants[1].proof_header()["jwk"].clone();
    assert_eq!(jwk_thumbprint(&jwk).as_deref(), Some(pep.key_thumbprint().as_str()));

    let evaluation = &stub.seen("/access/v1/evaluation")[0];
    assert_eq!(evaluation.header("Authorization"), Some("DPoP tok-authzen:evaluate-1"));
    let proof = evaluation.proof();
    assert_eq!(proof["htm"], "POST");
    assert_eq!(proof["htu"], format!("{}/access/v1/evaluation", stub.base));
    assert!(proof["ath"].is_string());
}

#[test]
fn the_evaluation_carries_the_bound_application_and_the_subjects_claims() {
    let stub = Stub::start();
    let mut c = config(&stub, "body");
    c.supported_obligations = vec!["step-up".into()];
    stub.script.lock().unwrap().catalogue_rows = vec![json!({"object": "subject", "property": "acr", "attributeId": "urn:example:acr"})];
    let pep = Pep::new(c).unwrap();
    pep.pull_now().unwrap();
    let mut access = read_42();
    access.context.insert("application".into(), json!("another-app"));
    let mut subject = alice();
    subject.properties.insert("email".into(), json!("alice@example.com"));
    pep.decide(&subject, &access);
    let body = stub.seen("/access/v1/evaluation")[0].json();
    assert_eq!(
        body["subject"],
        json!({"type": "user", "id": "alice", "properties": {"acr": "urn:example:mfa"}}),
        "a claim the catalogue doesn't declare is not sent: the service would refuse the evaluation"
    );
    assert_eq!(stub.seen("/xacml/pep/authzen-catalogue")[0].header("Authorization").map(|a| a.starts_with("DPoP ")), Some(true));
    pep.pull_now().unwrap();
    assert_eq!(stub.seen("/xacml/pep/authzen-catalogue")[1].header("If-None-Match"), Some("\"c1\""));
    assert_eq!(body["action"], json!({"name": "read"}));
    assert_eq!(body["resource"], json!({"type": "order", "id": "42"}));
    assert_eq!(body["context"]["application"], APP, "the PEP's binding, never the caller's");
    assert_eq!(body["context"]["supported_obligations"], json!(["step-up"]));
}

#[test]
fn permit_deny_obligations_and_failing_closed() {
    let stub = Stub::start();
    let pep = Pep::new(config(&stub, "answers")).unwrap();
    {
        let mut s = stub.script.lock().unwrap();
        s.evaluations.push_back((
            200,
            json!({"decision": true, "context": {"obligations": [{"id": "o1", "type": "step-up", "properties": {"acr_value": "phr"}}]}}),
            vec![],
        ));
        s.evaluations.push_back((200, json!({"decision": false, "context": {"reason_admin": {"en": "not the owner"}}}), vec![]));
        s.evaluations.push_back((500, json!({"error": "server_error"}), vec![]));
        s.evaluations.push_back((400, json!({"error": "invalid_request", "error_description": "no resource.type"}), vec![]));
    }
    match pep.decide(&alice(), &read_42()) {
        Decision::Permit { obligations, advice } => {
            assert_eq!(obligations.len(), 1);
            assert_eq!(obligations[0].kind, "step-up");
            assert_eq!(obligations[0].properties["acr_value"], "phr");
            assert!(advice.is_empty());
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(pep.decide(&alice(), &read_42()), Decision::Deny { why: "not the owner".into() });
    assert!(matches!(pep.decide(&alice(), &read_42()), Decision::Unavailable { .. }), "a 500 is no decision");
    assert!(matches!(pep.decide(&alice(), &read_42()), Decision::Deny { why } if why.contains("no resource.type")));

    // Nobody there at all.
    let mut gone = config(&stub, "gone");
    gone.pdp_url = "http://127.0.0.1:9/realm/r1".into();
    gone.timeout_ms = 500;
    let pep = Pep::new(gone).unwrap();
    assert!(matches!(pep.decide(&alice(), &read_42()), Decision::Unavailable { .. }));
    let s = pep.status();
    assert_eq!((s.decisions, s.unavailable), (1, 1));
}

#[test]
fn a_refused_token_is_replaced_once_and_only_once() {
    let stub = Stub::start();
    let pep = Pep::new(config(&stub, "replace")).unwrap();
    let invalid = vec![("WWW-Authenticate".to_string(), "DPoP error=\"invalid_token\"".to_string())];
    stub.script.lock().unwrap().evaluations.push_back((401, json!({"error": "invalid_token"}), invalid.clone()));
    assert!(pep.decide(&alice(), &read_42()).is_permit(), "a new token, and the call made once more");
    let calls = stub.seen("/access/v1/evaluation");
    assert_eq!(calls.len(), 2);
    assert_ne!(calls[0].header("Authorization"), calls[1].header("Authorization"));
    assert_eq!(stub.count("/oauth2/token"), 2);

    {
        let mut s = stub.script.lock().unwrap();
        s.evaluations.push_back((401, json!({"error": "invalid_token"}), invalid.clone()));
        s.evaluations.push_back((401, json!({"error": "invalid_token"}), invalid));
    }
    assert!(matches!(pep.decide(&alice(), &read_42()), Decision::Unavailable { .. }), "a second refusal in a row is not retried");
    assert_eq!(stub.count("/access/v1/evaluation"), 4);
}

#[test]
fn a_resource_nonce_demand_is_answered_once() {
    let stub = Stub::start();
    let pep = Pep::new(config(&stub, "rnonce")).unwrap();
    stub.script.lock().unwrap().evaluations.push_back((
        401,
        json!({"error": "use_dpop_nonce"}),
        vec![("WWW-Authenticate".into(), "DPoP error=\"use_dpop_nonce\"".into()), ("DPoP-Nonce".into(), "n-res".into())],
    ));
    assert!(pep.decide(&alice(), &read_42()).is_permit());
    let calls = stub.seen("/access/v1/evaluation");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].proof()["nonce"], "n-res");
    assert_eq!(calls[0].header("Authorization"), calls[1].header("Authorization"), "the same token");
}

#[test]
fn a_refused_grant_is_unavailable_and_not_asked_again_at_once() {
    let stub = Stub::start();
    stub.script.lock().unwrap().token_refused = true;
    let pep = Pep::new(config(&stub, "refused")).unwrap();
    assert!(matches!(pep.decide(&alice(), &read_42()), Decision::Unavailable { why } if why.contains("invalid_grant")));
    assert!(matches!(pep.decide(&alice(), &read_42()), Decision::Unavailable { .. }));
    assert_eq!(stub.count("/oauth2/token"), 1, "held for five seconds");
    assert_eq!(stub.count("/access/v1/evaluation"), 0, "no call without a token");
}

#[test]
fn the_permit_cache_is_short_and_cleared_by_the_event() {
    let stub = Stub::start();
    let mut c = config(&stub, "cache");
    c.permit_cache_ms = 30_000;
    let pep = Pep::new(c).unwrap();
    assert!(pep.decide(&alice(), &read_42()).is_permit());
    assert!(pep.decide(&alice(), &read_42()).is_permit());
    assert_eq!(stub.count("/access/v1/evaluation"), 1, "the second came from the cache");
    assert_eq!(pep.status().permit_cache_hits, 1);
    assert_eq!(pep.status().permit_cache_entries, 1);
    assert!(pep.decide(&alice(), &Access::new("write", "order", "42")).is_permit());
    assert_eq!(stub.count("/access/v1/evaluation"), 2, "another action is another question");

    assert!(!pep.on_policy_event(&json!({"pep": "someone-else", "changed": ["policies"]})), "another PEP's event");
    pep.decide(&alice(), &read_42());
    assert_eq!(stub.count("/access/v1/evaluation"), 2);
    assert!(pep.on_policy_event(&json!({"pep": NAME, "changed": ["policies"], "sync_token": "t2"})));
    pep.decide(&alice(), &read_42());
    assert_eq!(stub.count("/access/v1/evaluation"), 3, "the event cleared the cache");

    stub.script.lock().unwrap().evaluation_default = (200, json!({"decision": false}));
    pep.on_policy_event(&json!({"pep": NAME}));
    assert!(!pep.decide(&alice(), &read_42()).is_permit());
    assert!(!pep.decide(&alice(), &read_42()).is_permit());
    assert_eq!(stub.count("/access/v1/evaluation"), 5, "a Deny is never cached");
}

#[test]
fn start_registers_as_embedded_and_the_heartbeat_reports() {
    let stub = Stub::start();
    let pep = Pep::new(config(&stub, "register")).unwrap();
    pep.start().unwrap();
    let register = stub.seen("/xacml/pep/register");
    assert_eq!(register.len(), 1);
    let body = register[0].json();
    assert_eq!(body["kind"], "embedded");
    assert_eq!(body["application"], APP);
    assert_eq!(body["mode"], "central");
    assert_eq!(body["protocolVersion"], iya_pep::PROTOCOL_VERSION);
    assert_eq!(body["name"], NAME);
    assert_eq!(stub.seen("/oauth2/token")[0].form("scope").as_deref(), Some("xacml:pep"));
    assert!(pep.status().registered);

    assert!(stub.wait(Duration::from_secs(5), |s| s.count("/xacml/pep/heartbeat") >= 1));
    let beat = stub.seen("/xacml/pep/heartbeat")[0].json();
    assert_eq!(beat["kind"], "embedded");
    assert_eq!(beat["policyEvents"], "none");
    assert!(beat["decisions"].is_u64());

    // A heartbeat that doesn't know the PEP makes it register again.
    stub.script.lock().unwrap().heartbeat_status = 404;
    assert!(stub.wait(Duration::from_secs(6), |s| s.count("/xacml/pep/register") >= 2), "registered again");
    pep.stop();
    assert!(!pep.status().running);
}

#[test]
fn a_registration_the_service_refuses_is_retried_and_on_the_status() {
    let stub = Stub::start();
    stub.script.lock().unwrap().register_status = 403;
    let pep = Pep::new(config(&stub, "regfail")).unwrap();
    pep.start().unwrap();
    assert!(!pep.status().registered);
    assert!(pep.status().last_error.contains("403"), "{}", pep.status().last_error);
    std::thread::sleep(Duration::from_millis(3500));
    let tries = stub.count("/xacml/pep/register");
    assert!((2..=3).contains(&tries), "a refused registration backs off (2 s, then 4 s), not once a second: {tries} in 3.5 s");
    stub.script.lock().unwrap().register_status = 201;
    assert!(stub.wait(Duration::from_secs(6), |_| pep.status().registered));
}

#[test]
fn a_changed_key_file_drops_the_tokens_and_a_bad_one_is_refused_at_start() {
    let stub = Stub::start();
    let c = config(&stub, "rekey");
    let path = c.assertion_key.clone();
    let pep = Pep::new(c).unwrap();
    let before = pep.key_thumbprint();
    pep.decide(&alice(), &read_42());
    // Another key in the same file.
    use p256::pkcs8::EncodePrivateKey;
    let other = p256::ecdsa::SigningKey::from_slice(&[3u8; 32]).unwrap().to_pkcs8_pem(Default::default()).unwrap().to_string();
    std::thread::sleep(Duration::from_millis(20));
    std::fs::write(&path, other).unwrap();
    assert!(pep.reload_key().unwrap(), "the file changed");
    assert_ne!(pep.key_thumbprint(), before);
    pep.decide(&alice(), &read_42());
    let grants = stub.seen("/oauth2/token");
    assert_eq!(grants.len(), 2, "the token bound to the old key was dropped");
    assert_eq!(jwk_thumbprint(&grants[1].proof_header()["jwk"]).as_deref(), Some(pep.key_thumbprint().as_str()));
    assert!(!pep.reload_key().unwrap(), "unchanged");

    let bad = std::env::temp_dir().join(format!("iya-pep-bad-{}.pem", std::process::id()));
    std::fs::write(&bad, "not a key").unwrap();
    let Err(err) = Pep::new(config_with_key(&stub, &bad.to_string_lossy())) else { panic!("refused") };
    assert_eq!(err.code, "config");
}

fn config_with_key(stub: &Stub, path: &str) -> PepConfig {
    let mut c = PepConfig::new(NAME, Mode::Central, path, &stub.base, APP);
    c.heartbeat_interval_ms = 1000;
    c
}

#[test]
fn a_configuration_from_json_runs() {
    let stub = Stub::start();
    let section: Value = json!({"name": NAME, "assertionKey": key_file("json"), "mode": "central", "permitCacheMs": 1000});
    let c = PepConfig::from_json(&section, &stub.base, APP).unwrap();
    assert!(Pep::new(c).unwrap().decide(&alice(), &read_42()).is_permit());
}

#[test]
fn advice_in_the_answers_context_is_handed_as_local_hands_it() {
    // The service sends advice under context only while the realm's
    // authzen.returnReasons is on; when it does, central hands it in the
    // shape local hands the engine's: the id as kind, each attribute a
    // property, a repeated one an array.
    let stub = Stub::start();
    let pep = Pep::new(config(&stub, "advice")).unwrap();
    stub.script.lock().unwrap().evaluations.push_back((
        200,
        json!({"decision": true, "context": {"xacml_decision": "Permit", "advice": [
            {"id": "urn:example:advice:banner", "attributes": [
                {"id": "urn:example:text", "value": "be careful"},
                {"id": "urn:example:tag", "value": "a"},
                {"id": "urn:example:tag", "value": "b"},
                {"id": "urn:example:count", "value": 3}]}]}}),
        vec![],
    ));
    match pep.decide(&alice(), &read_42()) {
        Decision::Permit { obligations, advice } => {
            assert!(obligations.is_empty());
            assert_eq!(advice.len(), 1);
            assert_eq!(advice[0].id, "urn:example:advice:banner");
            assert_eq!(advice[0].kind, "urn:example:advice:banner");
            assert_eq!(advice[0].properties["urn:example:text"], "be careful");
            assert_eq!(advice[0].properties["urn:example:tag"], json!(["a", "b"]));
            assert_eq!(advice[0].properties["urn:example:count"], "3");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn local_is_the_default_mode() {
    let stub = Stub::start();
    let section: Value = json!({"name": NAME, "assertionKey": key_file("json-default")});
    let read = PepConfig::from_json(&section, &stub.base, APP);
    if cfg!(feature = "local") {
        let c = read.unwrap();
        assert_eq!(c.mode, iya_pep::Mode::Local, "no mode: local");
        assert!(Pep::new(c).is_ok(), "a build with the engine runs it");
    } else {
        let err = read.expect_err("refused without the engine");
        assert!(err.message.contains("the default") && err.message.contains("\"mode\": \"central\""), "{}", err.message);
    }
}
