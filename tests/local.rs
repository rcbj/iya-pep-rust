// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! `local` mode against the stub PDP: failing closed before the first pull,
//! a Permit and a Deny decided in process, the catalogue, the PIP, the pulls
//! (`If-None-Match` and `304`, the event, the poll, the heartbeat's
//! `current`), a set that doesn't compile, and the decision records.

#![cfg(feature = "local")]

mod support;

use std::time::Duration;

use iya_pep::{Access, Decision, EventStream, Mode, Pep, PepConfig, Subject};
use serde_json::{json, Map, Value};
use support::{key_file, Stub, APP, NAME};

const STRING: &str = "http://www.w3.org/2001/XMLSchema#string";
const ACTION: &str = "urn:oasis:names:tc:xacml:3.0:attribute-category:action";
const SUBJECT: &str = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";

fn action_is(name: &str) -> String {
    format!(
        r#"<Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal"><AttributeValue DataType="{STRING}">{name}</AttributeValue><AttributeDesignator Category="{ACTION}" AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" DataType="{STRING}" MustBePresent="false"/></Match></AllOf></AnyOf></Target>"#
    )
}

fn subject_has(attribute: &str, value: &str) -> String {
    format!(
        r#"<Condition><Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-is-in"><AttributeValue DataType="{STRING}">{value}</AttributeValue><AttributeDesignator Category="{SUBJECT}" AttributeId="{attribute}" DataType="{STRING}" MustBePresent="false"/></Apply></Condition>"#
    )
}

/// `read` for anyone; `delete` for the `eng` department (from the PIP);
/// `update` with the `mfa` acr (a claim, through the catalogue); nothing
/// else.
fn orders_policy(read_allowed: bool) -> Value {
    let read = if read_allowed { format!(r#"<Rule RuleId="read" Effect="Permit">{}</Rule>"#, action_is("read")) } else { String::new() };
    let document = format!(
        r#"<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="orders" Version="1.0" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit"><Target/>{read}<Rule RuleId="delete" Effect="Permit">{}{}</Rule><Rule RuleId="update" Effect="Permit">{}{}</Rule></Policy>"#,
        action_is("delete"),
        subject_has("urn:example:dept", "eng"),
        action_is("update"),
        subject_has("urn:example:acr", "urn:example:mfa"),
    );
    json!({"name": "orders", "policyId": "orders", "kind": "Policy", "version": "1.0",
           "combiningAlgId": "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit",
           "isRoot": true, "description": "", "document": document})
}

fn stub() -> Stub {
    let stub = Stub::start();
    {
        let mut s = stub.script.lock().unwrap();
        s.policies = vec![orders_policy(true)];
        s.catalogue_rows = vec![json!({"object": "subject", "property": "acr", "attributeId": "urn:example:acr"})];
    }
    stub
}

fn config(stub: &Stub, tag: &str) -> PepConfig {
    let mut c = PepConfig::new(NAME, Mode::Local, &key_file(tag), &stub.base, APP);
    c.heartbeat_interval_ms = 1000;
    c
}

fn alice(acr: Option<&str>) -> Subject {
    let mut claims = Map::new();
    if let Some(acr) = acr {
        claims.insert("acr".into(), json!(acr));
    }
    Subject::user("alice", claims)
}

fn on(action: &str) -> Access {
    Access::new(action, "order", "42")
}

#[test]
fn nothing_is_permitted_before_the_first_pull() {
    let stub = stub();
    let pep = Pep::new(config(&stub, "l-before")).unwrap();
    assert!(matches!(pep.decide(&alice(None), &on("read")), Decision::Unavailable { why } if why.contains("no policy")));
    assert_eq!(stub.count("/access/v1/evaluation"), 0, "local mode never asks AuthZEN");
}

#[test]
fn a_permit_and_a_deny_are_decided_in_process_and_recorded() {
    let stub = stub();
    let pep = Pep::new(config(&stub, "l-decide")).unwrap();
    pep.start().unwrap();
    let pull = &stub.seen("/xacml/pep/policies")[0];
    assert!(pull.query.contains("scope=bound-application"), "{}", pull.query);
    assert!(pull.query.contains(&format!("pep={NAME}")));
    assert_eq!(stub.seen("/oauth2/token").iter().filter(|g| g.form("scope").as_deref() == Some("xacml:pep")).count(), 1);

    assert!(pep.decide(&alice(None), &on("read")).is_permit());
    assert!(matches!(pep.decide(&alice(None), &on("write")), Decision::Deny { .. }));
    assert_eq!(stub.count("/access/v1/evaluation"), 0);
    let status = pep.status();
    assert!(status.holds_policy);
    assert_eq!((status.policy_count, status.sync_token.as_str()), (1, "p1"));

    pep.stop();
    let pushes = stub.seen("/admin-api/pep-audit");
    assert_eq!(pushes.len(), 1, "the queued records are sent on stop");
    let body = pushes[0].json();
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["seq"], 1);
    assert_eq!(events[0]["kind"], "authzen");
    assert_eq!(events[0]["allowed"], true);
    assert_eq!(events[1]["allowed"], false);
    assert_eq!(events[0]["application"], APP);
    assert_eq!(pushes[0].form("scope"), None);
    assert!(stub.seen("/oauth2/token").iter().any(|g| g.form("scope").as_deref() == Some("xacml:pep-audit")));
    assert_eq!(pep.status().records_queued, 0, "acknowledged and gone");
}

#[test]
fn a_claim_reaches_the_policy_through_the_catalogue() {
    let stub = stub();
    let pep = Pep::new(config(&stub, "l-claim")).unwrap();
    pep.pull_now().unwrap();
    assert!(pep.decide(&alice(Some("urn:example:mfa")), &on("update")).is_permit());
    assert!(!pep.decide(&alice(Some("urn:example:pwd")), &on("update")).is_permit());
    assert!(!pep.decide(&alice(None), &on("update")).is_permit());
}

#[test]
fn the_pip_is_asked_once_for_what_the_request_does_not_carry() {
    let stub = stub();
    stub.script.lock().unwrap().pip_answer = format!(
        r#"<PIPResponse xmlns="urn:sts:xacml:pip:1.0"><Attributes xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" Category="{SUBJECT}"><Attribute AttributeId="urn:example:dept" IncludeInResult="false"><AttributeValue DataType="{STRING}">eng</AttributeValue></Attribute></Attributes></PIPResponse>"#
    );
    let pep = Pep::new(config(&stub, "l-pip")).unwrap();
    pep.pull_now().unwrap();
    assert!(pep.decide(&alice(Some("urn:example:mfa")), &on("delete")).is_permit());
    let queries = stub.seen("/xacml/pip");
    assert_eq!(queries.len(), 1);
    assert!(queries[0].body.contains(">alice<"));
    assert!(queries[0].body.contains("urn:example:dept"));
    assert!(!queries[0].body.contains("AttributeId=\"urn:example:acr\" DataType"), "the claim was carried, so it isn't asked for");

    stub.script.lock().unwrap().pip_answer = String::new();
    assert!(!pep.decide(&alice(None), &on("delete")).is_permit(), "an empty PIP answer is an empty bag");
}

#[test]
fn a_second_pull_sends_the_tokens_and_keeps_the_set_on_304() {
    let stub = stub();
    let pep = Pep::new(config(&stub, "l-304")).unwrap();
    pep.pull_now().unwrap();
    pep.pull_now().unwrap();
    let pulls = stub.seen("/xacml/pep/policies");
    assert_eq!(pulls.len(), 2);
    assert_eq!(pulls[0].header("If-None-Match"), None);
    assert_eq!(pulls[1].header("If-None-Match"), Some("\"p1\""));
    assert_eq!(stub.seen("/xacml/pep/authzen-catalogue")[1].header("If-None-Match"), Some("\"c1\""));
    assert!(pep.decide(&alice(None), &on("read")).is_permit());
}

#[test]
fn the_event_makes_the_pep_pull_with_its_own_token() {
    let stub = stub();
    let mut c = config(&stub, "l-event");
    c.signals = true;
    let pep = Pep::new(c).unwrap();
    pep.start().unwrap();
    assert!(pep.decide(&alice(None), &on("read")).is_permit());
    {
        let mut s = stub.script.lock().unwrap();
        s.policies = vec![orders_policy(false)];
        s.policy_token = "p2".into();
    }
    let before = stub.count("/xacml/pep/policies");
    assert!(!pep.on_policy_event(&json!({"pep": "another-pep", "changed": ["policies"], "sync_token": "p2"})));
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(stub.count("/xacml/pep/policies"), before, "another PEP's event pulls nothing");

    assert!(pep.on_policy_event(&json!({"pep": NAME, "changed": ["policies"], "sync_token": "forged-token"})));
    assert!(stub.wait(Duration::from_secs(5), |_| !pep.decide(&alice(None), &on("read")).is_permit()), "the new set is held");
    assert_eq!(pep.status().sync_token, "p2", "the pull's token, never the event's");
    let pull = stub.seen("/xacml/pep/policies").last().unwrap().clone();
    assert!(pull.header("Authorization").unwrap().starts_with("DPoP tok-xacml:pep-"));
    pep.stop();
}

#[test]
fn without_a_signal_stream_the_pep_polls() {
    let stub = stub();
    let mut c = config(&stub, "l-poll");
    c.poll_interval_ms = 1000;
    let pep = Pep::new(c).unwrap();
    pep.start().unwrap();
    assert!(pep.decide(&alice(None), &on("read")).is_permit());
    {
        let mut s = stub.script.lock().unwrap();
        s.policies = vec![orders_policy(false)];
        s.policy_token = "p2".into();
    }
    assert!(stub.wait(Duration::from_secs(5), |_| !pep.decide(&alice(None), &on("read")).is_permit()));
    pep.stop();
}

#[test]
fn with_a_stream_it_waits_for_the_event_or_a_heartbeat_saying_it_is_stale() {
    let stub = stub();
    let mut c = config(&stub, "l-stale");
    c.signals = true;
    c.poll_interval_ms = 1000;
    let pep = Pep::new(c).unwrap();
    pep.start().unwrap();
    {
        let mut s = stub.script.lock().unwrap();
        s.policies = vec![orders_policy(false)];
        s.policy_token = "p2".into();
    }
    std::thread::sleep(Duration::from_millis(2500));
    assert!(pep.decide(&alice(None), &on("read")).is_permit(), "no event and the fallback poll is 5 minutes away");
    stub.script.lock().unwrap().heartbeat_current = false;
    assert!(stub.wait(Duration::from_secs(5), |_| !pep.decide(&alice(None), &on("read")).is_permit()), "the heartbeat said the PEP is not current");
    pep.stop();
}

#[test]
fn a_set_that_does_not_compile_keeps_the_one_held() {
    let stub = stub();
    let pep = Pep::new(config(&stub, "l-broken")).unwrap();
    pep.pull_now().unwrap();
    {
        let mut s = stub.script.lock().unwrap();
        let mut broken = orders_policy(false);
        broken["document"] = json!("<Policy this is not xml");
        s.policies = vec![broken];
        s.policy_token = "p3".into();
    }
    let err = pep.pull_now().unwrap_err();
    assert_eq!(err.code, "policy");
    assert!(pep.decide(&alice(None), &on("read")).is_permit());
    assert_eq!(pep.status().sync_token, "p1");
}

#[test]
fn the_heartbeat_reports_what_is_held_and_the_stream() {
    let stub = stub();
    let mut c = config(&stub, "l-beat");
    c.signals = true;
    let pep = Pep::new(c).unwrap();
    pep.start().unwrap();
    assert!(stub.wait(Duration::from_secs(5), |s| s.count("/xacml/pep/heartbeat") >= 1));
    let beat = stub.seen("/xacml/pep/heartbeat")[0].json();
    assert_eq!(beat["mode"], "local");
    assert_eq!(beat["syncToken"], "p1");
    assert_eq!(beat["policyCount"], 1);
    assert_eq!(beat["policyEvents"], "requested");
    pep.set_event_stream(EventStream::Excluded);
    assert!(stub.wait(Duration::from_secs(5), |s| s.seen("/xacml/pep/heartbeat").last().unwrap().json()["policyEvents"] == "excluded"));
    pep.stop();
}

#[test]
fn the_status_reports_times_counters_and_what_is_held() {
    let stub = stub();
    let mut c = config(&stub, "l-status");
    c.signals = true;
    c.fallback_poll_ms = 60_000;
    let pep = Pep::new(c).unwrap();
    let before = pep.status();
    assert_eq!((before.uptime, before.since_last_pull, before.until_next_pull), (None, None, None), "nothing has happened yet");
    pep.start().unwrap();
    assert!(stub.wait(Duration::from_secs(5), |_| pep.status().until_next_pull.is_some() && pep.status().since_last_heartbeat.is_some()));
    pep.decide(&alice(None), &on("read"));
    pep.decide(&alice(None), &on("write"));
    pep.on_policy_event(&json!({"pep": "another-pep"}));
    pep.on_policy_event(&json!({"pep": NAME}));
    assert!(stub.wait(Duration::from_secs(5), |_| pep.status().pulls >= 2), "the event pulled");
    let s = pep.status();
    assert!(s.uptime.is_some());
    assert_eq!(s.policy_count, 1);
    assert_eq!((s.decisions, s.allowed, s.refused), (2, 1, 1));
    assert_eq!(s.pulls_changed, 1, "the first pull brought the set, the second was 304");
    assert_eq!(s.pull_failures, 0);
    assert!(s.since_policy_update.is_some() && s.since_last_pull.unwrap() <= s.since_policy_update.unwrap());
    let next = s.until_next_pull.unwrap();
    assert!(next <= Duration::from_secs(60) && next > Duration::from_secs(50), "the fallback poll is about a minute away: {next:?}");
    assert!(s.until_next_heartbeat.unwrap() <= Duration::from_secs(1));
    assert!(s.heartbeats >= 1 && s.registrations == 1);
    assert_eq!((s.events_received, s.events_ignored), (1, 1));
    assert!(s.since_last_event.is_some());
    assert_eq!(s.catalogue_token, "c1");
    assert_eq!(s.catalogue_subject_properties, 1, "acr");
    assert_eq!(s.event_stream, EventStream::Requested);
    assert!(s.max_decision_micros >= s.mean_decision_micros && s.mean_decision_micros > 0);
    assert_eq!(s.pdp_url, stub.base);
    pep.stop();
    assert_eq!(pep.status().until_next_pull, None, "nothing is scheduled once stopped");
}
