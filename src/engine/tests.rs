// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! What the corpus does not pin down: `designators()`, compile errors, the
//! status code, the target index, and that nothing panics.

use std::time::SystemTime;

use super::*;

const NS: &str = r#"xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17""#;
const F: &str = "urn:oasis:names:tc:xacml:1.0:function:";
const INTEGER: &str = "http://www.w3.org/2001/XMLSchema#integer";

fn row(id: &str, is_root: bool, document: String) -> PolicyDocument {
    let kind = if document.trim_start().starts_with("<PolicySet") { "PolicySet" } else { "Policy" };
    PolicyDocument { policy_id: id.into(), kind: kind.into(), version: "1.0".into(), is_root, document }
}

fn designator(category: &str, id: &str, data_type: &str, must: bool) -> String {
    format!(
        r#"<AttributeDesignator Category="{}" AttributeId="{}" DataType="{}" MustBePresent="{}"/>"#,
        category, id, data_type, must
    )
}

/// A Policy for `subject-id` equal to `who`, with one Permit rule.
fn permit_for(id: &str, who: &str) -> String {
    format!(
        r#"<Policy {NS} PolicyId="{id}" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
            <Target><AnyOf><AllOf>
              <Match MatchId="{F}string-equal"><AttributeValue DataType="{STRING}">{who}</AttributeValue>{d}</Match>
            </AllOf></AnyOf></Target>
            <Rule RuleId="r" Effect="Permit"/>
           </Policy>"#,
        d = designator(ACCESS_SUBJECT, "subject-id", STRING, false)
    )
}

fn subject(id: &str) -> Request {
    Request {
        categories: vec![Category {
            category: ACCESS_SUBJECT.into(),
            has_content: false,
            attributes: vec![Attribute {
                attribute_id: "subject-id".into(),
                issuer: None,
                include_in_result: false,
                values: vec![AttributeValue::string(id)],
            }],
        }],
        ..Request::default()
    }
}

fn set_of(id: &str, alg: &str, children: &str) -> String {
    format!(
        r#"<PolicySet {NS} PolicySetId="{id}" PolicyCombiningAlgId="urn:oasis:names:tc:xacml:{alg}"><Target/>{children}</PolicySet>"#
    )
}

#[test]
fn designators_cover_referenced_policies_conditions_variables_and_obligations() {
    let referenced = format!(
        r#"<Policy {NS} PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:first-applicable">
            <VariableDefinition VariableId="age">
              <Apply FunctionId="{F}integer-one-and-only">{age}</Apply>
            </VariableDefinition>
            <Rule RuleId="r" Effect="Permit">
              <Condition><Apply FunctionId="{F}integer-greater-than"><VariableReference VariableId="age"/>
                <AttributeValue DataType="{INTEGER}">17</AttributeValue></Apply></Condition>
              <ObligationExpressions><ObligationExpression ObligationId="o" FulfillOn="Permit">
                <AttributeAssignmentExpression AttributeId="mail">{mail}</AttributeAssignmentExpression>
              </ObligationExpression></ObligationExpressions>
            </Rule>
           </Policy>"#,
        age = designator(ACCESS_SUBJECT, "age", INTEGER, true),
        mail = designator(ACCESS_SUBJECT, "mail", STRING, false),
    );
    let root = set_of(
        "root",
        "3.0:policy-combining-algorithm:deny-overrides",
        &format!("<PolicyIdReference>p</PolicyIdReference>{}", permit_for("inline", "alice")),
    );
    let policies = Policies::compile(&[row("root", true, root), row("p", false, referenced)]).unwrap();
    assert_eq!(policies.len(), 2);
    let ids: Vec<String> = policies.designators(ACCESS_SUBJECT).into_iter().map(|d| d.attribute_id).collect();
    assert_eq!(ids, ["age", "mail", "subject-id"]);
    assert!(policies.designators(RESOURCE).is_empty());

    // The variable is read through the reference, and the obligation fires.
    let mut request = subject("bob");
    request.categories[0].attributes.push(Attribute {
        attribute_id: "age".into(),
        issuer: None,
        include_in_result: false,
        values: vec![AttributeValue { data_type: INTEGER.into(), value: "42".into() }],
    });
    let response = policies.evaluate(&request, SystemTime::UNIX_EPOCH, &NoResolver);
    assert_eq!(response.decision, Decision::Permit);
    assert_eq!(response.obligations.len(), 1);
    assert!(response.obligations[0].assignments.is_empty(), "mail is absent, so no assignment");
    assert_eq!(response.status_code, STATUS_OK);
}

#[test]
fn a_compile_error_names_its_policy() {
    let bad = permit_for("broken", "x").replace("string-equal", "string-equal-ish");
    let root = set_of(
        "root",
        "3.0:policy-combining-algorithm:deny-overrides",
        "<PolicyIdReference>broken</PolicyIdReference>",
    );
    let error = Policies::compile(&[row("root", true, root.clone()), row("broken", false, bad)]).err().unwrap();
    assert_eq!(error.policy_id, "broken");
    assert!(error.message.contains("string-equal-ish"), "{}", error);

    let error = Policies::compile(&[row("root", true, root)]).err().unwrap();
    assert_eq!(error.policy_id, "root");
    assert!(error.message.contains("broken"), "{}", error);

    let looped =
        set_of("a", "3.0:policy-combining-algorithm:deny-overrides", "<PolicySetIdReference>a</PolicySetIdReference>");
    assert_eq!(Policies::compile(&[row("a", true, looped)]).err().unwrap().policy_id, "a");

    let error = Policies::compile(&[row("x", true, "<Policy".into())]).err().unwrap();
    assert_eq!(error.policy_id, "x");

    let cyclic = format!(
        r#"<Policy {NS} PolicyId="v" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
            <VariableDefinition VariableId="a"><VariableReference VariableId="b"/></VariableDefinition>
            <VariableDefinition VariableId="b"><Apply FunctionId="{F}not"><VariableReference VariableId="a"/></Apply></VariableDefinition>
           </Policy>"#
    );
    let error = Policies::compile(&[row("v", true, cyclic)]).err().unwrap();
    assert!(error.message.contains("VariableDefinition"), "{}", error);
}

#[test]
fn a_missing_must_be_present_attribute_is_missing_attribute() {
    let policy = format!(
        r#"<Policy {NS} PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
            <Rule RuleId="r" Effect="Permit"><Condition>
              <Apply FunctionId="{F}string-is-in"><AttributeValue DataType="{STRING}">a</AttributeValue>{d}</Apply>
            </Condition></Rule></Policy>"#,
        d = designator(RESOURCE, "owner", STRING, true)
    );
    let policies = Policies::compile(&[row("p", true, policy)]).unwrap();
    let response = policies.evaluate(&subject("alice"), SystemTime::UNIX_EPOCH, &NoResolver);
    assert_eq!(response.decision, Decision::Indeterminate);
    assert_eq!(response.status_code, "urn:oasis:names:tc:xacml:1.0:status:missing-attribute");

    // A resolver that supplies it turns the same request into a Permit.
    struct Owner;
    impl Resolver for Owner {
        fn resolve(&self, d: &Designator) -> Option<Vec<AttributeValue>> {
            (d.attribute_id == "owner").then(|| vec![AttributeValue::string("a")])
        }
    }
    let response = policies.evaluate(&subject("alice"), SystemTime::UNIX_EPOCH, &Owner);
    assert_eq!(response.decision, Decision::Permit);
}

#[test]
fn the_target_index_skips_only_what_cannot_match() {
    // Twenty keyed policies under first-applicable, one unkeyed at the end.
    let mut children: String = (0..20).map(|i| permit_for(&format!("p{}", i), &format!("user{}", i))).collect();
    children.push_str(&permit_for("catch", "user7").replace(r#"Effect="Permit""#, r#"Effect="Deny""#));
    let root = set_of("root", "1.0:policy-combining-algorithm:first-applicable", &children);
    let policies = Policies::compile(&[row("root", true, root)]).unwrap();
    assert!(policies.tree.nodes[policies.tree.root as usize].index.is_some());
    let decide = |who: &str| policies.evaluate(&subject(who), SystemTime::UNIX_EPOCH, &NoResolver).decision;
    assert_eq!(decide("user3"), Decision::Permit);
    assert_eq!(decide("user19"), Decision::Permit);
    assert_eq!(decide("nobody"), Decision::NotApplicable);

    // A value that cannot be parsed at the designator's type skips nothing,
    // and its Indeterminate surfaces.
    let integer_policy = permit_for("q", "1").replace(STRING, INTEGER).replace("string-equal", "integer-equal");
    let integer_set = set_of(
        "root",
        "3.0:policy-combining-algorithm:deny-overrides",
        &format!("{}{}", integer_policy, integer_policy.replace(r#"PolicyId="q""#, r#"PolicyId="r""#)),
    );
    let policies = Policies::compile(&[row("root", true, integer_set)]).unwrap();
    let mut request = subject("x");
    request.categories[0].attributes[0].values =
        vec![AttributeValue { data_type: INTEGER.into(), value: "one".into() }];
    let response = policies.evaluate(&request, SystemTime::UNIX_EPOCH, &NoResolver);
    assert_eq!(response.decision, Decision::Indeterminate);
    assert_eq!(response.status_code, "urn:oasis:names:tc:xacml:1.0:status:syntax-error");
}

#[test]
fn garbage_does_not_panic() {
    for document in [
        "",
        "not xml",
        "<Policy/>",
        "<PolicySet PolicySetId='x' PolicyCombiningAlgId='nope'/>",
        "<!DOCTYPE x [<!ENTITY a 'b'>]><Policy/>",
        &"<Apply>".repeat(100_000),
        &format!("<Policy>{}{}</Policy>", "<a>".repeat(300), "</a>".repeat(300)),
    ] {
        assert!(Policies::compile(&[row("x", true, document.to_string())]).is_err());
    }

    // Deep, but within the limits: compiles and evaluates.
    let deep = format!(
        r#"<Policy {NS} PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
            <Rule RuleId="r" Effect="Permit"><Condition>{}<AttributeValue DataType="http://www.w3.org/2001/XMLSchema#boolean">true</AttributeValue>{}</Condition></Rule></Policy>"#,
        format!(r#"<Apply FunctionId="{F}not">"#).repeat(150),
        "</Apply>".repeat(150)
    );
    let policies = Policies::compile(&[row("p", true, deep)]).unwrap();
    assert_eq!(policies.evaluate(&subject("x"), SystemTime::UNIX_EPOCH, &NoResolver).decision, Decision::Permit);
    assert!(Policies::compile(&[]).is_err());

    // Every function over every kind of odd value, with absurd literals.
    let odd = [
        ("integer", "170141183460469231731687303715884105727"),
        ("integer", "-170141183460469231731687303715884105728"),
        ("double", "NaN"),
        ("double", "-INF"),
        ("string", "\u{1F600}\u{0}"),
        ("dateTime", "999999999-12-31T24:59:60.999Z"),
        ("dateTime", "-999999999-01-01T00:00:00+99:99"),
        ("date", "0000-02-29"),
        ("dayTimeDuration", "P99999999999DT1S"),
        ("yearMonthDuration", "-P9999999999Y"),
        ("hexBinary", ""),
        ("base64Binary", "===="),
        ("anyURI", ""),
    ];
    let functions = [
        ("1.0", "integer-add"),
        ("1.0", "integer-multiply"),
        ("1.0", "integer-subtract"),
        ("1.0", "integer-divide"),
        ("1.0", "integer-mod"),
        ("1.0", "integer-abs"),
        ("1.0", "double-divide"),
        ("1.0", "double-to-integer"),
        ("1.0", "round"),
        ("1.0", "string-regexp-match"),
        ("1.0", "n-of"),
        ("1.0", "x500Name-match"),
        ("1.0", "dateTime-less-than"),
        ("3.0", "string-substring"),
        ("3.0", "dateTime-add-dayTimeDuration"),
        ("3.0", "dateTime-subtract-yearMonthDuration"),
        ("3.0", "date-add-yearMonthDuration"),
        ("3.0", "any-of"),
        ("3.0", "map"),
        ("3.0", "string-concatenate"),
    ];
    let mut body = String::new();
    for (version, f) in functions {
        for (ty, value) in odd {
            for (ty2, value2) in odd.iter().take(4) {
                body.push_str(&format!(
                    r#"<Rule RuleId="{n}" Effect="Permit"><Condition><Apply FunctionId="urn:oasis:names:tc:xacml:{version}:function:{f}">
                        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#{ty}">{value}</AttributeValue>
                        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#{ty2}">{value2}</AttributeValue>
                        {d}</Apply></Condition></Rule>"#,
                    n = body.len(),
                    value = value.replace('\u{0}', ""),
                    value2 = value2,
                    d = designator(ACCESS_SUBJECT, "subject-id", STRING, false),
                ));
            }
        }
    }
    let policy = format!(
        r#"<Policy {NS} PolicyId="p" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-unless-deny">{body}</Policy>"#
    );
    let policies = Policies::compile(&[row("p", true, policy)]).unwrap();
    for when in
        [SystemTime::UNIX_EPOCH, SystemTime::now(), SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(1 << 40)]
    {
        let mut request = subject("x");
        for (ty, value) in odd {
            request.categories[0].attributes[0].values.push(AttributeValue {
                data_type: format!("http://www.w3.org/2001/XMLSchema#{}", ty),
                value: value.into(),
            });
        }
        let response = policies.evaluate(&request, when, &NoResolver);
        assert_eq!(response.decision, Decision::Permit);
    }
}
