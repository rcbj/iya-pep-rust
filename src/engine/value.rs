// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The datatypes: lexical form to value, value back to the canonical lexical
//! form, equality and order.
//!
//! The canonical forms are the reference engine's (`sts-xacml`), because the
//! corpus states obligation values in them and the PEP hands them on.
//!
//! The places where equality is not string equality: a double's NaN equals
//! NaN (XML Schema has one NaN); an rfc822Name folds the domain's case and
//! not the local part's; an x500Name compares its RDNs in order, values
//! case-insensitively; dates and times compare as instants, and one with a
//! timezone against one without is ordered only when every timezone the
//! missing one could be (-14:00 to +14:00) gives the same answer.

use std::cmp::Ordering;
use std::sync::Arc;

/// The datatypes, by URI. `Other` is a datatype this engine does not know:
/// a designator may still name it, and any value of it fails to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Type {
    String,
    Boolean,
    Integer,
    Double,
    Time,
    Date,
    DateTime,
    DayTimeDuration,
    YearMonthDuration,
    AnyUri,
    HexBinary,
    Base64Binary,
    Rfc822Name,
    X500Name,
    DnsName,
    IpAddress,
    XPathExpression,
    Other,
}

const XS: &str = "http://www.w3.org/2001/XMLSchema#";
const LEGACY_XQ: &str = "http://www.w3.org/TR/2002/WD-xquery-operators-20020816#";

/// Every known type but `XPathExpression`, which takes part in no function
/// family, and `Other`.
pub(crate) const FAMILY: [Type; 16] = [
    Type::String,
    Type::Boolean,
    Type::Integer,
    Type::Double,
    Type::Time,
    Type::Date,
    Type::DateTime,
    Type::DayTimeDuration,
    Type::YearMonthDuration,
    Type::AnyUri,
    Type::HexBinary,
    Type::Base64Binary,
    Type::Rfc822Name,
    Type::X500Name,
    Type::DnsName,
    Type::IpAddress,
];

impl Type {
    /// The type a URI names. The two pre-3.0 XQuery spellings of the
    /// durations are accepted.
    pub(crate) fn from_uri(uri: &str) -> Type {
        if let Some(name) = uri.strip_prefix(XS) {
            return match name {
                "string" => Type::String,
                "boolean" => Type::Boolean,
                "integer" => Type::Integer,
                "double" => Type::Double,
                "time" => Type::Time,
                "date" => Type::Date,
                "dateTime" => Type::DateTime,
                "dayTimeDuration" => Type::DayTimeDuration,
                "yearMonthDuration" => Type::YearMonthDuration,
                "anyURI" => Type::AnyUri,
                "hexBinary" => Type::HexBinary,
                "base64Binary" => Type::Base64Binary,
                _ => Type::Other,
            };
        }
        match uri {
            "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name" => Type::Rfc822Name,
            "urn:oasis:names:tc:xacml:1.0:data-type:x500Name" => Type::X500Name,
            "urn:oasis:names:tc:xacml:2.0:data-type:dnsName" => Type::DnsName,
            "urn:oasis:names:tc:xacml:2.0:data-type:ipAddress" => Type::IpAddress,
            "urn:oasis:names:tc:xacml:3.0:data-type:xpathExpression" => Type::XPathExpression,
            _ => match uri.strip_prefix(LEGACY_XQ) {
                Some("dayTimeDuration") => Type::DayTimeDuration,
                Some("yearMonthDuration") => Type::YearMonthDuration,
                _ => Type::Other,
            },
        }
    }

    /// The canonical URI; `None` for `Other`.
    pub(crate) fn uri(self) -> Option<&'static str> {
        Some(match self {
            Type::String => "http://www.w3.org/2001/XMLSchema#string",
            Type::Boolean => "http://www.w3.org/2001/XMLSchema#boolean",
            Type::Integer => "http://www.w3.org/2001/XMLSchema#integer",
            Type::Double => "http://www.w3.org/2001/XMLSchema#double",
            Type::Time => "http://www.w3.org/2001/XMLSchema#time",
            Type::Date => "http://www.w3.org/2001/XMLSchema#date",
            Type::DateTime => "http://www.w3.org/2001/XMLSchema#dateTime",
            Type::DayTimeDuration => "http://www.w3.org/2001/XMLSchema#dayTimeDuration",
            Type::YearMonthDuration => "http://www.w3.org/2001/XMLSchema#yearMonthDuration",
            Type::AnyUri => "http://www.w3.org/2001/XMLSchema#anyURI",
            Type::HexBinary => "http://www.w3.org/2001/XMLSchema#hexBinary",
            Type::Base64Binary => "http://www.w3.org/2001/XMLSchema#base64Binary",
            Type::Rfc822Name => "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name",
            Type::X500Name => "urn:oasis:names:tc:xacml:1.0:data-type:x500Name",
            Type::DnsName => "urn:oasis:names:tc:xacml:2.0:data-type:dnsName",
            Type::IpAddress => "urn:oasis:names:tc:xacml:2.0:data-type:ipAddress",
            Type::XPathExpression => "urn:oasis:names:tc:xacml:3.0:data-type:xpathExpression",
            Type::Other => return None,
        })
    }

    /// The short name function identifiers are built from.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Type::String => "string",
            Type::Boolean => "boolean",
            Type::Integer => "integer",
            Type::Double => "double",
            Type::Time => "time",
            Type::Date => "date",
            Type::DateTime => "dateTime",
            Type::DayTimeDuration => "dayTimeDuration",
            Type::YearMonthDuration => "yearMonthDuration",
            Type::AnyUri => "anyURI",
            Type::HexBinary => "hexBinary",
            Type::Base64Binary => "base64Binary",
            Type::Rfc822Name => "rfc822Name",
            Type::X500Name => "x500Name",
            Type::DnsName => "dnsName",
            Type::IpAddress => "ipAddress",
            Type::XPathExpression => "xpathExpression",
            Type::Other => "",
        }
    }

    /// Whether the type has an order (and so the four comparison functions).
    pub(crate) fn is_ordered(self) -> bool {
        matches!(
            self,
            Type::String
                | Type::Integer
                | Type::Double
                | Type::Time
                | Type::Date
                | Type::DateTime
                | Type::DayTimeDuration
                | Type::YearMonthDuration
        )
    }
}

/// A canonical datatype URI: the legacy duration spellings mapped to XML
/// Schema's, anything else unchanged.
pub(crate) fn canonical_uri(uri: &str) -> &str {
    match Type::from_uri(uri) {
        Type::DayTimeDuration | Type::YearMonthDuration => Type::from_uri(uri).uri().unwrap_or(uri),
        _ => uri,
    }
}

/// Which of the three date/time grammars a [`Temporal`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    Date,
    Time,
    DateTime,
}

/// A date, time or dateTime in its local components. `tz` is minutes east
/// of UTC, and `None` (no timezone) is not UTC.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Temporal {
    pub(crate) shape: Shape,
    pub(crate) year: i64,
    pub(crate) month: u8,
    pub(crate) day: u8,
    pub(crate) hour: u8,
    pub(crate) minute: u8,
    pub(crate) second: f64,
    pub(crate) tz: Option<i32>,
}

/// A port range; `None` at an end is unbounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ports {
    pub(crate) low: Option<i64>,
    pub(crate) high: Option<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Rdn {
    /// Lower-cased.
    pub(crate) attribute: String,
    pub(crate) value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IpAddress {
    pub(crate) address: String,
    pub(crate) mask: Option<String>,
    pub(crate) ports: Ports,
}

/// A parsed value. Cheap to clone: everything that owns text is behind an
/// `Arc`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    String(Arc<str>),
    Boolean(bool),
    /// xs:integer is unbounded; this engine holds 128 bits, and a value or
    /// a result beyond them is Indeterminate.
    Integer(i128),
    Double(f64),
    Temporal(Temporal),
    /// Months.
    YearMonth(i64),
    /// Seconds.
    DayTime(f64),
    AnyUri(Arc<str>),
    Hex(Arc<[u8]>),
    Base64(Arc<[u8]>),
    /// The local part as written and the domain lower-cased.
    Rfc822(Arc<(String, String)>),
    X500(Arc<[Rdn]>),
    /// The host lower-cased.
    Dns(Arc<(String, Ports)>),
    Ip(Arc<IpAddress>),
    XPath(Arc<str>),
}

impl Value {
    /// The text of a string or an anyURI, which the string functions treat
    /// alike.
    pub(crate) fn text(&self) -> Option<&str> {
        match self {
            Value::String(s) | Value::AnyUri(s) => Some(s),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing.
// ---------------------------------------------------------------------------

/// Parses a lexical form at a type. `None` is a syntax error, which the
/// evaluator turns into an Indeterminate.
pub(crate) fn parse(ty: Type, lexical: &str) -> Option<Value> {
    let text = lexical.trim();
    Some(match ty {
        // xs:string keeps its whitespace.
        Type::String => Value::String(Arc::from(lexical)),
        Type::Boolean => match text {
            "true" | "1" => Value::Boolean(true),
            "false" | "0" => Value::Boolean(false),
            _ => return None,
        },
        Type::Integer => Value::Integer(parse_integer(text)?),
        Type::Double => Value::Double(parse_double(text)?),
        Type::Date => Value::Temporal(parse_temporal(text, Shape::Date)?),
        Type::Time => Value::Temporal(parse_temporal(text, Shape::Time)?),
        Type::DateTime => Value::Temporal(parse_temporal(text, Shape::DateTime)?),
        Type::YearMonthDuration => Value::YearMonth(parse_year_month(text)?),
        Type::DayTimeDuration => Value::DayTime(parse_day_time(text)?),
        Type::AnyUri => Value::AnyUri(Arc::from(text)),
        Type::HexBinary => Value::Hex(parse_hex(text)?.into()),
        Type::Base64Binary => Value::Base64(parse_base64(lexical)?.into()),
        Type::Rfc822Name => parse_rfc822(text)?,
        Type::X500Name => Value::X500(parse_x500(text)?.into()),
        Type::DnsName => parse_dns(text)?,
        Type::IpAddress => parse_ip(text)?,
        Type::XPathExpression => Value::XPath(Arc::from(text)),
        Type::Other => return None,
    })
}

fn all_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

fn parse_integer(text: &str) -> Option<i128> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if !all_digits(digits) {
        return None;
    }
    text.strip_prefix('+').unwrap_or(text).parse().ok()
}

fn parse_double(text: &str) -> Option<f64> {
    match text {
        "INF" | "+INF" => return Some(f64::INFINITY),
        "-INF" => return Some(f64::NEG_INFINITY),
        "NaN" => return Some(f64::NAN),
        _ => {}
    }
    // [+-]? (digits ('.' digits?)? | '.' digits) ([eE] [+-]? digits)?
    let body = text.strip_prefix(['+', '-']).unwrap_or(text);
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(at) => (&body[..at], Some(&body[at + 1..])),
        None => (body, None),
    };
    let mantissa_ok = match mantissa.split_once('.') {
        None => all_digits(mantissa),
        Some((whole, fraction)) => {
            (all_digits(whole) && (fraction.is_empty() || all_digits(fraction)))
                || (whole.is_empty() && all_digits(fraction))
        }
    };
    let exponent_ok = exponent.is_none_or(|e| all_digits(e.strip_prefix(['+', '-']).unwrap_or(e)));
    if !(mantissa_ok && exponent_ok) {
        return None;
    }
    text.parse().ok()
}

/// A run of exactly `n` ASCII digits at the front of `text`.
fn digits_n(text: &str, n: usize) -> Option<(i64, &str)> {
    let head = text.get(..n)?;
    if !all_digits(head) {
        return None;
    }
    Some((head.parse().ok()?, &text[n..]))
}

/// `Z`, `+hh:mm` or `-hh:mm`, or nothing. The hours and minutes are not
/// range-checked, as in the reference.
fn parse_timezone(text: &str) -> Option<Option<i32>> {
    if text.is_empty() {
        return Some(None);
    }
    if text == "Z" {
        return Some(Some(0));
    }
    let sign = match text.as_bytes()[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let (hours, rest) = digits_n(&text[1..], 2)?;
    let rest = rest.strip_prefix(':')?;
    let (minutes, rest) = digits_n(rest, 2)?;
    if !rest.is_empty() {
        return None;
    }
    Some(Some(sign * (hours * 60 + minutes) as i32))
}

/// Years beyond this are refused rather than risking overflow in the
/// calendar arithmetic (the reference takes any 64-bit year).
const MAX_YEAR: i64 = 999_999_999;

fn parse_date_part(text: &str) -> Option<(i64, i64, i64, &str)> {
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let year_len = rest.bytes().take_while(u8::is_ascii_digit).count();
    if year_len < 4 {
        return None;
    }
    let year: i64 = rest[..year_len].parse().ok()?;
    if year > MAX_YEAR {
        return None;
    }
    let rest = rest[year_len..].strip_prefix('-')?;
    let (month, rest) = digits_n(rest, 2)?;
    let rest = rest.strip_prefix('-')?;
    let (day, rest) = digits_n(rest, 2)?;
    Some((if negative { -year } else { year }, month, day, rest))
}

fn parse_time_part(text: &str) -> Option<(i64, i64, f64, &str)> {
    let (hour, rest) = digits_n(text, 2)?;
    let rest = rest.strip_prefix(':')?;
    let (minute, rest) = digits_n(rest, 2)?;
    let rest = rest.strip_prefix(':')?;
    rest.get(..2).filter(|w| all_digits(w))?;
    let mut end = 2;
    if rest[2..].starts_with('.') {
        let fraction = rest[3..].bytes().take_while(u8::is_ascii_digit).count();
        if fraction == 0 {
            return None;
        }
        end = 3 + fraction;
    }
    let second: f64 = rest[..end].parse().ok()?;
    Some((hour, minute, second, &rest[end..]))
}

fn parse_temporal(text: &str, shape: Shape) -> Option<Temporal> {
    let (mut year, mut month, mut day) = (1970, 1, 1);
    let (mut hour, mut minute, mut second) = (0, 0, 0.0);
    let rest = match shape {
        Shape::Date => {
            let (y, m, d, rest) = parse_date_part(text)?;
            (year, month, day) = (y, m, d);
            rest
        }
        Shape::Time => {
            let (h, mi, s, rest) = parse_time_part(text)?;
            (hour, minute, second) = (h, mi, s);
            rest
        }
        Shape::DateTime => {
            let (y, m, d, rest) = parse_date_part(text)?;
            let rest = rest.strip_prefix('T')?;
            let (h, mi, s, rest) = parse_time_part(rest)?;
            (year, month, day, hour, minute, second) = (y, m, d, h, mi, s);
            rest
        }
    };
    let tz = parse_timezone(rest)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 24 || minute > 59 || second >= 61.0 {
        return None;
    }
    Some(Temporal {
        shape,
        year,
        month: month as u8,
        day: day as u8,
        hour: hour as u8,
        minute: minute as u8,
        second,
        tz,
    })
}

fn parse_year_month(text: &str) -> Option<i64> {
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let mut rest = rest.strip_prefix('P')?;
    let mut months: i64 = 0;
    let mut any = false;
    for (unit, scale) in [('Y', 12i64), ('M', 1)] {
        let n = rest.bytes().take_while(u8::is_ascii_digit).count();
        if n > 0 && rest[n..].starts_with(unit) {
            let value: i64 = rest[..n].parse().ok()?;
            months = months.checked_add(value.checked_mul(scale)?)?;
            rest = &rest[n + 1..];
            any = true;
        }
    }
    if !any || !rest.is_empty() {
        return None;
    }
    Some(if negative { -months } else { months })
}

fn parse_day_time(text: &str) -> Option<f64> {
    let (negative, rest) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let mut rest = rest.strip_prefix('P')?;
    let mut seconds = 0.0;
    let mut any = false;
    let mut take = |rest: &mut &str, unit: char, scale: f64, fraction: bool| -> Option<()> {
        let n = rest.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return Some(());
        }
        let mut end = n;
        if fraction && rest[n..].starts_with('.') {
            let f = rest[n + 1..].bytes().take_while(u8::is_ascii_digit).count();
            if f == 0 {
                return Some(());
            }
            end = n + 1 + f;
        }
        if !rest[end..].starts_with(unit) {
            return Some(());
        }
        let value: f64 = if fraction { rest[..end].parse().ok()? } else { rest[..end].parse::<i64>().ok()? as f64 };
        seconds += value * scale;
        any = true;
        *rest = &rest[end + 1..];
        Some(())
    };
    take(&mut rest, 'D', 86400.0, false)?;
    if let Some(after) = rest.strip_prefix('T') {
        if after.is_empty() {
            return None;
        }
        rest = after;
        take(&mut rest, 'H', 3600.0, false)?;
        take(&mut rest, 'M', 60.0, false)?;
        take(&mut rest, 'S', 1.0, true)?;
    }
    if !any || !rest.is_empty() {
        return None;
    }
    Some(if negative { -seconds } else { seconds })
}

fn parse_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digit = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    text.as_bytes().chunks(2).map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?)).collect()
}

fn parse_base64(lexical: &str) -> Option<Vec<u8>> {
    let text: Vec<u8> = lexical.chars().filter(|c| !c.is_whitespace()).collect::<String>().into_bytes();
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let body_len = text.iter().rposition(|&b| b != b'=').map_or(0, |i| i + 1);
    if text.len() - body_len > 2 {
        return None;
    }
    let sextet = |b: u8| -> Option<u32> {
        Some(match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::with_capacity(body_len * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &b in &text[..body_len] {
        buffer = (buffer << 6) | sextet(b)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    // Leftover bits are ignored, not insisted to be zero (as Node's decoder).
    Some(out)
}

fn has_space_or_at(text: &str) -> bool {
    text.chars().any(|c| c.is_whitespace() || c == '@')
}

fn parse_rfc822(text: &str) -> Option<Value> {
    let at = text.rfind('@')?;
    if at == 0 || at == text.len() - 1 {
        return None;
    }
    let (local, domain) = (&text[..at], &text[at + 1..]);
    if has_space_or_at(local) || has_space_or_at(domain) {
        return None;
    }
    Some(Value::Rfc822(Arc::new((local.to_string(), domain.to_lowercase()))))
}

/// RFC 2253 far enough to compare: a comma that is quoted or escaped does
/// not separate.
fn parse_x500(text: &str) -> Option<Vec<Rdn>> {
    if text.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    let mut current = String::new();
    let (mut escaped, mut quoted) = (false, false);
    for c in text.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if c == ',' && !quoted {
            parts.push(std::mem::take(&mut current));
            continue;
        }
        current.push(c);
    }
    parts.push(current);
    parts
        .iter()
        .map(|part| {
            let piece = part.trim();
            let equals = piece.find('=').filter(|&e| e > 0)?;
            Some(Rdn {
                attribute: piece[..equals].trim().to_lowercase(),
                value: piece[equals + 1..].trim().to_string(),
            })
        })
        .collect()
}

/// JavaScript's `parseInt(text, 10)`: leading digits after a sign.
fn js_parse_int(text: &str) -> Option<i64> {
    let text = text.trim_start();
    let (sign, rest) = match text.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, text.strip_prefix('+').unwrap_or(text)),
    };
    let n = rest.bytes().take_while(u8::is_ascii_digit).count();
    if n == 0 {
        return None;
    }
    rest[..n].parse::<i64>().ok().map(|v| sign * v)
}

fn parse_ports(text: &str) -> Option<Ports> {
    if text.is_empty() {
        return Some(Ports { low: None, high: None });
    }
    match text.find('-') {
        None => {
            let single = js_parse_int(text)?;
            Some(Ports { low: Some(single), high: Some(single) })
        }
        Some(dash) => {
            let end = |part: &str| if part.is_empty() { None } else { js_parse_int(part) };
            Some(Ports { low: end(&text[..dash]), high: end(&text[dash + 1..]) })
        }
    }
}

fn parse_dns(text: &str) -> Option<Value> {
    let (host, ports) = text.split_once(':').unwrap_or((text, ""));
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        return None;
    }
    Some(Value::Dns(Arc::new((host.to_lowercase(), parse_ports(ports)?))))
}

/// An IPv6 literal is bracketed, which tells its colons from the port's.
fn parse_ip(text: &str) -> Option<Value> {
    if text.is_empty() {
        return None;
    }
    let (address, rest) = match text.strip_prefix('[') {
        Some(inner) => {
            let close = inner.find(']')?;
            (&inner[..close], &inner[close + 1..])
        }
        None => match text.find(':') {
            Some(colon) => (&text[..colon], &text[colon..]),
            None => (text, ""),
        },
    };
    let (address, mask) = match address.split_once('/') {
        Some((address, mask)) => (address, Some(mask.to_string())),
        None => (address, None),
    };
    let ports = parse_ports(rest.strip_prefix(':').unwrap_or(""))?;
    Some(Value::Ip(Arc::new(IpAddress { address: address.to_lowercase(), mask, ports })))
}

// ---------------------------------------------------------------------------
// Writing: the canonical lexical forms.
// ---------------------------------------------------------------------------

/// A value's canonical lexical form at a type. `None` when the type is
/// unknown or the value is not of it.
pub(crate) fn write(ty: Type, value: &Value) -> Option<String> {
    Some(match (ty, value) {
        (Type::String, v) | (Type::AnyUri, v) => v.text()?.to_string(),
        (Type::Boolean, Value::Boolean(b)) => b.to_string(),
        (Type::Integer, Value::Integer(i)) => i.to_string(),
        (Type::Double, Value::Double(d)) => write_double(*d),
        (Type::Date | Type::Time | Type::DateTime, Value::Temporal(t)) => write_temporal(t),
        (Type::YearMonthDuration, Value::YearMonth(m)) => {
            let sign = if *m < 0 { "-" } else { "" };
            let m = m.unsigned_abs();
            format!("{}P{}Y{}M", sign, m / 12, m % 12)
        }
        (Type::DayTimeDuration, Value::DayTime(s)) => write_day_time(*s),
        (Type::HexBinary, Value::Hex(bytes)) => bytes.iter().map(|b| format!("{:02X}", b)).collect(),
        (Type::Base64Binary, Value::Base64(bytes)) => encode_base64(bytes),
        (Type::Rfc822Name, Value::Rfc822(pair)) => format!("{}@{}", pair.0, pair.1),
        (Type::X500Name, Value::X500(rdns)) => {
            let parts: Vec<String> =
                rdns.iter().map(|r| format!("{}={}", r.attribute.to_uppercase(), r.value)).collect();
            parts.join(",")
        }
        (Type::DnsName, Value::Dns(pair)) => write_host_ports(&pair.0, &pair.1),
        // The port range is not written back, as in the reference.
        (Type::IpAddress, Value::Ip(ip)) => match &ip.mask {
            Some(mask) if !mask.is_empty() => format!("{}/{}", ip.address, mask),
            _ => ip.address.clone(),
        },
        (Type::XPathExpression, Value::XPath(x)) => x.to_string(),
        _ => return None,
    })
}

fn write_host_ports(host: &str, ports: &Ports) -> String {
    if ports.low.is_none() && ports.high.is_none() {
        return host.to_string();
    }
    let show = |p: Option<i64>| p.map(|v| v.to_string()).unwrap_or_default();
    if ports.low == ports.high {
        format!("{}:{}", host, show(ports.low))
    } else {
        format!("{}:{}-{}", host, show(ports.low), show(ports.high))
    }
}

/// xs:double's form: an integral value keeps a `.0`.
fn write_double(v: f64) -> String {
    if v == f64::INFINITY {
        "INF".into()
    } else if v == f64::NEG_INFINITY {
        "-INF".into()
    } else if v.is_nan() {
        "NaN".into()
    } else if v.fract() == 0.0 && v.abs() < 1e21 {
        if v == 0.0 {
            "0.0".into()
        } else {
            format!("{:.1}", v)
        }
    } else {
        js_number(v)
    }
}

fn write_day_time(total: f64) -> String {
    let sign = if total < 0.0 { "-" } else { "" };
    let mut rest = total.abs();
    let days = (rest / 86400.0).floor();
    rest -= days * 86400.0;
    let hours = (rest / 3600.0).floor();
    rest -= hours * 3600.0;
    let minutes = (rest / 60.0).floor();
    rest -= minutes * 60.0;
    format!("{}P{}DT{}H{}M{}S", sign, js_number(days), js_number(hours), js_number(minutes), js_number(rest))
}

fn write_temporal(t: &Temporal) -> String {
    let year = if t.year.abs() < 1000 && t.year >= 0 {
        format!("{:04}", t.year)
    } else if t.year < 0 && t.year > -100 {
        // JavaScript's padStart(4, '0') of "-5" is "00-5"; kept for identical
        // output.
        format!("{:0>4}", t.year)
    } else {
        t.year.to_string()
    };
    let seconds = format!("{}{}", if t.second < 10.0 { "0" } else { "" }, js_number(t.second));
    let date = || format!("{}-{:02}-{:02}", year, t.month, t.day);
    let time = || format!("{:02}:{:02}:{}", t.hour, t.minute, seconds);
    let body = match t.shape {
        Shape::Date => date(),
        Shape::Time => time(),
        Shape::DateTime => format!("{}T{}", date(), time()),
    };
    let zone = match t.tz {
        None => String::new(),
        Some(0) => "Z".into(),
        Some(m) => format!("{}{:02}:{:02}", if m < 0 { '-' } else { '+' }, m.abs() / 60, m.abs() % 60),
    };
    body + &zone
}

/// JavaScript's `Number.prototype.toString()`, which is how the reference
/// writes a double inside a duration or a time.
pub(crate) fn js_number(v: f64) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    if v == 0.0 {
        return "0".into();
    }
    // `{:e}` gives the shortest digits that round-trip, as ECMAScript asks.
    let scientific = format!("{:e}", v.abs());
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i64;
    let n = exponent.parse::<i64>().unwrap_or(0) + 1;
    let body = if k <= n && n <= 21 {
        format!("{}{}", digits, "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        let e = n - 1;
        let sign = if e >= 0 { '+' } else { '-' };
        if k == 1 {
            format!("{}e{}{}", digits, sign, e.abs())
        } else {
            format!("{}.{}e{}{}", &digits[..1], &digits[1..], sign, e.abs())
        }
    };
    if v < 0.0 {
        format!("-{}", body)
    } else {
        body
    }
}

fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &b)| acc | (b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Equality and order.
// ---------------------------------------------------------------------------

/// Equality over the value space. Values of different kinds are unequal.
pub(crate) fn equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Double(x), Value::Double(y)) => (x.is_nan() && y.is_nan()) || x == y,
        (Value::Temporal(x), Value::Temporal(y)) => compare_temporal(x, y) == Some(Ordering::Equal),
        (Value::X500(x), Value::X500(y)) => x500_equal(x, y),
        _ => a == b,
    }
}

/// The order, or `None` when the two are incomparable (which the comparison
/// functions turn into an Indeterminate).
pub(crate) fn compare(a: &Value, b: &Value) -> Option<Ordering> {
    match (a, b) {
        (Value::String(x), Value::String(y)) => Some(x.encode_utf16().cmp(y.encode_utf16())),
        (Value::Integer(x), Value::Integer(y)) => Some(x.cmp(y)),
        (Value::Double(x), Value::Double(y)) => x.partial_cmp(y),
        (Value::Temporal(x), Value::Temporal(y)) => compare_temporal(x, y),
        (Value::YearMonth(x), Value::YearMonth(y)) => Some(x.cmp(y)),
        (Value::DayTime(x), Value::DayTime(y)) => x.partial_cmp(y),
        _ => None,
    }
}

pub(crate) fn x500_equal(a: &[Rdn], b: &[Rdn]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(x, y)| x.attribute == y.attribute && x.value.to_lowercase() == y.value.to_lowercase())
}

/// Days since 1970-01-01 in the proleptic Gregorian calendar.
pub(crate) fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
pub(crate) fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// Seconds since the epoch, the value's own offset applied or `assumed`
/// minutes where it has none. A time has no date.
fn instant(t: &Temporal, assumed: i32) -> f64 {
    let mut seconds = 0.0;
    if t.shape != Shape::Time {
        seconds += (days_from_civil(t.year, t.month.into(), t.day.into()) * 86_400) as f64;
    }
    seconds += f64::from(t.hour) * 3600.0 + f64::from(t.minute) * 60.0 + t.second;
    seconds - f64::from(t.tz.unwrap_or(assumed)) * 60.0
}

fn compare_temporal(a: &Temporal, b: &Temporal) -> Option<Ordering> {
    if a.tz.is_some() == b.tz.is_some() {
        return instant(a, 0).partial_cmp(&instant(b, 0));
    }
    let east = instant(a, 14 * 60).partial_cmp(&instant(b, 14 * 60))?;
    let west = instant(a, -14 * 60).partial_cmp(&instant(b, -14 * 60))?;
    (east == west).then_some(east)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    const LENGTHS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    if month == 2 && leap {
        29
    } else {
        LENGTHS[(month - 1).clamp(0, 11) as usize]
    }
}

/// Months added on the local components, the day clamped to the target
/// month's length and the timezone carried through.
pub(crate) fn add_months(t: &Temporal, months: i64) -> Option<Temporal> {
    let total = t.year.checked_mul(12)?.checked_add(i64::from(t.month) - 1)?.checked_add(months)?;
    let year = total.div_euclid(12);
    if year.abs() > MAX_YEAR {
        return None;
    }
    let month = total.rem_euclid(12) + 1;
    let day = i64::from(t.day).min(days_in_month(year, month));
    Some(Temporal { year, month: month as u8, day: day as u8, ..*t })
}

/// Seconds added on the local components, the timezone carried through.
pub(crate) fn add_seconds(t: &Temporal, seconds: f64) -> Option<Temporal> {
    let date = if t.shape == Shape::Time {
        0.0
    } else {
        (days_from_civil(t.year, t.month.into(), t.day.into()) * 86_400) as f64
    };
    let total = date + f64::from(t.hour) * 3600.0 + f64::from(t.minute) * 60.0 + t.second + seconds;
    if !total.is_finite() || total.abs() > (MAX_YEAR as f64) * 366.0 * 86_400.0 {
        return None;
    }
    let days = (total / 86_400.0).floor();
    let mut rest = total - days * 86_400.0;
    let hour = (rest / 3600.0).floor();
    rest -= hour * 3600.0;
    let minute = (rest / 60.0).floor();
    let second = rest - minute * 60.0;
    let (year, month, day) = civil_from_days(days as i64);
    Some(Temporal {
        shape: t.shape,
        year,
        month: month as u8,
        day: day as u8,
        hour: hour as u8,
        minute: minute as u8,
        second,
        tz: t.tz,
    })
}

/// `now` as the three `current-*` values, in UTC to the whole second.
pub(crate) fn now_temporal(seconds: i64, shape: Shape) -> Temporal {
    let days = seconds.div_euclid(86_400);
    let of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let mut t = Temporal {
        shape,
        year,
        month: month as u8,
        day: day as u8,
        hour: (of_day / 3600) as u8,
        minute: (of_day % 3600 / 60) as u8,
        second: (of_day % 60) as f64,
        tz: Some(0),
    };
    match shape {
        Shape::Date => (t.hour, t.minute, t.second) = (0, 0, 0.0),
        Shape::Time => (t.year, t.month, t.day) = (1970, 1, 1),
        Shape::DateTime => {}
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(ty: Type, text: &str) -> Option<String> {
        write(ty, &parse(ty, text)?)
    }

    #[test]
    fn canonical_forms() {
        assert_eq!(round_trip(Type::Double, "1").as_deref(), Some("1.0"));
        assert_eq!(round_trip(Type::Double, "-INF").as_deref(), Some("-INF"));
        assert_eq!(round_trip(Type::Double, "1.5e-7").as_deref(), Some("1.5e-7"));
        assert_eq!(round_trip(Type::DayTimeDuration, "P1DT2H").as_deref(), Some("P1DT2H0M0S"));
        assert_eq!(round_trip(Type::YearMonthDuration, "-P14M").as_deref(), Some("-P1Y2M"));
        assert_eq!(
            round_trip(Type::DateTime, "2002-03-22T08:23:47-05:00").as_deref(),
            Some("2002-03-22T08:23:47-05:00")
        );
        assert_eq!(round_trip(Type::Time, "08:23:47.5Z").as_deref(), Some("08:23:47.5Z"));
        assert_eq!(round_trip(Type::HexBinary, "0fb7").as_deref(), Some("0FB7"));
        assert_eq!(round_trip(Type::Base64Binary, "Zm9v\nYmE=").as_deref(), Some("Zm9vYmE="));
        assert_eq!(round_trip(Type::X500Name, "cn=Bob, o=Acme").as_deref(), Some("CN=Bob,O=Acme"));
        assert_eq!(round_trip(Type::Rfc822Name, "Bob@EXAMPLE.com").as_deref(), Some("Bob@example.com"));
    }

    #[test]
    fn rejects_bad_lexical_forms() {
        for (ty, text) in [
            (Type::Integer, "1.0"),
            (Type::Double, "1e"),
            (Type::Date, "2002-13-01"),
            (Type::DayTimeDuration, "P1DT"),
            (Type::DayTimeDuration, "PT"),
            (Type::YearMonthDuration, "P"),
            (Type::Boolean, "yes"),
            (Type::Base64Binary, "abc"),
            (Type::HexBinary, "abc"),
            (Type::Rfc822Name, "@x"),
        ] {
            assert!(parse(ty, text).is_none(), "{:?} {}", ty, text);
        }
    }

    #[test]
    fn equality_rules() {
        let nan = parse(Type::Double, "NaN").unwrap();
        assert!(equal(&nan, &nan));
        let a = parse(Type::DateTime, "2002-03-22T08:23:47").unwrap();
        let b = parse(Type::DateTime, "2002-03-22T08:23:47Z").unwrap();
        assert_eq!(compare(&a, &b), None);
        assert!(!equal(&a, &b));
        let x = parse(Type::X500Name, "CN=Bob,O=Acme").unwrap();
        let y = parse(Type::X500Name, "cn=bob, o=ACME").unwrap();
        assert!(equal(&x, &y));
    }

    #[test]
    fn calendar_round_trip_and_month_clamp() {
        for days in [-800_000, -1, 0, 1, 19_000, 2_000_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        let jan31 = parse(Type::Date, "2024-01-31").unwrap();
        let Value::Temporal(t) = jan31 else { unreachable!() };
        let feb = add_months(&t, 1).unwrap();
        assert_eq!((feb.year, feb.month, feb.day), (2024, 2, 29));
    }

    #[test]
    fn js_numbers() {
        assert_eq!(js_number(1.0), "1");
        assert_eq!(js_number(1e21), "1e+21");
        assert_eq!(js_number(1e20), "100000000000000000000");
        assert_eq!(js_number(0.000001), "0.000001");
        assert_eq!(js_number(-0.25), "-0.25");
    }
}
