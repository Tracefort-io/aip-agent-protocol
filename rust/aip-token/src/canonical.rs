//! Canonical Simple-profile block encoding (draft-prakash-aip-01 Section 3.4.1).
//!
//! Every caller that renders AIP Datalog goes through this module. The encoding
//! is normative: Section 3.4.1 requires implementations of the Simple profile to
//! emit exactly these forms, and two independent renderings of the same intent
//! drift into tokens that no other implementation can verify.
//!
//! Two rules from Section 3.4.1 are easy to get wrong and are enforced here by
//! construction:
//!
//! * Depth and budget are carried as FACTS, never as checks. A check of the form
//!   `check if budget($b), $b <= N` binds to whatever budget facts are in scope
//!   during evaluation, which is a different question from whether this block's
//!   ceiling narrows its parent's. Encoding either as a check therefore rejects
//!   valid chains, or passes unconditionally when the verifier supplies a
//!   satisfying ambient fact. Both are verified structurally in step V4 instead.
//!
//! * A block's scope constraint is ONE self-contained check. A rule-based
//!   encoding does not attenuate, because a delegation block's narrower rule is
//!   unioned with an ancestor's broader rule of the same name rather than
//!   replacing it, and the broader one then satisfies the delegation's check.

use std::time::SystemTime;

use crate::error::TokenError;

/// Render a string-valued fact, e.g. `identity("aip:web:example.com");`.
pub fn str_fact(name: &str, value: &str) -> String {
    format!("{name}(\"{value}\");\n")
}

/// Render an integer-valued fact, e.g. `max_depth(3);`.
pub fn int_fact(name: &str, value: i64) -> String {
    format!("{name}({value});\n")
}

/// Render a block's scope constraint as one self-contained check.
///
/// An all-exact scope set produces the Simple profile form (spec/aip-tokens.md
/// section 7.1). A set containing a wildcard produces the Standard profile
/// form (section 7.2), where patterns become `starts_with` clauses joined to
/// the exact-match clause with `or`.
pub fn tool_check(scopes: &[&str]) -> String {
    let exact: Vec<&str> = scopes.iter().filter(|s| !s.ends_with('*')).copied().collect();
    let wildcards: Vec<&str> = scopes.iter().filter(|s| s.ends_with('*')).copied().collect();

    let mut clauses: Vec<String> = Vec::new();
    if !exact.is_empty() {
        let items: Vec<String> = exact.iter().map(|s| format!("\"{s}\"")).collect();
        clauses.push(format!("tool($t), [{}].contains($t)", items.join(", ")));
    }
    for pattern in wildcards {
        let prefix = &pattern[..pattern.len() - 1];
        if prefix.is_empty() {
            clauses.push("tool($t)".to_string());
        } else {
            clauses.push(format!("tool($t), $t.starts_with(\"{prefix}\")"));
        }
    }

    if clauses.is_empty() {
        return String::new();
    }
    format!("check if {};\n", clauses.join(" or "))
}

/// Format a `SystemTime` as an RFC 3339 date-time string suitable for Biscuit Datalog.
pub fn format_system_time(t: SystemTime) -> String {
    let duration = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time before epoch");
    let secs = duration.as_secs();
    let dt = chrono::DateTime::from_timestamp(secs as i64, 0).expect("valid timestamp");
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Render a block's expiry constraint.
pub fn time_check(expiry: SystemTime) -> String {
    format!("check if time($t), $t <= {};\n", format_system_time(expiry))
}

/// Characters that let a value escape the Datalog string context it is written
/// into. A double quote closes the string outright. A backslash reprints as an
/// escape sequence that this implementation's block parsers do not decode. A
/// control character (newline included) splits one fact across lines, which the
/// line-oriented parsers in the attenuation walk then read as two facts.
///
/// Nothing else needs excluding. Semicolons, parentheses, brackets, commas,
/// `//`, spaces, colons and non-ASCII characters are all inert inside a quoted
/// term and round-trip unambiguously, so identifiers and free-form context
/// strings keep working.
const FORBIDDEN_CHARS: [char; 2] = ['"', '\\'];

/// Reject a string that could escape the Datalog string context.
///
/// AIP block and authorizer sources are Datalog text. A value carrying a double
/// quote can close its own term and append arbitrary facts, checks or policies
/// to a block that is then signed, or to the authorizer that decides a request.
/// Both are authorization bypasses, so this is enforced at every boundary where
/// a caller-supplied string becomes Datalog rather than left to the caller.
pub fn validate_term(value: &str, field: &str) -> Result<(), TokenError> {
    for ch in value.chars() {
        if FORBIDDEN_CHARS.contains(&ch) || ch.is_control() {
            return Err(TokenError::TokenMalformed(format!(
                "{field} contains a character that is not permitted in an AIP \
                 Datalog term: {ch:?}"
            )));
        }
    }
    Ok(())
}

/// Validate every scope in an allowlist.
pub fn validate_scopes(scopes: &[&str]) -> Result<(), TokenError> {
    for scope in scopes {
        validate_term(scope, "scope")?;
    }
    Ok(())
}
