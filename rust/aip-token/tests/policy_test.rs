//! Tests for SimplePolicy Datalog generation.
//!
//! The canonical Simple-profile encoding is normative (draft-prakash-aip-01
//! Section 3.4.1). These tests pin the mandated forms and, just as importantly,
//! pin the two forms the draft forbids.

use aip_token::policy::{PolicyProfile, SimplePolicy};

fn policy(
    tools: &[&str],
    budget_cents: Option<i64>,
    max_depth: Option<u32>,
    ttl_seconds: Option<u64>,
) -> SimplePolicy {
    SimplePolicy {
        tools: tools.iter().map(|s| (*s).to_string()).collect(),
        budget_cents,
        max_depth,
        ttl_seconds,
    }
}

#[test]
fn test_simple_policy_tool_allowlist() {
    let datalog = policy(&["search", "browse"], None, None, None).to_datalog();
    assert!(datalog.contains(r#"check if tool($t), ["search", "browse"].contains($t);"#));
}

#[test]
fn test_wildcard_scope_uses_starts_with() {
    let datalog = policy(&["fs.read", "net.*"], None, None, None).to_datalog();
    assert!(datalog.contains(r#"tool($t), ["fs.read"].contains($t)"#));
    assert!(datalog.contains(r#"tool($t), $t.starts_with("net.")"#));
    assert!(datalog.contains(" or "));
}

#[test]
fn test_budget_is_a_fact_not_a_check() {
    let datalog = policy(&[], Some(50), None, None).to_datalog();
    assert!(datalog.contains("budget_ceiling(50);"));
}

#[test]
fn test_depth_is_a_fact_not_a_check() {
    let datalog = policy(&[], None, Some(3), None).to_datalog();
    assert!(datalog.contains("max_depth(3);"));
}

/// Section 3.4.1: implementations MUST NOT emit a check over budget.
///
/// A check binds to whatever budget facts are in scope at evaluation rather
/// than to this block's ceiling, so it either rejects valid chains or passes
/// unconditionally. Depth is a fact for the same reason. Both are verified
/// structurally in step V4.
#[test]
fn test_never_emits_a_check_over_budget_or_depth() {
    let datalog = policy(&["search"], Some(100), Some(3), Some(3600)).to_datalog();
    assert!(!datalog.contains("check if budget"));
    assert!(!datalog.contains("check if depth"));
    assert!(!datalog.contains("budget($b)"));
    assert!(!datalog.contains("depth($d)"));
}

#[test]
fn test_simple_policy_full_emits_canonical_order() {
    let datalog = policy(&["search"], Some(100), Some(3), Some(3600)).to_datalog();
    assert!(datalog.contains("max_depth(3);"));
    assert!(datalog.contains("budget_ceiling(100);"));
    assert!(datalog.contains("check if tool($t)"));
    assert!(datalog.contains("check if time($t)"));

    // Section 3.4.1 lists facts before checks, and max_depth before budget_ceiling.
    let depth_at = datalog.find("max_depth(3);").unwrap();
    let budget_at = datalog.find("budget_ceiling(100);").unwrap();
    let tool_at = datalog.find("check if tool($t)").unwrap();
    let time_at = datalog.find("check if time($t)").unwrap();
    assert!(depth_at < budget_at);
    assert!(budget_at < tool_at);
    assert!(tool_at < time_at);
}

#[test]
fn test_simple_policy_empty() {
    let datalog = policy(&[], None, None, None).to_datalog();
    assert!(datalog.is_empty());
}

#[test]
fn test_policy_profile_enum() {
    let simple = PolicyProfile::Simple(policy(&["search"], None, None, None));
    assert!(!simple.to_datalog().is_empty());
}

#[test]
fn test_standard_profile_passthrough() {
    let standard = PolicyProfile::Standard("check if user($u);".into());
    assert_eq!(standard.to_datalog(), "check if user($u);");
}
