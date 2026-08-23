//! Regression tests for Datalog injection in the block encoders and authorizer.
//!
//! Both of these were live authorization bypasses, present identically in the
//! Python SDK, with forged tokens portable between the two.
//!
//! F1, the authorizer: `authorize()` interpolated the requested tool name into
//! the Biscuit authorizer source. A tool name that closed its own string could
//! append `allow if true` and an in-allowlist `tool()` fact, so a token granting
//! only `tool:search` authorized anything. No malicious token, no forged
//! signature and no control of the issuer was required, only influence over the
//! tool name being checked. In an MCP binding that name arrives directly from
//! the agent's JSON-RPC `params.name`.
//!
//! F2, the block encoders: `create_authority` and `delegate` interpolated the
//! issuer, scope, delegator, delegate and context values into block Datalog. A
//! breakout in any of them injected facts into a block that was then signed. An
//! injected in-allowlist `tool()` fact satisfies the authority block's own scope
//! check for any requested tool, and an injected `max_depth()` placed before the
//! real one is what the first-match parser in V3 reads.

use aip_core::crypto::KeyPair;
use aip_token::chained::ChainedToken;

/// Closes the tool string, satisfies the scope check with an in-allowlist fact,
/// forces the policy, and comments out the generated remainder.
const AUTHORIZER_PAYLOAD: &str = r#"admin:wipe"); tool("tool:search"); allow if true; //"#;

/// Closes the identity string and injects a permissive tool fact plus a wider
/// max_depth ahead of the real one.
const BLOCK_PAYLOAD: &str =
    r#"aip:web:x"); tool("tool:search"); max_depth(99); identity("aip:web:x"#;

fn search_only() -> (ChainedToken, KeyPair) {
    let kp = KeyPair::generate();
    let token = ChainedToken::create_authority(
        "aip:web:honest.example",
        &["tool:search"],
        Some(100),
        2,
        3600,
        &kp,
    )
    .expect("authority token");
    (token, kp)
}

fn pubkey(kp: &KeyPair) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&kp.public_key_bytes());
    out
}

#[test]
fn control_legitimate_tool_is_authorized() {
    let (token, kp) = search_only();
    assert!(token.authorize("tool:search", &pubkey(&kp)).is_ok());
}

#[test]
fn control_unauthorized_tool_is_denied() {
    let (token, kp) = search_only();
    let err = token.authorize("admin:wipe", &pubkey(&kp)).unwrap_err();
    assert_eq!(err.error_code(), "aip_scope_insufficient");
}

/// F1: a hostile tool name must never reach the authorizer source.
#[test]
fn authorizer_injection_is_rejected() {
    let (token, kp) = search_only();
    let payloads = [
        AUTHORIZER_PAYLOAD,
        r#"admin:wipe"); allow if true; //"#,
        r#"x"); time(2000-01-01T00:00:00Z); allow if true; //"#,
        "admin:wipe\ntool(\"tool:search\")",
        r#"admin:wipe\"); tool("tool:search"); allow if true; //"#,
    ];
    for payload in payloads {
        let err = token
            .authorize(payload, &pubkey(&kp))
            .err().expect("hostile tool name must be rejected");
        assert_eq!(
            err.error_code(),
            "aip_token_malformed",
            "payload was not rejected as malformed: {payload:?}"
        );
    }
}

/// F2: no mint field may inject facts into the signed authority block.
#[test]
fn authority_block_injection_is_rejected() {
    let kp = KeyPair::generate();

    let err = ChainedToken::create_authority(BLOCK_PAYLOAD, &["tool:search"], Some(100), 1, 3600, &kp)
        .err().expect("hostile issuer must be rejected");
    assert_eq!(err.error_code(), "aip_token_malformed");

    let err = ChainedToken::create_authority(
        "aip:web:honest.example",
        &[r#"tool:search"); tool("admin:wipe"#],
        Some(100),
        1,
        3600,
        &kp,
    )
    .err().expect("hostile scope must be rejected");
    assert_eq!(err.error_code(), "aip_token_malformed");

    let err = ChainedToken::create_authority(
        "aip:web:x\ntool(\"admin:wipe\")",
        &["tool:search"],
        Some(100),
        1,
        3600,
        &kp,
    )
    .err().expect("newline in issuer must be rejected");
    assert_eq!(err.error_code(), "aip_token_malformed");
}

#[test]
fn delegation_block_injection_is_rejected() {
    let (token, _kp) = search_only();

    for (delegator, delegate, context) in [
        (r#"aip:web:a"); tool("x"#, "aip:key:b", "ctx"),
        ("aip:web:a", r#"aip:key:b"); tool("x"#, "ctx"),
        ("aip:web:a", "aip:key:b", r#"ctx"); tool("admin:wipe"); //"#),
    ] {
        let err = token
            .delegate(delegator, delegate, &["tool:search"], Some(50), context)
            .err().expect("hostile delegation field must be rejected");
        assert_eq!(err.error_code(), "aip_token_malformed");
    }
}

/// Validation must not break identifiers and context that are merely odd.
///
/// Semicolons, parentheses, brackets, commas, `//`, spaces, colons and
/// non-ASCII characters are inert inside a quoted Datalog term.
#[test]
fn unusual_but_legitimate_values_still_work() {
    let kp = KeyPair::generate();
    let token = ChainedToken::create_authority(
        "aip:web:例え.com/path/to/agent",
        &["tool:search", "fs.*"],
        Some(100),
        2,
        3600,
        &kp,
    )
    .expect("unicode issuer is legitimate");

    let delegated = token
        .delegate(
            "aip:web:例え.com/path/to/agent",
            "aip:key:z",
            &["tool:search"],
            Some(50),
            "quarterly report; sub-task (2 of 3) [urgent] // rush",
        )
        .expect("punctuation in context is legitimate");

    assert!(delegated.authorize("tool:search", &pubkey(&kp)).is_ok());
}
