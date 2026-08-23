"""Regression tests for Datalog injection in the block encoders and authorizer.

Both of these were live authorization bypasses.

F1, the authorizer: `authorize()` interpolated the requested tool name into the
Biscuit authorizer source. A tool name that closed its own string could append
`allow if true` and an in-allowlist `tool()` fact, so a token granting only
`tool:search` authorized anything. No malicious token, no forged signature and
no control of the issuer was required, only influence over the tool name being
checked. In an MCP binding that name arrives directly from the agent's
JSON-RPC `params.name`.

F2, the block encoders: `create_authority` and `delegate` interpolated the
issuer, principal, scope, delegator, delegate and context values into block
Datalog. A breakout in any of them injected facts into a block that was then
signed. An injected in-allowlist `tool()` fact satisfies the authority block's
own scope check for any requested tool, an injected past `time()` fact defeats
expiry, and an injected `max_depth()` placed before the real one is what the
first-match parser in V3 reads.

The fix rejects the characters that can escape a Datalog string context, and
binds the tool as a parameter rather than interpolating it. Values that are
merely unusual must keep working, which the last test pins.
"""

import pytest

from aip_core.crypto import KeyPair
from aip_token.error import TokenError

biscuit = pytest.importorskip("biscuit_auth", reason="biscuit-python not installed")

from aip_token.chained import ChainedToken  # noqa: E402

# Closes the tool string, satisfies the scope check with an in-allowlist fact,
# forces the policy, and comments out the generated remainder.
AUTHORIZER_PAYLOAD = 'admin:wipe"); tool("tool:search"); allow if true; //'

# Closes the identity string and injects a permissive tool fact plus a wider
# max_depth ahead of the real one.
BLOCK_PAYLOAD = 'aip:web:x"); tool("tool:search"); max_depth(99); identity("aip:web:x'


@pytest.fixture
def search_only():
    kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:honest.example",
        scopes=["tool:search"],
        budget_cents=100,
        max_depth=2,
        ttl_seconds=3600,
        keypair=kp,
    )
    return token, kp.public_key_bytes()


def test_control_legitimate_tool_is_authorized(search_only):
    token, pk = search_only
    token.authorize("tool:search", pk)


def test_control_unauthorized_tool_is_denied(search_only):
    token, pk = search_only
    with pytest.raises(TokenError) as exc:
        token.authorize("admin:wipe", pk)
    assert exc.value.error_code() == "scope_insufficient"


@pytest.mark.parametrize(
    "payload",
    [
        AUTHORIZER_PAYLOAD,
        'admin:wipe"); allow if true; //',
        'x"); time(2000-01-01T00:00:00Z); allow if true; //',
        'admin:wipe\ntool("tool:search")',
        'admin:wipe\\"); tool("tool:search"); allow if true; //',
    ],
)
def test_authorizer_injection_is_rejected(search_only, payload):
    """F1: a hostile tool name must never reach the authorizer source."""
    token, pk = search_only
    with pytest.raises(TokenError) as exc:
        token.authorize(payload, pk)
    assert exc.value.error_code() == "token_malformed"


@pytest.mark.parametrize(
    "field,kwargs",
    [
        ("issuer", {"issuer": BLOCK_PAYLOAD}),
        ("scope", {"scopes": ['tool:search"); tool("admin:wipe']}),
        ("principal", {"principal": 'user:a"); tool("admin:wipe'}),
        ("issuer newline", {"issuer": 'aip:web:x\ntool("admin:wipe")'}),
    ],
)
def test_authority_block_injection_is_rejected(field, kwargs):
    """F2: no mint field may inject facts into the signed authority block."""
    base = {
        "issuer": "aip:web:honest.example",
        "scopes": ["tool:search"],
        "budget_cents": 100,
        "max_depth": 1,
        "ttl_seconds": 3600,
        "keypair": KeyPair.generate(),
    }
    with pytest.raises(TokenError) as exc:
        ChainedToken.create_authority(**{**base, **kwargs})
    assert exc.value.error_code() == "token_malformed"


@pytest.mark.parametrize(
    "field,args",
    [
        ("delegator", ('aip:web:a"); tool("x', "aip:key:b", "ctx")),
        ("delegate", ("aip:web:a", 'aip:key:b"); tool("x', "ctx")),
        ("context", ("aip:web:a", "aip:key:b", 'ctx"); tool("admin:wipe"); //')),
    ],
)
def test_delegation_block_injection_is_rejected(search_only, field, args):
    token, _ = search_only
    delegator, delegate, context = args
    with pytest.raises(TokenError) as exc:
        token.delegate(delegator, delegate, ["tool:search"], 50, context)
    assert exc.value.error_code() == "token_malformed"


def test_injected_token_cannot_be_minted_then_used():
    """The end-to-end bypass: mint with a hostile issuer, then authorize anything."""
    kp = KeyPair.generate()
    with pytest.raises(TokenError):
        forged = ChainedToken.create_authority(
            issuer=BLOCK_PAYLOAD,
            scopes=["tool:search"],
            budget_cents=100,
            max_depth=1,
            ttl_seconds=3600,
            keypair=kp,
        )
        # Unreachable once minting rejects the payload. If minting ever stops
        # rejecting it, this asserts the bypass it used to enable.
        forged.authorize("admin:wipe", kp.public_key_bytes())
        pytest.fail("forged token authorized a tool outside its allowlist")


def test_unusual_but_legitimate_values_still_work():
    """Validation must not break identifiers and context that are merely odd.

    Semicolons, parentheses, brackets, commas, `//`, spaces, colons and
    non-ASCII characters are inert inside a quoted Datalog term.
    """
    kp = KeyPair.generate()
    token = ChainedToken.create_authority(
        issuer="aip:web:例え.com/path/to/agent",
        scopes=["tool:search", "fs.*"],
        budget_cents=100,
        max_depth=2,
        ttl_seconds=3600,
        keypair=kp,
        principal="user:a(b), c",
    )
    delegated = token.delegate(
        "aip:web:例え.com/path/to/agent",
        "aip:key:z",
        ["tool:search"],
        50,
        "quarterly report; sub-task (2 of 3) [urgent] // rush",
    )
    delegated.authorize("tool:search", kp.public_key_bytes())
