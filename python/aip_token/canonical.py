"""Canonical Simple-profile block encoding (draft-prakash-aip-01 Section 3.4.1).

Every caller that renders AIP Datalog goes through this module. The encoding is
normative: Section 3.4.1 requires implementations of the Simple profile to emit
exactly these forms, and two independent renderings of the same intent drift
into tokens that no other implementation can verify.

Two rules from Section 3.4.1 are easy to get wrong and are enforced here by
construction:

*   Depth and budget are carried as FACTS, never as checks. A check of the form
    ``check if budget($b), $b <= N`` binds to whatever budget facts are in scope
    during evaluation, which is a different question from whether this block's
    ceiling narrows its parent's. Encoding either as a check therefore rejects
    valid chains, or passes unconditionally when the verifier supplies a
    satisfying ambient fact. Both are verified structurally in step V4 instead.

*   A block's scope constraint is ONE self-contained check. A rule-based
    encoding does not attenuate, because a delegation block's narrower rule is
    unioned with an ancestor's broader rule of the same name rather than
    replacing it, and the broader one then satisfies the delegation's own check.

This module deliberately has no dependency on ``biscuit_auth`` so that callers
needing only the Datalog text do not pull in the optional extra.
"""

from __future__ import annotations

from datetime import datetime

from aip_token.error import TokenError

_STR_FACT = '{name}("{value}");\n'

_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

#: Characters that let a value escape the Datalog string context it is written
#: into. A double quote closes the string outright. A backslash reprints as an
#: escape sequence that this implementation's block parsers do not decode. A
#: control character (newline included) splits one fact across lines, which the
#: line-oriented parsers in the attenuation walk then read as two facts.
#:
#: Nothing else needs excluding. Semicolons, parentheses, brackets, commas,
#: ``//``, spaces, colons and non-ASCII characters are all inert inside a
#: quoted term and round-trip unambiguously, so identifiers and free-form
#: context strings keep working.
_FORBIDDEN_CHARS = frozenset('"\\')


def validate_term(value: str, field: str) -> str:
    """Reject a string that could escape the Datalog string context.

    AIP block and authorizer sources are Datalog text. A value carrying a
    double quote can close its own term and append arbitrary facts, checks or
    policies to a block that is then signed, or to the authorizer that decides
    a request. Both are authorization bypasses, so this is enforced at every
    boundary where a caller-supplied string becomes Datalog rather than left to
    the caller.
    """
    if not isinstance(value, str):
        raise TokenError(f"{field} must be a string", "token_malformed")
    for char in value:
        if char in _FORBIDDEN_CHARS or ord(char) < 0x20 or ord(char) == 0x7F:
            raise TokenError(
                f"{field} contains a character that is not permitted in an AIP "
                f"Datalog term: {char!r}",
                "token_malformed",
            )
    return value


def str_fact(name: str, value: str) -> str:
    """Render a string-valued fact, e.g. ``identity("aip:web:example.com");``."""
    validate_term(value, name)
    return _STR_FACT.format(name=name, value=value)


def int_fact(name: str, value: int) -> str:
    """Render an integer-valued fact, e.g. ``max_depth(3);``."""
    return f"{name}({value});\n"


def scope_list(scopes: list[str]) -> str:
    """Render a scope allowlist as a Datalog set literal."""
    return ", ".join(f'"{s}"' for s in scopes)


def tool_check(scopes: list[str]) -> str:
    """Render a block's scope constraint as one self-contained check.

    An all-exact scope set produces the Simple profile form (spec/aip-tokens.md
    section 7.1). A set containing a wildcard produces the Standard profile
    form (section 7.2), where patterns become ``starts_with`` clauses joined to
    the exact-match clause with ``or``.
    """
    for scope in scopes:
        validate_term(scope, "scope")

    exact = [s for s in scopes if not s.endswith("*")]
    wildcards = [s for s in scopes if s.endswith("*")]

    clauses = []
    if exact:
        clauses.append(f"tool($t), [{scope_list(exact)}].contains($t)")
    for pattern in wildcards:
        prefix = pattern[:-1]
        if prefix:
            clauses.append(f'tool($t), $t.starts_with("{prefix}")')
        else:
            clauses.append("tool($t)")

    if not clauses:
        return ""
    return "check if " + " or ".join(clauses) + ";\n"


def time_check(expiry: datetime) -> str:
    """Render a block's expiry constraint."""
    return f"check if time($t), $t <= {expiry.strftime(_TIME_FORMAT)};\n"
