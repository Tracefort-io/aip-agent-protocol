"""Tests for SimplePolicy Datalog generation.

The canonical Simple-profile encoding is normative (draft-prakash-aip-01
Section 3.4.1). These tests pin the mandated forms and, just as importantly,
pin the two forms the draft forbids.
"""

from aip_token.policy import SimplePolicy


def test_simple_tool_allowlist():
    p = SimplePolicy(tools=["search", "browse"])
    dl = p.to_datalog()
    assert 'check if tool($t), ["search", "browse"].contains($t);' in dl


def test_wildcard_scope_uses_starts_with():
    p = SimplePolicy(tools=["fs.read", "net.*"])
    dl = p.to_datalog()
    assert 'tool($t), ["fs.read"].contains($t)' in dl
    assert 'tool($t), $t.starts_with("net.")' in dl
    assert " or " in dl


def test_budget_is_a_fact_not_a_check():
    p = SimplePolicy(budget_cents=50)
    dl = p.to_datalog()
    assert "budget_ceiling(50);" in dl


def test_depth_is_a_fact_not_a_check():
    p = SimplePolicy(max_depth=3)
    dl = p.to_datalog()
    assert "max_depth(3);" in dl


def test_never_emits_a_check_over_budget_or_depth():
    """Section 3.4.1: implementations MUST NOT emit a check over budget.

    A check binds to whatever budget facts are in scope at evaluation rather
    than to this block's ceiling, so it either rejects valid chains or passes
    unconditionally. Depth is a fact for the same reason. Both are verified
    structurally in step V4.
    """
    dl = SimplePolicy(
        tools=["search"], budget_cents=100, max_depth=3, ttl_seconds=3600
    ).to_datalog()
    assert "check if budget" not in dl
    assert "check if depth" not in dl
    assert "budget($b)" not in dl
    assert "depth($d)" not in dl


def test_simple_full_emits_canonical_order():
    dl = SimplePolicy(
        tools=["search"], budget_cents=100, max_depth=3, ttl_seconds=3600
    ).to_datalog()
    assert "max_depth(3);" in dl
    assert "budget_ceiling(100);" in dl
    assert "check if tool($t)" in dl
    assert "check if time($t)" in dl
    # Section 3.4.1 lists facts before checks, and max_depth before
    # budget_ceiling.
    assert dl.index("max_depth(3);") < dl.index("budget_ceiling(100);")
    assert dl.index("budget_ceiling(100);") < dl.index("check if tool($t)")
    assert dl.index("check if tool($t)") < dl.index("check if time($t)")


def test_simple_empty():
    p = SimplePolicy()
    assert p.to_datalog() == ""
