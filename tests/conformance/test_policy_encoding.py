"""Cross-language conformance for the canonical Simple-profile encoding.

draft-prakash-aip-01 Section 3.4.1 is normative: "Implementations of the Simple
profile MUST emit exactly the forms below." Rust and Python implement that
encoding independently, so the only way to know they agree is to render the same
inputs in both and compare the bytes.

This file exists because they did not agree. Both `SimplePolicy` renderers
emitted `check if budget($b), $b <= N` and `check if depth($d), $d <= N`, which
Section 3.4.1 explicitly forbids, while the chained-token builders in the same
crates correctly emitted `budget_ceiling(N)` and `max_depth(N)` as facts. Unit
tests in each language asserted the forbidden output, so both suites passed.
A cross-language vector is what catches that class of bug.

Expiry is not compared: it is wall-clock dependent and cannot match across two
processes. Its format is pinned by the per-language unit tests instead.
"""

import os
import subprocess
import sys

import pytest

AIP_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUST_DIR = os.path.join(AIP_ROOT, "rust")
sys.path.insert(0, os.path.join(AIP_ROOT, "python"))

from aip_token.policy import SimplePolicy  # noqa: E402

# (tools, budget_cents, max_depth)
VECTORS = [
    ([], None, None),
    (["search"], None, None),
    (["search", "browse"], None, None),
    ([], 100, None),
    ([], None, 3),
    ([], 0, 0),
    (["search"], 100, 3),
    (["fs.read", "net.*"], 250, 5),
    (["*"], None, 1),
    (["a.b.c", "a.b.*", "z"], 999999, 10),
]


def _rust_render(tools, budget_cents, max_depth):
    args = ["cargo", "run", "--quiet", "--bin", "render_policy", "--", "--tools", ",".join(tools)]
    if budget_cents is not None:
        args += ["--budget-cents", str(budget_cents)]
    if max_depth is not None:
        args += ["--max-depth", str(max_depth)]
    proc = subprocess.run(args, cwd=RUST_DIR, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, f"rust render_policy failed: {proc.stderr}"
    return proc.stdout


@pytest.mark.parametrize("tools,budget_cents,max_depth", VECTORS)
def test_rust_and_python_render_identical_datalog(tools, budget_cents, max_depth):
    python_out = SimplePolicy(
        tools=list(tools), budget_cents=budget_cents, max_depth=max_depth
    ).to_datalog()
    rust_out = _rust_render(tools, budget_cents, max_depth)
    assert python_out == rust_out, (
        "canonical encoding drift between implementations\n"
        f"  inputs: tools={tools} budget_cents={budget_cents} max_depth={max_depth}\n"
        f"  python: {python_out!r}\n"
        f"  rust:   {rust_out!r}"
    )


@pytest.mark.parametrize("tools,budget_cents,max_depth", VECTORS)
def test_neither_implementation_emits_a_forbidden_check(tools, budget_cents, max_depth):
    """Section 3.4.1: MUST NOT emit a check statement over budget.

    Depth is a fact for the same reason. Both are verified structurally in V4.
    """
    for label, out in (
        ("python", SimplePolicy(
            tools=list(tools), budget_cents=budget_cents, max_depth=max_depth
        ).to_datalog()),
        ("rust", _rust_render(tools, budget_cents, max_depth)),
    ):
        assert "check if budget" not in out, f"{label} emitted a forbidden budget check"
        assert "check if depth" not in out, f"{label} emitted a forbidden depth check"
