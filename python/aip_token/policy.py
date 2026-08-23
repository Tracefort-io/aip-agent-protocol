"""Simple policy profiles for Biscuit-based AIP tokens."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from aip_token.canonical import int_fact, time_check, tool_check


@dataclass
class SimplePolicy:
    """A Simple-profile policy rendered as canonical AIP Datalog.

    Emits the forms mandated by draft-prakash-aip-01 Section 3.4.1, in the
    order given there: ``max_depth`` and ``budget_ceiling`` as facts, followed
    by the self-contained tool check and the expiry check.

    Depth and budget are facts, not checks. Section 3.4.1 states that
    implementations MUST NOT emit a check statement over budget, because such a
    check binds to whatever budget facts are in scope at evaluation rather than
    to this block's ceiling. Both dimensions are verified structurally in step
    V4 of Section 4 instead. See :mod:`aip_token.canonical`.

    Budget is expressed in integer cents (Biscuit has no float support).
    """

    tools: list[str] = field(default_factory=list)
    budget_cents: int | None = None
    max_depth: int | None = None
    ttl_seconds: int | None = None

    def to_datalog(self) -> str:
        parts: list[str] = []
        if self.max_depth is not None:
            parts.append(int_fact("max_depth", self.max_depth))
        if self.budget_cents is not None:
            parts.append(int_fact("budget_ceiling", self.budget_cents))
        if self.tools:
            parts.append(tool_check(self.tools))
        if self.ttl_seconds is not None:
            expiry = datetime.now(tz=timezone.utc) + timedelta(seconds=self.ttl_seconds)
            parts.append(time_check(expiry))
        return "".join(parts)
