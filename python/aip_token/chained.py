"""ChainedToken: Biscuit-backed delegation tokens for AIP.

Bridges AIP's Ed25519 key pairs with biscuit-python to provide
cryptographically attenuated delegation chains.

Block layout follows the canonical encoding in draft-prakash-aip-01
Section 3.4.1, and verification follows the algorithm in Section 4. Both are
normative: an implementation that encodes the same intent differently produces
tokens no other implementation can verify.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from biscuit_auth import (
    AuthorizerBuilder,
    Biscuit,
    BiscuitBuilder,
    BlockBuilder,
    Fact,
    Policy,
    PrivateKey as BiscuitPrivateKey,
    PublicKey as BiscuitPublicKey,
    Rule,
)

from aip_core.crypto import KeyPair
from aip_token.canonical import (
    int_fact,
    str_fact,
    time_check,
    tool_check,
    validate_term,
)
from aip_token.error import TokenError

# biscuit-python >= 0.4 requires an Algorithm argument for from_bytes();
# older versions do not.  Detect at import time.
try:
    from biscuit_auth import Algorithm as _Algorithm
    _ED25519 = _Algorithm.Ed25519
except ImportError:
    _ED25519 = None  # type: ignore[assignment]


def _biscuit_private_key(keypair: KeyPair) -> BiscuitPrivateKey:
    """Convert an AIP KeyPair's private key to a biscuit PrivateKey."""
    raw = keypair.private_key_bytes()
    if _ED25519 is not None:
        return BiscuitPrivateKey.from_bytes(raw, _ED25519)
    return BiscuitPrivateKey.from_bytes(raw)  # type: ignore[call-arg]


def _biscuit_public_key(raw_bytes: bytes) -> BiscuitPublicKey:
    """Convert raw 32-byte public key bytes to a biscuit PublicKey."""
    if _ED25519 is not None:
        return BiscuitPublicKey.from_bytes(raw_bytes, _ED25519)
    return BiscuitPublicKey.from_bytes(raw_bytes)  # type: ignore[call-arg]



# Canonical block encoding lives in aip_token.canonical so that the chained
# builder and the standalone SimplePolicy renderer cannot drift apart.


def _covers(pattern: str, scope: str) -> bool:
    """Does a parent scope pattern permit a child scope?

    A wildcard in the parent permits any specific value in the child. A
    specific value in the parent never widens to a wildcard in the child.
    """
    if pattern == scope:
        return True
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return scope.startswith(pattern[:-1])
    return False


def _parse_scopes(source: str) -> set[str] | None:
    """Extract a block's scope patterns from its tool check.

    The check statement is the authoritative declaration, because it is what
    constrains authorization. `right` facts are descriptive metadata and are
    deliberately not trusted here: a block carrying a permissive check and no
    matching facts would otherwise read as declaring nothing.

    Returns None when the block has no tool check, meaning it does not
    constrain scope and inherits its parent's allowlist.
    """
    match = re.search(r"^check if (.*?);\s*$", source, re.M | re.S)
    if not match or "tool($t)" not in match.group(1):
        return None

    scopes: set[str] = set()
    for clause in match.group(1).split(" or "):
        clause = clause.strip()
        if clause == "tool($t)":
            scopes.add("*")
            continue
        contains = re.search(r"\[(.*?)\]\.contains\(\$t\)", clause, re.S)
        if contains:
            scopes.update(re.findall(r'"([^"]*)"', contains.group(1)))
        for prefix in re.findall(r'\$t\.starts_with\("([^"]*)"\)', clause):
            scopes.add(f"{prefix}*")
    return scopes or None


def _parse_int_fact(source: str, name: str) -> int | None:
    match = re.search(rf"^{name}\((-?\d+)\);", source, re.M)
    return int(match.group(1)) if match else None


def _parse_str_fact(source: str, name: str) -> str | None:
    match = re.search(rf'^{name}\("([^"]*)"\);', source, re.M)
    return match.group(1) if match else None


class ChainedToken:
    """A Biscuit-based chained delegation token.

    Supports creating authority tokens, delegating with attenuation, and
    verifying a chain end to end.
    """

    def __init__(
        self,
        biscuit: Biscuit,
        issuer: str,
        max_depth: int,
        root_pubkey_bytes: bytes,
        depth: int = 0,
    ) -> None:
        self._biscuit = biscuit
        self._issuer = issuer
        self._max_depth = max_depth
        self._root_pubkey_bytes = root_pubkey_bytes
        self._depth = depth

    # -- accessors ---------------------------------------------------------

    def issuer(self) -> str:
        return self._issuer

    def max_depth(self) -> int:
        return self._max_depth

    def current_depth(self) -> int:
        return self._depth

    def block_count(self) -> int:
        return self._biscuit.block_count()

    def block_source(self, index: int) -> str:
        """Datalog source of one block. Only meaningful after signature verification."""
        return self._biscuit.block_source(index) or ""

    def to_base64(self) -> str:
        return self._biscuit.to_base64()

    # -- minting -----------------------------------------------------------

    @staticmethod
    def create_authority(
        issuer: str,
        scopes: list[str],
        budget_cents: int | None,
        max_depth: int,
        ttl_seconds: int,
        keypair: KeyPair,
        principal: str | None = None,
    ) -> ChainedToken:
        """Create a new authority (root) token."""
        if budget_cents is not None and budget_cents < 0:
            raise TokenError("budget ceiling must be non-negative", "budget_exceeded")

        expiry = datetime.now(tz=timezone.utc) + timedelta(seconds=ttl_seconds)

        facts = str_fact("identity", issuer)
        if principal is not None:
            facts += str_fact("principal", principal)
        for scope in scopes:
            facts += str_fact("right", scope)
        facts += int_fact("max_depth", max_depth)
        if budget_cents is not None:
            facts += int_fact("budget_ceiling", budget_cents)
        if scopes:
            facts += tool_check(scopes)
        facts += time_check(expiry)

        biscuit = BiscuitBuilder(facts).build(_biscuit_private_key(keypair))
        return ChainedToken(biscuit, issuer, max_depth, keypair.public_key_bytes(), depth=0)

    def delegate(
        self,
        delegator: str,
        delegate: str,
        scopes: list[str],
        budget_cents: int | None,
        context: str,
        principal: str | None = None,
    ) -> ChainedToken:
        """Append an attenuated delegation block.

        Attenuation is checked here at mint time as a convenience to the
        delegator. It is checked again at verification, because an attacker
        appending a block does not run this code.
        """
        if not context or not context.strip():
            raise TokenError("Context must be non-empty", "token_malformed")

        if self._depth >= self._max_depth:
            raise TokenError("Delegation depth exceeded", "depth_exceeded")

        parent_scopes = self._effective_scopes()
        if parent_scopes is not None:
            widened = [
                s for s in scopes if not any(_covers(p, s) for p in parent_scopes)
            ]
            if widened:
                raise TokenError(
                    f"delegation would widen scope: {', '.join(sorted(widened))}",
                    "scope_insufficient",
                )

        if budget_cents is not None:
            if budget_cents < 0:
                raise TokenError("budget ceiling must be non-negative", "budget_exceeded")
            parent_budget = self._effective_budget()
            if parent_budget is not None and budget_cents > parent_budget:
                raise TokenError(
                    f"delegation would raise budget ceiling from {parent_budget} "
                    f"to {budget_cents}",
                    "budget_exceeded",
                )

        block = str_fact("delegator", delegator)
        block += str_fact("delegate", delegate)
        block += str_fact("context", context)
        if principal is not None:
            block += str_fact("principal", principal)
        if budget_cents is not None:
            block += int_fact("budget_ceiling", budget_cents)
        if scopes:
            block += tool_check(scopes)

        new_biscuit = self._biscuit.append(BlockBuilder(block))
        return ChainedToken(
            new_biscuit,
            self._issuer,
            self._max_depth,
            self._root_pubkey_bytes,
            depth=self._depth + 1,
        )

    # -- verification (draft-prakash-aip-01 Section 4) ---------------------

    def verify_chain(self, root_public_key_bytes: bytes) -> Biscuit:
        """Verify the chain without evaluating a tool-specific policy.

        Runs V1 (chain integrity), V3 (depth), V4 (structural attenuation
        walk) and V5 (delegation context), and returns the verified Biscuit so
        a caller can run V6 against it.

        This exists for relying parties that must establish what a chain
        conveys on a request that names no tool. An MCP proxy sees
        `initialize` and `tools/list` as well as `tools/call`, and skipping
        verification on those because there is no tool to check would leave
        depth, attenuation and context unenforced for the whole session.

        V2 (root binding) is the caller's responsibility: it supplies the root
        key it resolved for the issuer this chain declares, and MUST confirm
        that the key belongs to that issuer. V7 (revocation) is handled by the
        transport binding.
        """
        # V1: re-verify every block signature from the serialized form. Nothing
        # below may read block content before this succeeds.
        verified = Biscuit.from_base64(
            self._biscuit.to_base64(), _biscuit_public_key(root_public_key_bytes)
        )

        # V3: depth
        declared_depth = _parse_int_fact(self.block_source(0), "max_depth")
        if declared_depth is not None and self.block_count() - 1 > declared_depth:
            raise TokenError("Delegation depth exceeded", "depth_exceeded")

        # V4 and V5
        self._attenuation_walk()

        return verified

    def authorize(self, tool: str, root_public_key_bytes: bytes) -> None:
        """Verify the chain and authorize one tool invocation.

        Runs V1, V3, V4, V5 via :meth:`verify_chain`, then V6 (policy
        evaluation) for the named tool.
        """
        verified = self.verify_chain(root_public_key_bytes)

        # V6: policy evaluation. Ambient facts are tool, time and depth only.
        # Supplying a budget fact here would make any budget check evaluate
        # against verifier-chosen data; budget is handled in V4.
        #
        # The requested tool is the one input to this step that the caller
        # controls, and in an MCP binding it arrives straight from the agent's
        # JSON-RPC params. It is validated and then bound as a Datalog
        # parameter, never interpolated into the source: a tool name that
        # closed its own string could append `allow if true` to this very
        # authorizer and pass any check the token carries.
        validate_term(tool, "tool")

        now = datetime.now(tz=timezone.utc)
        try:
            builder = AuthorizerBuilder(
                f'time({now.strftime("%Y-%m-%dT%H:%M:%SZ")});\n'
                f"depth({self._depth});\n"
            )
            builder.add_fact(Fact("tool({t})", {"t": tool}))
            builder.add_policy(Policy("allow if tool({t})", {"t": tool}))
            builder.build(verified).authorize()
        except TokenError:
            raise
        except Exception as exc:
            raise TokenError(f"insufficient scope: {exc}", "scope_insufficient") from exc

    def _attenuation_walk(self) -> None:
        """V4: confirm every hop narrows its parent. V5: context is present."""
        sources = [self.block_source(i) for i in range(self.block_count())]

        scopes = _parse_scopes(sources[0])
        budget = _parse_int_fact(sources[0], "budget_ceiling")
        principal = _parse_str_fact(sources[0], "principal")

        if budget is not None and budget < 0:
            raise TokenError("budget ceiling must be non-negative", "budget_exceeded")

        for index, source in enumerate(sources[1:], start=1):
            # V5: every delegation block carries a non-empty context.
            context = _parse_str_fact(source, "context")
            if not context or not context.strip():
                raise TokenError(
                    f"delegation block {index} has no context", "token_malformed"
                )

            block_scopes = _parse_scopes(source)
            if block_scopes is not None:
                if scopes is not None:
                    widened = [
                        s for s in block_scopes if not any(_covers(p, s) for p in scopes)
                    ]
                    if widened:
                        raise TokenError(
                            f"delegation block {index} widens scope: "
                            f"{', '.join(sorted(widened))}",
                            "scope_insufficient",
                        )
                scopes = block_scopes

            block_budget = _parse_int_fact(source, "budget_ceiling")
            if block_budget is not None:
                if block_budget < 0:
                    raise TokenError(
                        f"delegation block {index} has a negative budget ceiling",
                        "budget_exceeded",
                    )
                if budget is not None and block_budget > budget:
                    raise TokenError(
                        f"delegation block {index} raises the budget ceiling from "
                        f"{budget} to {block_budget}",
                        "budget_exceeded",
                    )
                budget = block_budget

            block_principal = _parse_str_fact(source, "principal")
            if block_principal is not None:
                if principal is not None and block_principal != principal:
                    raise TokenError(
                        f"delegation block {index} substitutes the principal: "
                        f"{principal} became {block_principal}",
                        "token_malformed",
                    )
                principal = block_principal

    def _effective_scopes(self) -> set[str] | None:
        """The most recent allowlist declared in the chain, or None if unconstrained.

        The last declaration is the narrowest: every block that declares scopes
        was checked against its parent when it was appended and again in the
        attenuation walk, so a later declaration can only be a subset.
        """
        scopes = None
        for i in range(self.block_count()):
            block_scopes = _parse_scopes(self.block_source(i))
            if block_scopes is not None:
                scopes = block_scopes
        return scopes

    def _effective_budget(self) -> int | None:
        """The lowest ceiling declared so far, or None if none is declared."""
        budget = None
        for i in range(self.block_count()):
            block_budget = _parse_int_fact(self.block_source(i), "budget_ceiling")
            if block_budget is not None:
                budget = block_budget if budget is None else min(budget, block_budget)
        return budget

    # -- deserialization ---------------------------------------------------

    @staticmethod
    def from_base64(s: str, root_public_key_bytes: bytes) -> ChainedToken:
        """Deserialize and verify a token against the root public key (V1)."""
        biscuit = Biscuit.from_base64(s, _biscuit_public_key(root_public_key_bytes))
        source = biscuit.block_source(0) or ""
        issuer = _parse_str_fact(source, "identity") or "unknown"
        max_depth = _parse_int_fact(source, "max_depth")
        return ChainedToken(
            biscuit,
            issuer,
            max_depth if max_depth is not None else 3,
            root_public_key_bytes,
            depth=biscuit.block_count() - 1,
        )
