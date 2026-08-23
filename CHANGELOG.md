# Changelog

All notable changes to AIP (Agent Identity Protocol) are documented here.

## [0.4.0] - 2026-08-23

### Security

Two authorization bypasses, both caused by building Biscuit Datalog with string
interpolation. Anyone running 0.3.0 or earlier should upgrade.

- **Authorizer injection in `ChainedToken.authorize()`.** The requested tool name
  was interpolated into the authorizer source. A tool name that closed its own
  string could append an in-allowlist `tool()` fact and `allow if true`, so a
  token granting only `tool:search` authorized any tool. This required no
  malicious token, no forged signature and no control of the issuer, only
  influence over the tool name being checked. In an MCP binding that name comes
  straight from the agent's JSON-RPC `params.name`. The tool is now validated and
  bound as a Datalog parameter rather than interpolated.
- **Block-encoder injection in `create_authority()` and `delegate()`.** The
  issuer, principal, scope, delegator, delegate and context values were
  interpolated into block Datalog, so a breakout in any of them injected facts
  into a block that was then signed. An injected `tool()` fact satisfied the
  authority block's own scope check for any tool, an injected `time()` fact
  defeated expiry, and an injected `max_depth()` ahead of the real one was what
  the depth check read. All six fields are now validated at the API boundary.

`aip_token.canonical.validate_term()` rejects the double quote, the backslash and
control characters, which are the only characters that can escape a Datalog
string context. Semicolons, parentheses, brackets, commas, `//`, spaces, colons
and non-ASCII characters remain valid, so ordinary identifiers and free-form
context strings are unaffected.

### Fixed

- `SimplePolicy.to_datalog()` emitted `check if budget($b), $b <= N` and
  `check if depth($d), $d <= N` in both the Python and Rust SDKs. Section 3.4.1
  of draft-prakash-aip-01 requires these as the facts `budget_ceiling(N)` and
  `max_depth(N)`, and states that implementations MUST NOT emit a check over
  budget: such a check binds to whatever budget facts are in scope at evaluation
  rather than to the block's own ceiling, so it either rejects valid chains or
  passes unconditionally. Both dimensions are verified structurally in step V4.
  The chained-token builders were already correct; only `SimplePolicy` was wrong.

### Changed

- The canonical Section 3.4.1 encoding now lives in one module per language
  (`aip_token.canonical`, `aip_token::canonical`). It had been implemented twice
  in each SDK, which is how `SimplePolicy` drifted from the chained builder.
- New cross-language conformance vectors compare the Rust and Python renderings
  byte for byte, and both SDKs now carry regression tests for the two bypasses.

### Breaking

- `SimplePolicy.to_datalog()` output has changed. It now emits the canonical
  Section 3.4.1 form. Callers embedding the old output in their own Datalog
  should re-render.
- Identifiers, scopes and context strings containing a double quote, a backslash
  or control characters are now rejected with `token_malformed`.

## [0.3.0] - 2026-05-08

### Added
- New `aip_a2a` module: AIP binding for the Agent-to-Agent (A2A) protocol.
  - `verify_a2a_task()` — verify chained tokens carried in A2A task `metadata.aip_token`
  - `append_delegation_block()` — extend a chain before forwarding a task
  - `A2AVerifyMiddleware` — framework-agnostic wrapper for A2A task handlers
  - `parse_aip_identity()` — extract and validate the `aip_identity` extension from agent cards
  - A2A-specific error types: `AudienceError`, `ScopeError`, `ChainError`, `ExpiryError`, `DepthError`
- Rendered specification at https://sunilprakash.com/aip/spec/.
- Interactive protocol page at https://sunilprakash.com/aip/paper/ (verification flow, chain viewer, attack simulator).

### Changed
- `agent-identity-protocol` package now ships four sub-packages: `aip_core`, `aip_token`, `aip_mcp`, `aip_a2a`.
- `ChainedToken.authorize()` now correctly handles delegated tokens with budget constraints (was previously failing on any chained token with `budget_cents` set on a delegation block) and explicitly enforces scope attenuation across delegation hops.

### Notes
- No breaking changes. All `aip_core`, `aip_token`, `aip_mcp` imports continue to work unchanged.

## [0.2.0] - 2026-04-13

### Added
- `aip-proxy` CLI: drop-in MCP authentication proxy that wraps any MCP server with AIP token verification
- `aip_mcp.audit` module: security self-audit for compact and chained tokens (token hygiene, scope safety, budget limits, chain integrity)
- `aip_mcp.config` module: TOML-based proxy configuration
- `aip_mcp.proxy` module: HTTP proxy server for MCP transports
- `__version__` attribute in `aip_core`
- Project hub site at sunilprakash.com/aip/ with quickstart tutorial, security model, and framework guides

### Changed
- README rewritten: problem-first structure with framework quickstart examples
- Added sitemap.xml for site SEO

## [0.1.1] - 2026-03-28

### Added
- LangChain adapter in `aip-agents`
- SECURITY.md with vulnerability reporting guidelines
- PyPI keywords and classifiers for discoverability

## [0.1.0] - 2026-03-27

### Added
- Core SDK: `aip_core` with Ed25519 key pairs, AIP identifiers (`aip:web:`, `aip:key:`), identity documents
- Compact token mode: `aip_token` with JWT+EdDSA invocation-bound capability tokens (IBCTs)
- MCP middleware: `aip_mcp` with token extraction, mode detection, request verification
- `aip-agents` package with CrewAI and Google ADK adapters
- Cross-language interop tests (Rust <-> Python)
- 63 tests passing
