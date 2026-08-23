"""The proxy must run the verification algorithm, not just check signatures.

`aip_mcp/proxy.py` used to call `ChainedToken.from_base64` (V1) and then an
audit function whose `errors` list nothing ever wrote to, so `passed` was
unconditionally True. Steps V2 through V7 never ran. A chain with a raised
budget ceiling, an expired time check, an empty delegation context, or depth
past `max_depth` was forwarded as verified so long as its signatures chained,
by a component documented as "drop-in authentication for any MCP server".

It also tried each configured trust key until one verified and then trusted the
token's self-declared identity, so with two trusted issuers a token signed by
one could claim the identity of the other.

These tests pin the enforcement. They drive the real proxy over HTTP against a
real upstream, because the bug was that the wiring never reached the checks,
which a unit test of the checks themselves would not have caught.
"""

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

import httpx
import pytest

from aip_core.crypto import KeyPair
from aip_mcp.config import ProxyConfig
from aip_mcp.proxy import AipProxy

biscuit = pytest.importorskip("biscuit_auth", reason="biscuit-python not installed")

from aip_token.chained import ChainedToken  # noqa: E402


class EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        payload = json.dumps({"forwarded": True, "body": body.decode()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def upstream():
    server = HTTPServer(("127.0.0.1", 0), EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(scope="module")
def issuer_key():
    return KeyPair.generate()


ISSUER = "aip:web:honest.example"


@pytest.fixture()
def proxy(upstream, issuer_key):
    config = ProxyConfig(
        upstream=upstream,
        port=0,
        host="127.0.0.1",
        trust_keys={ISSUER: issuer_key.public_key_multibase()},
    )
    server = AipProxy(config)
    server.start()
    yield server
    server.stop()


def tools_call(name, **arguments):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def post(proxy, token, body, path="/mcp"):
    return httpx.post(
        f"http://127.0.0.1:{proxy.port}{path}",
        headers={"X-AIP-Token": token},
        json=body,
        timeout=10.0,
    )


def authority(issuer_key, scopes=("tool:search",), issuer=ISSUER, ttl=3600, depth=2):
    return ChainedToken.create_authority(
        issuer=issuer,
        scopes=list(scopes),
        budget_cents=100,
        max_depth=depth,
        ttl_seconds=ttl,
        keypair=issuer_key,
    )


class TestScopeEnforcement:
    def test_in_scope_tool_is_forwarded(self, proxy, issuer_key):
        token = authority(issuer_key).to_base64()
        resp = post(proxy, token, tools_call("search", q="x"))
        assert resp.status_code == 200
        assert resp.json()["forwarded"] is True

    def test_out_of_scope_tool_is_denied_with_403(self, proxy, issuer_key):
        """The core bug: this used to be forwarded as verified."""
        token = authority(issuer_key).to_base64()
        resp = post(proxy, token, tools_call("delete_everything"))
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "aip_scope_insufficient"

    def test_delegated_token_cannot_exceed_its_grant(self, proxy, issuer_key):
        root = authority(issuer_key, scopes=("tool:search", "tool:read"))
        narrowed = root.delegate(
            ISSUER, "aip:key:worker", ["tool:search"], 50, "sub-task"
        ).to_base64()

        assert post(proxy, narrowed, tools_call("search")).status_code == 200

        resp = post(proxy, narrowed, tools_call("read"))
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "aip_scope_insufficient"


class TestExpiryEnforcement:
    def test_expired_chain_is_denied(self, proxy, issuer_key):
        token = authority(issuer_key, ttl=-10).to_base64()
        resp = post(proxy, token, tools_call("search"))
        assert resp.status_code in (401, 403)
        assert resp.json()["error"]["code"] != "aip_token_missing"


class TestRootBinding:
    def test_token_cannot_claim_another_trusted_issuers_identity(self, upstream):
        """V2: two trusted issuers, one signs a token claiming the other's name."""
        alice_key, bob_key = KeyPair.generate(), KeyPair.generate()
        config = ProxyConfig(
            upstream=upstream,
            port=0,
            host="127.0.0.1",
            trust_keys={
                "aip:web:alice.example": alice_key.public_key_multibase(),
                "aip:web:bob.example": bob_key.public_key_multibase(),
            },
        )
        server = AipProxy(config)
        server.start()
        try:
            # Bob's key signs a token that declares Alice as the issuer.
            impostor = ChainedToken.create_authority(
                issuer="aip:web:alice.example",
                scopes=["tool:search"],
                budget_cents=100,
                max_depth=1,
                ttl_seconds=3600,
                keypair=bob_key,
            ).to_base64()

            resp = post(server, impostor, tools_call("search"))
            assert resp.status_code == 401
            assert resp.json()["error"]["code"] == "aip_identity_unresolvable"

            # Bob under his own name still works.
            honest = ChainedToken.create_authority(
                issuer="aip:web:bob.example",
                scopes=["tool:search"],
                budget_cents=100,
                max_depth=1,
                ttl_seconds=3600,
                keypair=bob_key,
            ).to_base64()
            assert post(server, honest, tools_call("search")).status_code == 200
        finally:
            server.stop()

    def test_multiple_unbound_keys_are_refused_at_startup(self, upstream):
        """A bare list of keys cannot support V2, so it must not be served."""
        config = ProxyConfig(
            upstream=upstream,
            port=0,
            host="127.0.0.1",
            trust_keys=[
                KeyPair.generate().public_key_multibase(),
                KeyPair.generate().public_key_multibase(),
            ],
        )
        with pytest.raises(ValueError, match="cannot be bound to issuers"):
            AipProxy(config)


class TestNonToolRequests:
    def test_request_naming_no_tool_still_has_its_chain_verified(
        self, proxy, issuer_key
    ):
        """`initialize` names no tool, but V1 through V5 must still run."""
        token = authority(issuer_key).to_base64()
        resp = post(proxy, token, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert resp.status_code == 200

    def test_request_naming_no_tool_still_rejects_a_bad_signature(
        self, proxy, issuer_key
    ):
        stranger = ChainedToken.create_authority(
            issuer=ISSUER,
            scopes=["tool:search"],
            budget_cents=100,
            max_depth=1,
            ttl_seconds=3600,
            keypair=KeyPair.generate(),
        ).to_base64()
        resp = post(proxy, stranger, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert resp.status_code == 401

    def test_batch_invoking_several_tools_is_refused(self, proxy, issuer_key):
        """One policy evaluation cannot authorize two different tools."""
        token = authority(issuer_key, scopes=("tool:search", "tool:read")).to_base64()
        resp = post(proxy, token, [tools_call("search"), tools_call("read")])
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "aip_scope_insufficient"


class TestAuditIsARealGate:
    def test_audit_can_fail_on_a_configured_limit(self, upstream, issuer_key):
        """`audit_chained` previously never populated `errors`, so it never failed."""
        config = ProxyConfig(
            upstream=upstream,
            port=0,
            host="127.0.0.1",
            trust_keys={ISSUER: issuer_key.public_key_multibase()},
            max_depth=1,
        )
        server = AipProxy(config)
        server.start()
        try:
            token = authority(issuer_key, depth=9).to_base64()
            resp = post(server, token, tools_call("search"))
            assert resp.status_code == 403
            assert resp.json()["error"]["code"] == "aip_audit_failed"
        finally:
            server.stop()
