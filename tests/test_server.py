"""End-to-end tests for the GymSuit MCP server.

Runs the stub GymSuit API on a real local port and drives the MCP
server (OAuth + Streamable HTTP) through HTTP, the way a client would.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import threading
import time
from urllib.parse import parse_qs, urlparse

import pytest
import uvicorn
from starlette.testclient import TestClient

from stub_gymsuit import StubState, create_stub_app

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from gymsuit_mcp.app import create_app
from gymsuit_mcp.config import Settings

VERIFIER = "testverifier-0123456789-abcdefghij-0123456789"
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")
EMAIL = "athul.6560@gmail.com"
REDIRECT_URI = "http://127.0.0.1:9999/callback"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def stub():
    state = StubState()
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(create_stub_app(state), host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    yield state, f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture()
def app_client(stub, tmp_path):
    _, stub_base = stub
    settings = Settings(
        public_url="http://127.0.0.1:8000",
        gymsuit_api_base=stub_base,
        secret_key="test-secret-key-for-tests-only-0123456789",
        database_path=str(tmp_path / "test.db"),
    )
    with TestClient(create_app(settings)) as client:
        yield client


def _register(client) -> str:
    resp = client.post(
        "/oauth/register",
        json={"redirect_uris": [REDIRECT_URI], "client_name": "test-client"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["client_id"]


def _authorize_url(client_id: str) -> str:
    return (
        "/oauth/authorize?response_type=code"
        f"&client_id={client_id}&redirect_uri={REDIRECT_URI}"
        "&scope=food%3Aread+food%3Awrite&state=xyz"
        f"&code_challenge={CHALLENGE}&code_challenge_method=S256"
    )


def _full_login(client, client_id: str) -> str:
    """Run the browser login flow; return the authorization code."""
    resp = client.get(_authorize_url(client_id))
    assert resp.status_code == 200, resp.text
    assert "Sign in to GymSuit" in resp.text
    resp = client.post("/oauth/authorize/email", data={"email": EMAIL})
    assert resp.status_code == 200, resp.text
    assert "6-digit code" in resp.text
    resp = client.post("/oauth/authorize/otp", data={"otp": "123456"})
    assert resp.status_code == 200, resp.text
    assert "Allow this assistant?" in resp.text
    resp = client.post("/oauth/authorize/consent", data={"approve": "yes"}, follow_redirects=False)
    assert resp.status_code == 302, resp.text
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["state"] == ["xyz"]
    return query["code"][0]


def test_metadata(app_client):
    resp = app_client.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    assert resp.json() == {
        "resource": "http://127.0.0.1:8000/mcp",
        "authorization_servers": ["http://127.0.0.1:8000"],
    }
    resp = app_client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    meta = resp.json()
    assert meta["issuer"] == "http://127.0.0.1:8000"
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert "food:write" in meta["scopes_supported"]


def test_authorize_rejects_unknown_client(app_client):
    resp = app_client.get("/oauth/authorize?response_type=code&client_id=nope")
    assert resp.status_code == 400


def _get_tokens(client) -> dict:
    """Register + log in + exchange the code; return the token response."""
    client_id = _register(client)
    code = _full_login(client, client_id)
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": VERIFIER,
        },
    )
    assert resp.status_code == 200, resp.text
    tokens = resp.json()
    assert tokens["token_type"] == "Bearer"
    assert tokens["expires_in"] == 3600
    return tokens, client_id, code


def test_full_oauth_flow_and_refresh_rotation(app_client, stub):
    state, _ = stub
    tokens, client_id, code = _get_tokens(app_client)
    assert state.otp_sent_to == [EMAIL]

    # A used code is dead.
    resp = app_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": VERIFIER,
        },
    )
    assert resp.status_code == 400

    # Refresh rotates: new pair, old refresh token rejected after.
    resp = app_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": client_id,
        },
    )
    assert resp.status_code == 200, resp.text
    new_tokens = resp.json()
    assert new_tokens["access_token"] != tokens["access_token"]
    resp = app_client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": client_id,
        },
    )
    assert resp.status_code == 400


def _parse_mcp(resp):
    """Streamable HTTP answers JSON-RPC as JSON or as an SSE data: frame."""
    ctype = resp.headers.get("content-type", "")
    if "text/event-stream" in ctype:
        datas = [line[5:].strip() for line in resp.text.splitlines() if line.startswith("data:")]
        assert datas, f"no SSE data in response: {resp.text[:500]!r}"
        return json.loads(datas[-1])
    return resp.json()


def _mcp_call(client, access_token: str, session_id: str | None, method: str, params: dict, msg_id: int):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if session_id:
        headers["mcp-session-id"] = session_id
    return client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params},
    )


def test_mcp_tools_end_to_end(app_client, stub):
    state, stub_base = stub
    tokens, _, _ = _get_tokens(app_client)
    access = tokens["access_token"]

    # No token -> 401 with resource metadata pointer.
    resp = app_client.post(
        "/mcp",
        headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
        json={"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}},
    )
    assert resp.status_code == 401
    assert "oauth-protected-resource" in resp.headers["www-authenticate"]

    # Initialize a streamable-HTTP session.
    resp = _mcp_call(
        app_client,
        access,
        None,
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
        1,
    )
    assert resp.status_code == 200, resp.text
    session_id = resp.headers.get("mcp-session-id")
    assert session_id
    init = _parse_mcp(resp)
    assert init["result"]["serverInfo"]["name"] == "GymSuit"

    _mcp_call(app_client, access, session_id, "notifications/initialized", {}, 2)

    resp = _mcp_call(app_client, access, session_id, "tools/list", {}, 3)
    assert resp.status_code == 200, resp.text
    names = [t["name"] for t in _parse_mcp(resp)["result"]["tools"]]
    assert {"log_food", "get_eating_score", "delete_food_entry", "whoami"} <= set(names)

    resp = _mcp_call(
        app_client,
        access,
        session_id,
        "tools/call",
        {
            "name": "whoami",
            "arguments": {},
        },
        4,
    )
    assert resp.status_code == 200, resp.text
    who = json.loads(_parse_mcp(resp)["result"]["content"][0]["text"])
    assert who["email"] == EMAIL
    assert who["member_id"] == 9

    resp = _mcp_call(
        app_client,
        access,
        session_id,
        "tools/call",
        {
            "name": "log_food",
            "arguments": {
                "meal": "LUNCH",
                "dish_name": "rice + chicken curry",
                "calories": 450,
                "protein_g": 35.0,
                "carbs_g": 45.0,
                "fat_g": 12.0,
                "record_date": "2026-11-16",
            },
        },
        5,
    )
    assert resp.status_code == 200, resp.text
    logged = json.loads(_parse_mcp(resp)["result"]["content"][0]["text"])
    assert logged["synced"] == 1
    assert logged["external_id"].startswith("mcp-")
    assert logged["calories"] == 450
    assert len(state.entries) == 1
    assert state.entries[0]["dishName"] == "rice + chicken curry"
    assert state.entries[0]["proteinG"] == 35.0

    resp = _mcp_call(
        app_client, access, session_id, "tools/call",
        {"name": "get_eating_score", "arguments": {"days": 7}}, 6,
    )
    assert resp.status_code == 200, resp.text
    score = json.loads(_parse_mcp(resp)["result"]["content"][0]["text"])
    assert score["score"] == 78
    assert score["label"] == "Optimal"

    resp = _mcp_call(
        app_client, access, session_id, "tools/call",
        {"name": "delete_food_entry", "arguments": {"external_id": logged["external_id"]}}, 7,
    )
    assert resp.status_code == 200, resp.text
    assert len(state.entries) == 0
