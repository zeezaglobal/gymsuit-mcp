"""OAuth 2.1 authorization server for the GymSuit MCP server.

This server is its own authorization server (MCP Authorization spec):
it verifies the user against the *existing* GymSuit OTP login
(/api/mobile/auth/send-otp + /verify-login), then issues its own MCP
access/refresh tokens. The GymSuit tokens it receives are stored
Fernet-encrypted, one row per user, so tool calls can act as that user.
No GymSuit backend changes are needed.

Endpoints:
- /.well-known/oauth-protected-resource  (RFC 9728)
- /.well-known/oauth-authorization-server (RFC 8414)
- POST /oauth/register                   (RFC 7591 dynamic client registration)
- GET  /oauth/authorize                  (login + consent, browser flow)
- POST /oauth/authorize/email|otp|consent
- POST /oauth/token                      (authorization_code + refresh_token)
- GET  /                                 (landing page)
"""

from __future__ import annotations

from urllib.parse import urlencode

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route, Router

from .config import Settings
from .crypto import decrypt, encrypt
from .gymsuit import GymSuitClient, GymSuitError
from .store import Store


def _page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — GymSuit MCP</title>
<style>
body {{ font-family: -apple-system, system-ui, sans-serif; background: #f6f8fa;
  color: #1a1a1a; margin: 0; padding: 40px 16px; }}
.card {{ max-width: 420px; margin: 0 auto; background: #fff; border-radius: 12px;
  padding: 28px; box-shadow: 0 2px 12px rgba(0,0,0,.08); }}
h1 {{ font-size: 20px; margin: 0 0 8px; }} p {{ color: #555; line-height: 1.5; }}
label {{ display: block; font-weight: 600; margin: 16px 0 6px; }}
input {{ width: 100%; box-sizing: border-box; padding: 10px 12px; font-size: 16px;
  border: 1px solid #ccc; border-radius: 8px; }}
button {{ width: 100%; margin-top: 20px; padding: 12px; font-size: 16px; font-weight: 600;
  color: #fff; background: #007375; border: 0; border-radius: 8px; cursor: pointer; }}
button.secondary {{ background: #e5e7eb; color: #1a1a1a; }}
.error {{ background: #fdecea; color: #8f1d13; padding: 10px 12px; border-radius: 8px; }}
.scopes {{ background: #f0f7f7; padding: 10px 12px; border-radius: 8px; }}
small {{ color: #888; }}
</style></head><body><div class="card">{body}</div></body></html>"""


def _email_page(error: str | None = None) -> str:
    err = f'<div class="error">{error}</div>' if error else ""
    return _page(
        "Sign in",
        f"""<h1>Sign in to GymSuit</h1>
<p>Enter the email address of your GymSuit account. We will send you a
6-digit code, the same way the GymSuit app signs you in.</p>{err}
<form method="post" action="/oauth/authorize/email">
<label for="email">Email</label>
<input id="email" name="email" type="email" required autocomplete="email"
  placeholder="you@example.com">
<button type="submit">Send code</button></form>""",
    )


def _otp_page(email: str, error: str | None = None) -> str:
    err = f'<div class="error">{error}</div>' if error else ""
    return _page(
        "Enter code",
        f"""<h1>Check your email</h1>
<p>We sent a 6-digit code to <b>{email}</b>. It expires in a few minutes.</p>{err}
<form method="post" action="/oauth/authorize/otp">
<label for="otp">6-digit code</label>
<input id="otp" name="otp" type="text" inputmode="numeric" pattern="[0-9]{{6}}"
  maxlength="6" required autocomplete="one-time-code" placeholder="123456">
<button type="submit">Verify</button></form>
<form method="get" action="/oauth/authorize"><button class="secondary" type="submit">
Back</button></form>""",
    )


def _consent_page(email: str, client_name: str, scope: str) -> str:
    scopes = "".join(f"<li><code>{s}</code></li>" for s in scope.split())
    return _page(
        "Allow access",
        f"""<h1>Allow this assistant?</h1>
<p><b>{client_name}</b> wants to access your GymSuit account as
<b>{email}</b> with these permissions:</p>
<div class="scopes"><ul>{scopes}</ul></div>
<p><small>food:read — read your eating-habit score.<br>
food:write — log food and delete entries you logged through it.</small></p>
<form method="post" action="/oauth/authorize/consent">
<button type="submit" name="approve" value="yes">Allow</button>
<button class="secondary" type="submit" name="approve" value="no">Deny</button>
</form>""",
    )


class OAuthRoutes:
    def __init__(self, settings: Settings, store: Store, gymsuit: GymSuitClient) -> None:
        self.settings = settings
        self.store = store
        self.gymsuit = gymsuit

    def router(self) -> Router:
        return Router(
            [
                Route("/", self.landing, methods=["GET"]),
                Route("/.well-known/oauth-protected-resource", self.protected_resource, methods=["GET"]),
                Route("/.well-known/oauth-authorization-server", self.auth_server_meta, methods=["GET"]),
                Route("/oauth/register", self.register, methods=["POST"]),
                Route("/oauth/authorize", self.authorize_get, methods=["GET"]),
                Route("/oauth/authorize/email", self.authorize_email, methods=["POST"]),
                Route("/oauth/authorize/otp", self.authorize_otp, methods=["POST"]),
                Route("/oauth/authorize/consent", self.authorize_consent, methods=["POST"]),
                Route("/oauth/token", self.token, methods=["POST"]),
            ]
        )

    # -- landing + metadata -------------------------------------------
    async def landing(self, request: Request) -> Response:
        return HTMLResponse(
            _page(
                "GymSuit MCP",
                f"""<h1>GymSuit MCP server</h1>
<p>Log food into GymSuit from any MCP-compatible AI assistant. Each user
signs in with their own GymSuit account (OAuth 2.1, email + code).</p>
<p><b>MCP endpoint:</b> <code>{self.settings.public_url}/mcp</code><br>
<b>Protected resource:</b>
<code>{self.settings.public_url}/.well-known/oauth-protected-resource</code></p>
<p>Tools: <code>log_food</code>, <code>get_eating_score</code>,
<code>delete_food_entry</code>, <code>whoami</code>.</p>""",
            )
        )

    async def protected_resource(self, request: Request) -> Response:
        return JSONResponse(
            {
                "resource": f"{self.settings.public_url}/mcp",
                "authorization_servers": [self.settings.public_url],
            }
        )

    async def auth_server_meta(self, request: Request) -> Response:
        base = self.settings.public_url
        return JSONResponse(
            {
                "issuer": base,
                "authorization_endpoint": f"{base}/oauth/authorize",
                "token_endpoint": f"{base}/oauth/token",
                "registration_endpoint": f"{base}/oauth/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "scopes_supported": list(self.settings.scopes_supported),
                "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
            }
        )

    # -- dynamic client registration ------------------------------------
    async def register(self, request: Request) -> Response:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid_request", "error_description": "JSON body required"}, status_code=400)
        redirect_uris = body.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris or not all(
            isinstance(u, str) and u.startswith(("https://", "http://127.0.0.1", "http://localhost"))
            for u in redirect_uris
        ):
            return JSONResponse(
                {"error": "invalid_redirect_uri", "error_description": "redirect_uris must be a non-empty list of URLs"},
                status_code=400,
            )
        client_id = await self.store.create_client(redirect_uris, body.get("client_name"))
        return JSONResponse(
            {
                "client_id": client_id,
                "client_id_issued_at": int(__import__("time").time()),
                "redirect_uris": redirect_uris,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": " ".join(self.settings.scopes_supported),
            },
            status_code=201,
        )

    # -- authorize flow ---------------------------------------------------
    def _valid_scope(self, scope: str) -> bool:
        return bool(scope) and all(s in self.settings.scopes_supported for s in scope.split())

    async def authorize_get(self, request: Request) -> Response:
        params = request.query_params
        if params.get("response_type") != "code":
            return HTMLResponse(_page("Error", "<h1>Unsupported response type</h1><p>This server only supports <code>code</code>.</p>"), status_code=400)
        client = await self.store.get_client(params.get("client_id", ""))
        if client is None:
            return HTMLResponse(_page("Error", "<h1>Unknown client</h1><p>The app was not registered. Try connecting again.</p>"), status_code=400)
        redirect_uri = params.get("redirect_uri", "")
        import json as _json

        allowed = _json.loads(client["redirect_uris"])
        if redirect_uri not in allowed:
            return HTMLResponse(_page("Error", "<h1>Bad redirect URI</h1><p>The app gave a redirect address that was not registered.</p>"), status_code=400)
        if not params.get("code_challenge") or params.get("code_challenge_method", "S256") != "S256":
            return HTMLResponse(_page("Error", "<h1>PKCE required</h1><p>The app must use a S256 code challenge.</p>"), status_code=400)
        scope = params.get("scope") or " ".join(self.settings.scopes_supported)
        if not self._valid_scope(scope):
            return HTMLResponse(_page("Error", "<h1>Unknown scope</h1><p>The app asked for a permission this server does not offer.</p>"), status_code=400)
        request.session["auth_req"] = {
            "client_id": client["client_id"],
            "redirect_uri": redirect_uri,
            "state": params.get("state"),
            "code_challenge": params["code_challenge"],
            "scope": scope,
        }
        if request.session.get("gymsuit_email"):
            return HTMLResponse(
                _consent_page(
                    request.session["gymsuit_email"],
                    client.get("client_name") or client["client_id"],
                    scope,
                )
            )
        return HTMLResponse(_email_page())

    async def authorize_email(self, request: Request) -> Response:
        form = await request.form()
        email = str(form.get("email", "")).strip().lower()
        if "@" not in email:
            return HTMLResponse(_email_page("Enter a valid email address."), status_code=400)
        try:
            await self.gymsuit.send_otp(email)
        except GymSuitError as exc:
            return HTMLResponse(_email_page(f"Could not send a code: {exc.message}"), status_code=400)
        request.session["email"] = email
        return HTMLResponse(_otp_page(email))

    async def authorize_otp(self, request: Request) -> Response:
        form = await request.form()
        otp = str(form.get("otp", "")).strip()
        email = request.session.get("email", "")
        if not email or len(otp) != 6 or not otp.isdigit():
            return HTMLResponse(_otp_page(email, "Enter the 6-digit code."), status_code=400)
        try:
            profile = await self.gymsuit.verify_login(email, otp)
        except GymSuitError as exc:
            return HTMLResponse(_otp_page(email, f"That code did not work: {exc.message}"), status_code=400)
        await self.store.upsert_gymsuit_user(
            profile.get("email", email),
            profile,
            encrypt(self.settings.secret_key, profile["token"]),
            encrypt(self.settings.secret_key, profile["refreshToken"]),
        )
        request.session["gymsuit_email"] = profile.get("email", email)
        auth_req = request.session.get("auth_req") or {}
        client = await self.store.get_client(auth_req.get("client_id", ""))
        return HTMLResponse(
            _consent_page(
                request.session["gymsuit_email"],
                (client or {}).get("client_name") or auth_req.get("client_id", "this app"),
                auth_req.get("scope", ""),
            )
        )

    async def authorize_consent(self, request: Request) -> Response:
        form = await request.form()
        auth_req = request.session.get("auth_req") or {}
        redirect_uri = auth_req.get("redirect_uri", "")
        state = auth_req.get("state")
        if str(form.get("approve", "")) != "yes":
            query = {"error": "access_denied"}
            if state:
                query["state"] = state
            return RedirectResponse(f"{redirect_uri}?{urlencode(query)}", status_code=302)
        email = request.session.get("gymsuit_email", "")
        if not email or not redirect_uri:
            return HTMLResponse(_page("Error", "<h1>Session expired</h1><p>Start the sign-in again from your assistant.</p>"), status_code=400)
        code = await self.store.create_auth_code(
            auth_req["client_id"],
            redirect_uri,
            auth_req["code_challenge"],
            auth_req.get("scope", ""),
            email,
            self.settings.auth_code_ttl,
        )
        query = {"code": code}
        if state:
            query["state"] = state
        request.session.pop("auth_req", None)
        return RedirectResponse(f"{redirect_uri}?{urlencode(query)}", status_code=302)

    # -- token endpoint ----------------------------------------------------
    async def token(self, request: Request) -> Response:
        form = await request.form()
        grant = str(form.get("grant_type", ""))
        if grant == "authorization_code":
            code = str(form.get("code", ""))
            client_id = str(form.get("client_id", ""))
            redirect_uri = str(form.get("redirect_uri", ""))
            verifier = str(form.get("code_verifier", ""))
            if not all([code, client_id, redirect_uri, verifier]):
                return JSONResponse({"error": "invalid_request", "error_description": "code, client_id, redirect_uri and code_verifier are required"}, status_code=400)
            data = await self.store.redeem_auth_code(code, client_id, redirect_uri, verifier)
            if data is None:
                return JSONResponse({"error": "invalid_grant", "error_description": "Authorization code is invalid, expired, or already used"}, status_code=400)
            access, refresh = await self.store.issue_token_pair(
                client_id, data["email"], data["scope"],
                self.settings.access_token_ttl, self.settings.refresh_token_ttl,
            )
            return JSONResponse(
                {
                    "access_token": access,
                    "token_type": "Bearer",
                    "expires_in": self.settings.access_token_ttl,
                    "refresh_token": refresh,
                    "scope": data["scope"],
                }
            )
        if grant == "refresh_token":
            refresh_raw = str(form.get("refresh_token", ""))
            client_id = str(form.get("client_id", "")) or None
            if not refresh_raw:
                return JSONResponse({"error": "invalid_request", "error_description": "refresh_token is required"}, status_code=400)
            pair = await self.store.rotate_refresh_token(
                refresh_raw, client_id,
                self.settings.access_token_ttl, self.settings.refresh_token_ttl,
            )
            if pair is None:
                return JSONResponse({"error": "invalid_grant", "error_description": "Refresh token is invalid or expired"}, status_code=400)
            access, refresh = pair
            return JSONResponse(
                {
                    "access_token": access,
                    "token_type": "Bearer",
                    "expires_in": self.settings.access_token_ttl,
                    "refresh_token": refresh,
                    "scope": " ".join(self.settings.scopes_supported),
                }
            )
        return JSONResponse({"error": "unsupported_grant_type", "error_description": f"Grant type {grant!r} is not supported"}, status_code=400)
