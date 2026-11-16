# GymSuit MCP server

Log food into GymSuit from any MCP-compatible AI assistant (Muse, Claude,
ChatGPT, …). Each user signs in with **their own GymSuit account** via
OAuth 2.1 (email + 6-digit code, the same login the GymSuit app uses), and
every tool call acts as that user only.

No GymSuit backend changes are needed: this server verifies users against
the existing mobile OTP login and calls the existing food API.

## Tools

| Tool | What it does |
| --- | --- |
| `log_food` | Log one meal with full nutrition: `meal` (BREAKFAST/LUNCH/DINNER/SNACK), `dish_name`, `calories`, `protein_g`, `carbs_g`, `fat_g`, optional `record_date` (YYYY-MM-DD, default today) and `photo_base64`. Returns the `external_id` for corrections. |
| `get_eating_score` | Eating-habit score 0–100 from food logged over the trailing `days` (default 7, max 30), vs `calorie_target_kcal` (default 2000). |
| `delete_food_entry` | Delete one entry by `external_id` (the one `log_food` returned). |
| `whoami` | Show which GymSuit account the current login belongs to. |

Logged entries appear in the GymSuit app's food log, the eating-habit score
on the meals page, and the trainer progress page. Entries are tagged
`mcp-<id>` so they never collide with entries the app itself syncs.

## How login works

1. The AI client discovers this server's OAuth metadata, registers itself
   (dynamic client registration), and opens the login page in a browser.
2. The user enters their GymSuit email → a 6-digit code arrives by email →
   they enter it → they approve the requested scopes (`food:read food:write`).
3. The server issues the client an MCP access token (1 hour) + refresh
   token (30 days, rotated on use).
4. Behind the scenes, the server keeps that user's GymSuit tokens
   (Fernet-encrypted in SQLite) and refreshes them automatically when the
   GymSuit backend answers 401 (GymSuit access tokens live 24 h, refresh
   tokens 30 days and rotate).

Nothing about one user is ever visible to another: the user identity for
every tool call comes from the validated MCP access token, never from a
tool argument.

## Deploy (server operator)

```bash
git clone https://github.com/zeezaglobal/gymsuit-mcp.git
cd gymsuit-mcp
python3 -m venv venv && venv/bin/pip install .   # installs the package + its deps
cp .env.example .env   # then fill in PUBLIC_URL + MCP_SECRET_KEY
venv/bin/python -m gymsuit_mcp
```

Required env (see `.env.example`):

- `PUBLIC_URL` — the public base URL, e.g. `https://mcp.gymsuit.app`.
  Used as the OAuth issuer and in all metadata/redirect URLs.
- `MCP_SECRET_KEY` — long random string. Encrypts stored GymSuit tokens
  and signs web sessions. Generate with
  `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
- `GYMSUIT_API_BASE` — default `https://api.gymsuit.app`.
- `DATABASE_PATH` — SQLite file, default `data/gymsuit-mcp.db`.
- `PORT` — default `8000`.

Expose it with the same Cloudflare Tunnel setup as the GymSuit backend,
on its own hostname (e.g. `mcp.gymsuit.app`). The tunnel provides TLS;
the MCP endpoint itself requires a valid OAuth access token on every call.

A systemd unit is included (`gymsuit-mcp.service` — adjust `User` and
paths to the server layout):

```bash
sudo cp gymsuit-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now gymsuit-mcp
```

## Connect (user)

In your AI assistant, add an MCP server with the Streamable HTTP URL:

```
https://mcp.gymsuit.app/mcp
```

The assistant will handle OAuth itself: it registers, opens the GymSuit
sign-in page, you enter your email + code and approve, and it stays
signed in (refresh tokens rotate automatically). In Muse, this goes
through the custom-connector setup for an OAuth-protected MCP server —
the `resource` is `https://mcp.gymsuit.app/mcp`.

## Development

```bash
python3 -m venv venv && venv/bin/pip install -e . -r requirements.txt
venv/bin/python -m pytest tests/ -q
```

Tests run a stub GymSuit API on a local port and drive the whole flow
over HTTP: OAuth metadata → registration → email/OTP login → consent →
code exchange → refresh rotation → MCP `initialize` → `tools/list` →
`whoami` → `log_food` → `get_eating_score` → `delete_food_entry`.

## Status

v0.1.0. Tested end to end against a stub of the GymSuit API. Live check
against the real backend (real OTP + real food sync) still to do after
first deploy.
