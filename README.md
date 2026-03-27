# Partner POC (JWE Cookie Mode)

Small FastAPI app to test the widget's new `jwe_cookie` auth approach.

## What this POC does

- Uses a login page with default test users (username/password).
- On login, generates an HS256 JWT with the default sample claims and wraps it in a `dir` / `A256GCM` JWE.
- Stores JWE in cookie (default: `roy_widget_jwe`).
- Shows dashboard with embedded widget iframe.
- Listens for `ROY_WIDGET_JWE_REQUEST` and replies with `ROY_WIDGET_JWE_RESPONSE`.

## 1) Configure env

```bash
cd partner_poc_jwe
cp .env.example .env
```

Update `.env`:

- `WIDGET_IFRAME_URL` (your widget iframe URL)
- `PARTNER_ID` (must exist in Roy backend partner config)
- `PARTNER_JWE_KEY` (must match backend `jwe_decryption_key` for this partner)
- `PARTNER_JWT_SECRET` (defaults to `0123456789abcdef0123456789abcd`)
- `PARTNER_JWT_USER_ID` (defaults to `faraz7`)
- `PARTNER_JWT_EMAIL` (defaults to `faraz@devboxtech.co.uk`)
- `PARTNER_JWT_ROLES` (defaults to `partner,staff`)
- `ALLOWED_WIDGET_ORIGINS` (widget host origins allowed for postMessage)

## 2) Install and run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 9010 --reload
```

Open: `http://127.0.0.1:9010/dashboard`

## Demo users

- `partner_user / demo123` (role: `partner`)
- `staff_user / demo123` (role: `staff`)
- `public_user / demo123` (role: `public`)

## 3) Widget setup

Use widget loader with:

- `data-auth-approach="jwe_cookie"`
- `data-partner-id="<same partner_id>"`
- optional `data-widget-jwt-cookie-name="roy_widget_jwe"`

## 4) Expected behavior

- Open popup -> iframe sends `ROY_WIDGET_JWE_REQUEST`.
- Parent returns JWE from cookie.
- Widget calls `POST /widget/jwe-auth`.
- Widget updates to authenticated role/user.
- Every poll cycle while open, widget re-checks cookie presence via same message flow.

Token defaults:

- JWE key default: `0123456789abcdef0123456789abcdef`
- JWT secret default: `0123456789abcdef0123456789abcd`
- JWT default payload: `user_id=faraz7`, `email=faraz@devboxtech.co.uk`, `roles=["partner","staff"]`, `exp=now+3600`
- Expiry default: 1 hour

## Notes

- This POC sets cookie as non-HttpOnly so browser JS can read it for relay.
- Production systems should harden this pattern (strict origin checks, secure cookies, TLS).
