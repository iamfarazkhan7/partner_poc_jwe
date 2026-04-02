# Partner POC (Compact Token Cookie Mode)

Small FastAPI app to test the widget's compact token auth flow.

## What this POC does

- Uses a login page with default test users (username/password).
- On login, generates one compact token based on partner auth mode:
  - `jws`: signed JWT only
  - `jwe`: encrypted token with plain JSON claims
  - `nested`: encrypted token whose plaintext is a signed JWT
  - `auto`: allows all three on the backend; this demo uses `PARTNER_TOKEN_FLOW` to pick which one to emit
- Stores the compact token in a cookie (default: `roy_widget_jwe`).
- Shows dashboard with embedded widget iframe.
- Listens for widget token requests and replies with the cookie token.

## 1) Configure env

```bash
cd partner_poc_jwe
cp .env.example .env
```

Update `.env`:

- `WIDGET_IFRAME_URL` (your widget iframe URL)
- `PARTNER_ID` (must exist in Roy backend partner config)
- `PARTNER_AUTH_MODE` (`jws`, `jwe`, `nested`, `auto`)
- `PARTNER_TOKEN_FLOW` (`jws`, `jwe`, `nested`) only used when `PARTNER_AUTH_MODE=auto`
- `PARTNER_JWE` (must match backend `partnerJwtKey` for this partner)
- `PARTNER_JWS` (must match backend `partnerJwtSecret` for this partner)
- `PARTNER_JWS_ALG` (must match backend `signingSecretAlgorithm`)
- `PARTNER_JWE_ENC` (must match backend `encryptionSecretMethod`)
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

The widget still initializes session with:

```json
{
  "partner_id": "actual-partner-id"
}
```

The widget then authenticates with:

```json
{
  "session_id": "...",
  "token": "...",
  "parent_hostname": "example.com"
}
```

Use the widget loader / iframe with:

- `data-auth-approach="jwe_cookie"`
- `data-partner-id="<same partner_id>"`
- optional `data-widget-jwt-cookie-name="roy_widget_jwe"`

## 4) Expected behavior

- Open popup -> iframe asks the parent for the compact token.
- Parent returns the token from cookie.
- Widget calls `POST /widget/jwe-auth`.
- Widget updates to authenticated role/user.
- Every poll cycle while open, widget re-checks cookie presence via same message flow.

Token defaults:

- JWE key default: `partnerJwtKey`
- JWT secret default: `partnerJwtSecret`
- Partner config fields used by backend: `partnerId`, `partnerHostname`, `partnerJwtSecret`, `partnerJwtKey`, `partnerAuthMode`, `signingSecretAlgorithm`, `encryptionSecretMethod`
- JWT default payload: `user_id=partner-user`, `email=partner-user@devboxtech.co.uk`, `roles=["partner"]`, `exp=now+3600`
- Expiry default: 1 hour

## Notes

- Token handling is automatic by compact format on the backend:
  - 3 parts = JWS
  - 5 parts = JWE
- This POC sets cookie as non-HttpOnly so browser JS can read it for relay.
- Production systems should harden this pattern (strict origin checks, secure cookies, TLS).
