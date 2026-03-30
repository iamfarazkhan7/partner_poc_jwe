import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=False)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="Partner POC JWE")

SESSION_COOKIE_NAME = "partner_poc_session"

# Default demo users for local testing.
USERS = {
    "partner_user": {
        "password": "demo123",
        "role": "partner",
        "email": "partner@opexa-llc.com",
        "name": "Partner User",
    },
    "staff_user": {
        "password": "demo123",
        "role": "staff",
        "email": "staff@opexa-llc.com",
        "name": "Staff User",
    },
    "public_user": {
        "password": "demo123",
        "role": "public",
        "email": "public@opexa-llc.com",
        "name": "Public User",
    },
}


def _env(key: str, default: str) -> str:
    value = os.getenv(key, default)
    return value.strip() if isinstance(value, str) else default


def _allowed_widget_origins() -> list[str]:
    raw = _env(
        "ALLOWED_WIDGET_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    )
    return [x.strip() for x in raw.split(",") if x.strip()]


def _get_current_user(request: Request):
    username = (request.cookies.get(SESSION_COOKIE_NAME) or "").strip()
    if not username:
        return None
    user = USERS.get(username)
    if not user:
        return None
    return {"username": username, **user}


def _find_user_by_login(login_value: str):
    needle = (login_value or "").strip().lower()
    if not needle:
        return (None, None)
    # Direct username match first
    if needle in USERS:
        return (needle, USERS[needle])
    # Email fallback
    for username, user in USERS.items():
        email = str(user.get("email", "")).strip().lower()
        if email and email == needle:
            return (username, user)
    return (None, None)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _load_literal_env_secret(env_key: str, default: str) -> bytes:
    return _env(env_key, default).encode("utf-8")


def _load_jwe_key() -> bytes:
    enc = _env("PARTNER_JWE_ENC", "A256GCM")
    expected_lengths = {
        "A128GCM": 16,
        "A192GCM": 24,
        "A256GCM": 32,
    }
    expected_length = expected_lengths.get(enc)
    if expected_length is None:
        raise ValueError(
            f"Unsupported PARTNER_JWE_ENC value {enc!r}. Expected one of: A128GCM, A192GCM, A256GCM."
        )

    key = _load_literal_env_secret(
        "PARTNER_JWE",
        "0123456789abcdef0123456789abcdef",
    )
    if len(key) != expected_length:
        raise ValueError(
            f"PARTNER_JWE is {len(key)} bytes, but PARTNER_JWE_ENC={enc} requires {expected_length} bytes."
        )
    return key


def _load_jws_key() -> tuple[str, bytes, object]:
    alg = _env("PARTNER_JWS_ALG", "HS256")
    minimum_lengths = {
        "HS256": 32,
        "HS384": 48,
        "HS512": 64,
    }
    digest_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    minimum_length = minimum_lengths.get(alg)
    digest = digest_map.get(alg)
    if minimum_length is None or digest is None:
        raise ValueError(
            f"Unsupported PARTNER_JWS_ALG value {alg!r}. Expected one of: HS256, HS384, HS512."
        )

    secret = _load_literal_env_secret(
        "PARTNER_JWS",
        "0123456789abcdef0123456789abcd",
    )
    if len(secret) < minimum_length:
        raise ValueError(
            f"PARTNER_JWS is {len(secret)} bytes, but PARTNER_JWS_ALG={alg} requires at least {minimum_length} bytes."
        )
    return alg, secret, digest


def _create_jwe() -> str:
    jwe_key = _load_jwe_key()
    jwe_enc = _env("PARTNER_JWE_ENC", "A256GCM")
    jws_alg, jwt_secret, digest = _load_jws_key()
    now = int(time.time())
    payload = {
        "user_id": _env("PARTNER_JWT_USER_ID", "partner-user"),
        "email": _env("PARTNER_JWT_EMAIL", "partner-user@devboxtech.co.uk"),
        "roles": [
            role.strip()
            for role in _env("PARTNER_JWT_ROLES", "partner").split(",")
            if role.strip()
        ],
        "exp": now + 3600,
    }

    jwt_header = _b64url(json.dumps({"alg": jws_alg, "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
    jwt_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    jwt_signing_input = f"{jwt_header}.{jwt_payload}"
    jwt_signature = hmac.new(
        jwt_secret,
        jwt_signing_input.encode("utf-8"),
        digest,
    ).digest()
    inner_jwt = f"{jwt_signing_input}.{_b64url(jwt_signature)}"

    protected_b64 = _b64url(
        json.dumps({"alg": "dir", "enc": jwe_enc, "cty": "JWT"}, separators=(",", ":")).encode("utf-8")
    )
    iv = os.urandom(12)
    ciphertext_and_tag = AESGCM(jwe_key).encrypt(
        iv,
        inner_jwt.encode("utf-8"),
        protected_b64.encode("utf-8"),
    )
    ciphertext = ciphertext_and_tag[:-16]
    tag = ciphertext_and_tag[-16:]
    return ".".join(
        [
            protected_b64,
            "",
            _b64url(iv),
            _b64url(ciphertext),
            _b64url(tag),
        ]
    )


@app.get("/", response_class=HTMLResponse)
def home() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": error,
            "demo_users": list(USERS.keys()),
        },
    )


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    current_user = _get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/login", status_code=302)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "jwe_cookie_name": _env("JWE_COOKIE_NAME", "roy_widget_jwe"),
            "allowed_widget_origins": _allowed_widget_origins(),
            "current_user": current_user,
        },
    )


@app.post("/login")
def login(
    username: str = Form(...),
    password: str = Form(...),
):
    matched_username, user = _find_user_by_login(username)
    if not user or user["password"] != password:
        return RedirectResponse(
            url="/login?error=Invalid%20username%20or%20password",
            status_code=302,
        )
    token = _create_jwe()
    response = RedirectResponse(url="/dashboard", status_code=302)
    response.set_cookie(
        key=_env("JWE_COOKIE_NAME", "roy_widget_jwe"),
        value=token,
        max_age=60 * 60,
        httponly=False,  # parent page JS needs to read and relay this for PoC
        samesite="lax",
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=matched_username,
        max_age=60 * 60 * 8,
        httponly=True,
        samesite="lax",
    )
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(key=_env("JWE_COOKIE_NAME", "roy_widget_jwe"))
    response.delete_cookie(key=SESSION_COOKIE_NAME)
    return response
