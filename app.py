import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from urllib.parse import urlencode

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


def _load_aesgcm_key() -> bytes:
    key = _env("PARTNER_JWE_KEY", "0123456789abcdef0123456789abcdef").encode("utf-8")
    if len(key) not in {16, 24, 32}:
        raise ValueError(
            f"PARTNER_JWE_KEY must be 16, 24, or 32 bytes for AESGCM; got {len(key)} bytes."
        )
    return key


def _create_jwe() -> str:
    jwe_key = _load_aesgcm_key()
    jwt_secret = _env("PARTNER_JWT_SECRET", "0123456789abcdef0123456789abcd").encode("utf-8")
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

    jwt_header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
    jwt_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    jwt_signing_input = f"{jwt_header}.{jwt_payload}"
    jwt_signature = hmac.new(
        jwt_secret,
        jwt_signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    inner_jwt = f"{jwt_signing_input}.{_b64url(jwt_signature)}"

    protected_b64 = _b64url(
        json.dumps({"alg": "dir", "enc": "A256GCM", "cty": "JWT"}, separators=(",", ":")).encode("utf-8")
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

    parent_origin = str(request.base_url).rstrip("/")
    widget_base = _env("WIDGET_IFRAME_URL", "http://localhost:3000/roy/widget-iframe")
    partner_id = _env("PARTNER_ID", "partner-poc-jwe")
    query = urlencode(
        {
            "partner_id": partner_id,
            "parent_origin": parent_origin,
            "auth_approach": "jwe_cookie",
            "widget_jwt_cookie_name": _env("JWE_COOKIE_NAME", "roy_widget_jwe"),
        }
    )
    iframe_url = f"{widget_base}?{query}"
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "iframe_url": iframe_url,
            "partner_id": partner_id,
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
