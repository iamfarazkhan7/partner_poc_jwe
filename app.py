import base64
import hashlib
import hmac
import json
import os
import re
import time
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=False)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="Partner POC Token Auth")

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


def _widget_iframe_url() -> str:
    return _env("WIDGET_IFRAME_URL", "http://localhost:3000/roy/widget-iframe")


def _partner_id() -> str:
    return _env("PARTNER_ID", "050353eae9b6")


def _partner_auth_mode() -> str:
    mode = _env("PARTNER_AUTH_MODE", "nested").lower()
    supported = {"jws", "jwe", "nested", "auto"}
    if mode not in supported:
        raise ValueError(
            f"Unsupported PARTNER_AUTH_MODE value {mode!r}. Expected one of: auto, jwe, jws, nested."
        )
    return mode


def _demo_token_flow() -> str:
    configured_flow = _env("PARTNER_TOKEN_FLOW", "").lower()
    auth_mode = _partner_auth_mode()
    if auth_mode != "auto":
        return auth_mode
    if configured_flow:
        supported = {"jws", "jwe", "nested"}
        if configured_flow not in supported:
            raise ValueError(
                f"Unsupported PARTNER_TOKEN_FLOW value {configured_flow!r}. Expected one of: jwe, jws, nested."
            )
        return configured_flow
    return "nested"


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


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


_COMPACT_JWS_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


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


def _create_claims() -> dict:
    now = int(time.time())
    return {
        "user_id": _env("PARTNER_JWT_USER_ID", "partner-user"),
        "email": _env("PARTNER_JWT_EMAIL", "partner-user@devboxtech.co.uk"),
        "roles": [
            role.strip()
            for role in _env("PARTNER_JWT_ROLES", "partner").split(",")
            if role.strip()
        ],
        "exp": now + 3600,
    }


def _create_jws(payload: dict) -> str:
    jws_alg, jwt_secret, digest = _load_jws_key()
    jwt_header = _b64url(
        json.dumps({"alg": jws_alg, "typ": "JWT"}, separators=(",", ":")).encode("utf-8")
    )
    jwt_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    jwt_signing_input = f"{jwt_header}.{jwt_payload}"
    jwt_signature = hmac.new(
        jwt_secret,
        jwt_signing_input.encode("utf-8"),
        digest,
    ).digest()
    return f"{jwt_signing_input}.{_b64url(jwt_signature)}"


def _create_jwe(plaintext: bytes, content_type: Optional[str] = None) -> str:
    jwe_key = _load_jwe_key()
    protected_header = {"alg": "dir", "enc": _env("PARTNER_JWE_ENC", "A256GCM")}
    if content_type:
        protected_header["cty"] = content_type
    protected_b64 = _b64url(json.dumps(protected_header, separators=(",", ":")).encode("utf-8"))
    iv = os.urandom(12)
    ciphertext_and_tag = AESGCM(jwe_key).encrypt(
        iv,
        plaintext,
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


def _create_token() -> str:
    claims = _create_claims()
    flow = _demo_token_flow()
    if flow == "jws":
        return _create_jws(claims)
    if flow == "jwe":
        return _create_jwe(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    if flow == "nested":
        return _create_jwe(_create_jws(claims).encode("utf-8"), content_type="JWT")
    raise ValueError(f"Unsupported token flow {flow!r}.")


def _inspect_token(token: str) -> dict:
    token = (token or "").strip()
    details = {
        "present": bool(token),
        "part_count": 0,
        "kind": "missing",
        "header": None,
        "plaintext_kind": None,
        "plaintext_preview": None,
        "error": None,
    }
    if not token:
        return details

    parts = token.split(".")
    details["part_count"] = len(parts)

    try:
        if len(parts) == 3:
            details["kind"] = "jws"
            details["header"] = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
            payload = _b64url_decode(parts[1]).decode("utf-8")
            details["plaintext_kind"] = "json" if payload.lstrip().startswith("{") else "text"
            details["plaintext_preview"] = payload[:160]
            return details

        if len(parts) == 5:
            details["kind"] = "jwe"
            details["header"] = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
            plaintext = AESGCM(_load_jwe_key()).decrypt(
                _b64url_decode(parts[2]),
                _b64url_decode(parts[3]) + _b64url_decode(parts[4]),
                parts[0].encode("utf-8"),
            ).decode("utf-8")
            details["plaintext_preview"] = plaintext[:160]
            if plaintext.lstrip().startswith("{"):
                details["plaintext_kind"] = "json"
            elif _COMPACT_JWS_RE.fullmatch(plaintext):
                details["plaintext_kind"] = "compact_jws"
            else:
                details["plaintext_kind"] = "text"
            return details

        details["kind"] = "unknown"
        details["error"] = f"Unexpected compact part count: {len(parts)}"
        return details
    except Exception as exc:
        details["error"] = str(exc)
        return details


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
    cookie_name = _env("JWE_COOKIE_NAME", "roy_widget_jwe")
    token = _create_token()
    response = templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "jwe_cookie_name": cookie_name,
            "allowed_widget_origins": _allowed_widget_origins(),
            "current_user": current_user,
            "widget_iframe_url": _widget_iframe_url(),
            "partner_id": _partner_id(),
            "partner_auth_mode": _partner_auth_mode(),
            "token_flow": _demo_token_flow(),
            "token_debug": _inspect_token(token),
        },
    )
    response.set_cookie(
        key=cookie_name,
        value=token,
        max_age=60 * 60,
        httponly=False,  # parent page JS needs to read and relay this for PoC
        samesite="lax",
    )
    return response


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
    token = _create_token()
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
