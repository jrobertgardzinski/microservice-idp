"""Stub OpenID Connect provider — the identity sibling of the sms/push/image services: a tiny
framework-free HTTP service that lets the stack demonstrate "Sign in with Google" without Google.
microservice-security speaks the same Authorization Code + PKCE dance to this stub in the compose
stack and to a real provider in production; only the URLs in its config change.

    GET  /authorize?client_id&redirect_uri&state&nonce&code_challenge&code_challenge_method=S256
                                 -> HTML "who are you" form; with &email= present (the stub's
                                    automation convenience) it redirects immediately with a code
    POST /token                  -> {"access_token", "id_token", "token_type", "expires_in"}
                                    (single-use code, 5-minute TTL, PKCE S256 + client_secret check)
    GET  /userinfo               -> {"sub", "email", "email_verified"}  (Bearer access token)
    GET  /health                 -> {"status": "UP"}

The id_token is an HS256 JWS keyed with the client secret — exactly what OIDC prescribes for a
confidential client without an asymmetric keypair, and the strongest signature a stdlib-only
Python can mint. Anyone with the shared secret (i.e. microservice-security) can verify it.
"""

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode

SERVICE = "idp"

def log(level, message):
    """The stack's shared log line (observability/README.md in the aggregator repo): ISO
    time, level, cid/trace placeholders (this stdlib stack sets neither), service, message."""
    from datetime import datetime, timezone
    stamp = datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds")
    print(f"{stamp} {level:<5} [cid=-] [trace=-] {SERVICE} - {message}", flush=True)


ISSUER = os.environ.get("IDP_ISSUER", "http://localhost:8090")
CLIENT_ID = os.environ.get("IDP_CLIENT_ID", "demo-client")
CLIENT_SECRET = os.environ.get("IDP_CLIENT_SECRET", "demo-secret")
CODE_TTL_SECONDS = 300
TOKEN_TTL_SECONDS = 3600

_codes = {}    # code -> {email, nonce, code_challenge, redirect_uri, expires}
_tokens = {}   # access_token -> {email, expires}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def subject_of(email: str) -> str:
    """A stable pairwise-ish subject: real providers send an opaque id, never the email."""
    return "stub-" + hashlib.sha256(("sub:" + email).encode()).hexdigest()[:16]


def mint_id_token(email: str, nonce: str, now=None) -> str:
    now = int(now if now is not None else time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": subject_of(email),
        "email": email,
        "email_verified": True,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
        "nonce": nonce,
    }
    signing_input = b64url(json.dumps(header).encode()) + "." + b64url(json.dumps(claims).encode())
    signature = hmac.new(CLIENT_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64url(signature)


def issue_code(email: str, nonce: str, code_challenge: str, redirect_uri: str, now=None) -> str:
    code = secrets.token_urlsafe(24)
    _codes[code] = {
        "email": email,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "redirect_uri": redirect_uri,
        "expires": (now if now is not None else time.time()) + CODE_TTL_SECONDS,
    }
    return code


def exchange(code: str, code_verifier: str, client_id: str, client_secret: str,
             redirect_uri: str, now=None) -> dict:
    """The token endpoint's whole job. Raises ValueError with the OAuth error code on refusal."""
    if client_id != CLIENT_ID or client_secret != CLIENT_SECRET:
        raise ValueError("invalid_client")
    pending = _codes.pop(code, None)   # pop: a code is single-use, replay gets invalid_grant
    if pending is None or (now if now is not None else time.time()) > pending["expires"]:
        raise ValueError("invalid_grant")
    if redirect_uri != pending["redirect_uri"]:
        raise ValueError("invalid_grant")
    challenge = b64url(hashlib.sha256((code_verifier or "").encode()).digest())
    if challenge != pending["code_challenge"]:
        raise ValueError("invalid_grant")
    access_token = secrets.token_urlsafe(24)
    _tokens[access_token] = {"email": pending["email"],
                             "expires": (now if now is not None else time.time()) + TOKEN_TTL_SECONDS}
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL_SECONDS,
        "id_token": mint_id_token(pending["email"], pending["nonce"], now),
    }


def userinfo(access_token: str, now=None) -> dict:
    known = _tokens.get(access_token)
    if known is None or (now if now is not None else time.time()) > known["expires"]:
        raise ValueError("invalid_token")
    email = known["email"]
    return {"sub": subject_of(email), "email": email, "email_verified": True}


LOGIN_FORM = """<!doctype html><title>Stub IdP</title>
<body style="font-family:sans-serif;max-width:26rem;margin:4rem auto">
<h3>Stub identity provider</h3>
<p>Pretend to be anyone — this provider vouches for every inbox it is asked about.</p>
<form method="GET" action="/authorize">
{hidden}
<input name="email" type="email" placeholder="you@example.com" required autofocus>
<button>Sign in</button>
</form></body>"""


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        url = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path == "/health":
            self._json(200, {"status": "UP", "issuer": ISSUER})
        elif url.path == "/authorize":
            self._authorize(query)
        elif url.path == "/userinfo":
            self._userinfo()
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/token":
            self._json(404, {"error": "not found"})
            return
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        form = {k: v[0] for k, v in parse_qs(body).items()}
        try:
            self._json(200, exchange(form.get("code", ""), form.get("code_verifier", ""),
                                     form.get("client_id", ""), form.get("client_secret", ""),
                                     form.get("redirect_uri", "")))
        except ValueError as refused:
            self._json(400, {"error": str(refused)})

    def _authorize(self, query):
        required = ("client_id", "redirect_uri", "state", "nonce", "code_challenge")
        if query.get("client_id") != CLIENT_ID or query.get("code_challenge_method", "S256") != "S256" \
                or any(not query.get(name) for name in required):
            self._json(400, {"error": "invalid_request"})
            return
        email = query.get("email")
        if not email:   # a human: show the form, echo every OAuth param through it
            hidden = "\n".join(
                f'<input type="hidden" name="{html.escape(name)}" value="{html.escape(query[name])}">'
                for name in (*required, "code_challenge_method", "response_type", "scope") if name in query)
            page = LOGIN_FORM.format(hidden=hidden).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return
        code = issue_code(email, query["nonce"], query["code_challenge"], query["redirect_uri"])
        location = query["redirect_uri"] + ("&" if "?" in query["redirect_uri"] else "?") \
            + urlencode({"code": code, "state": query["state"]})
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _userinfo(self):
        header = self.headers.get("Authorization", "")
        try:
            self._json(200, userinfo(header.removeprefix("Bearer ").strip()))
        except ValueError:
            self._json(401, {"error": "invalid_token"})

    def _json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        log("INFO", f"{self.command} {urlparse(self.path).path}")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8090"))
    log("INFO", f"stub identity provider listening on {port} (issuer={ISSUER}, client_id={CLIENT_ID})")
    ThreadingHTTPServer(("", port), Handler).serve_forever()
