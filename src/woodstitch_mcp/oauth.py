"""OAuth 2.1 front door for the hosted server (api.woodstitch.com), so Claude apps, Cowork and Claude Code
can connect with "Sign in with Woodstitch" instead of a pasted header.

Flow (MCP authorization spec): /mcp without a token -> 401 + WWW-Authenticate pointing at
/.well-known/oauth-protected-resource -> client reads /.well-known/oauth-authorization-server ->
dynamic client registration (/oauth/register) -> /oauth/authorize (PKCE S256; our page: paste an API key, or
create a trial account with the standard $25 credit) -> /oauth/token -> Bearer wsm_... on every MCP call.
The access token maps to the user's Woodstitch API key; the key never leaves the server.
Raw ws_live_/ws_test_ keys are still accepted as Bearer tokens (headers, scripts).
State is small JSON files (no database): clients, codes, tokens (sha256 of the token -> key).
"""
import base64, hashlib, html, json, os, secrets, time, threading, urllib.parse
from pathlib import Path
import httpx

ISSUER = os.environ.get("WOODSTITCH_MCP_ISSUER", "https://api.woodstitch.com")
API = os.environ.get("WOODSTITCH_BASE_URL", "https://api.woodstitch.com/v1")
STATE = Path(os.environ.get("WOODSTITCH_MCP_STATE", "/home/ubuntu/woodstitch/mcp_remote/state"))
ACCESS_TTL = 3600            # 1 hour; clients refresh silently (rotating refresh tokens)
REFRESH_TTL = 180 * 86400    # a refresh token unused for 180 days dies
CODE_TTL = 600
SITE = os.environ.get("WOODSTITCH_SITE", "https://woodstitch.com")
PEPPER_FILE = os.environ.get("WOODSTITCH_PEPPER_FILE", "/home/ubuntu/woodstitch/pepper.php")
_lock = threading.Lock()


def _load(name):
    try:
        return json.loads((STATE / f"{name}.json").read_text())
    except Exception:
        return {}


def _save(name, obj):
    STATE.mkdir(parents=True, exist_ok=True)
    p = STATE / f"{name}.json"
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj))
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def _h(t):
    return hashlib.sha256(t.encode()).hexdigest()


def _pepper() -> bytes:
    import re
    try:
        m = re.search(r"return\s*'([^']+)'", Path(PEPPER_FILE).read_text())
        return m.group(1).encode() if m else b""
    except Exception:
        return b""


def _internal_ok(hdr: dict, payload: str) -> bool:
    """Calls from woodstitch.com's PHP (app.php) to 127.0.0.1:8765 directly: never via the Apache proxy
    (which adds X-Forwarded-For) and signed with the site pepper."""
    import hmac
    pep = _pepper()
    if not pep or hdr.get("x-forwarded-for"):
        return False
    want = hmac.new(pep, b"mcpint\0" + payload.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, hdr.get("x-ws-sig", ""))


def _redirect_host(uri: str) -> str:
    try:
        u = urllib.parse.urlparse(uri)
        return u.hostname or uri
    except Exception:
        return uri


def resolve_token(token: str) -> str:
    """Bearer value -> Woodstitch API key ('' if unknown/expired)."""
    if not token:
        return ""
    if token.startswith(("ws_live_", "ws_test_")):
        return token
    if token.startswith("wsm_"):
        rec = _load("tokens").get(_h(token))
        if rec and rec.get("exp", 0) > time.time():
            return rec["key"]
    return ""


# ------------------------------------------------------------------ helpers
async def _body(receive):
    data = b""
    while True:
        m = await receive()
        data += m.get("body", b"")
        if not m.get("more_body"):
            return data


async def _send(send, status, body, ctype="application/json", headers=None):
    if not isinstance(body, (bytes, bytearray)):
        body = (json.dumps(body) if ctype == "application/json" else str(body)).encode()
    hdrs = [(b"content-type", ctype.encode()), (b"cache-control", b"no-store"),
            (b"access-control-allow-origin", b"*"), (b"access-control-allow-headers", b"authorization, content-type, mcp-protocol-version")]
    for k, v in (headers or {}).items():
        hdrs.append((k.encode(), v.encode()))
    await send({"type": "http.response.start", "status": status, "headers": hdrs})
    await send({"type": "http.response.body", "body": body})


def _form(raw: bytes, ctype: str):
    if "application/json" in ctype:
        try:
            return json.loads(raw or b"{}")
        except Exception:
            return {}
    return {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode(), keep_blank_values=True).items()}


def unauthorized_headers(error: str = ""):
    v = f'Bearer resource_metadata="{ISSUER}/.well-known/oauth-protected-resource"'
    if error:
        v += f', error="{error}"'
    return {"www-authenticate": v}


# ------------------------------------------------------------------ metadata
def protected_resource():
    return {"resource": f"{ISSUER}/mcp", "authorization_servers": [ISSUER], "bearer_methods_supported": ["header"],
            "resource_name": "Woodstitch human listening tests", "resource_documentation": "https://woodstitch.com/docs"}


def as_metadata():
    return {"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/oauth/authorize", "token_endpoint": f"{ISSUER}/oauth/token",
            "registration_endpoint": f"{ISSUER}/oauth/register", "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"], "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "scopes_supported": ["woodstitch"], "service_documentation": "https://woodstitch.com/docs"}


# ------------------------------------------------------------------ pages
# The main sign-in lives on woodstitch.com (/app/connect): Google or an emailed link, the same as the
# dashboard, then an Allow screen. This page is only the "use an API key instead" fallback.
PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Connect with an API key · Woodstitch</title><style>
:root{{--bg:#F7F4F0;--card:#fff;--ink:#17202B;--mid:#5F6875;--line:#E3DAD2;--acc:#7E22CE}}
@media(prefers-color-scheme:dark){{:root{{--bg:#141217;--card:#1C1A20;--ink:#F2EEF5;--mid:#A9A2B0;--line:#2A262F;--acc:#B57BF0}}}}
body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 Manrope,Inter,system-ui,sans-serif}}
main{{max-width:440px;margin:48px auto;padding:0 16px}} .card{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px;margin:0 0 14px}}
h1{{font-size:22px;margin:0 0 6px}} p{{margin:0 0 14px;color:var(--mid)}} label{{font-size:13px;font-weight:700;display:block;margin:0 0 6px}}
input{{width:100%;box-sizing:border-box;font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:8px;margin:0 0 12px;background:var(--card);color:var(--ink)}}
button{{font:inherit;font-weight:700;border:0;border-radius:8px;padding:11px 16px;width:100%;cursor:pointer;background:var(--acc);color:#fff}}
.err{{color:#B42318;font-weight:600}} small{{color:var(--mid)}} a{{color:var(--acc)}}
</style></head><body><main>
<h1>Connect with an API key</h1>
<p>For accounts that use a key. Tokens go back to <strong>{host}</strong>.</p>
{err}
<form class=card method=post action="/oauth/key"><input type=hidden name=req value="{req}">
<label for=key>API key</label><input id=key name=api_key placeholder="ws_live_..." autocomplete=off autofocus>
<button>Connect</button>
<p style="margin:10px 0 0"><small>Keys are at <a href="{site}/app/api-keys" target=_blank>woodstitch.com/app/api-keys</a>.</small></p></form>
<p><small><a href="{site}/app/connect?r={req}">Sign in with Google or email instead</a></small></p>
</main></body></html>"""

MSG = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Woodstitch</title><style>body{{margin:0;background:#F7F4F0;color:#17202B;font:16px/1.55 system-ui,sans-serif}}
@media(prefers-color-scheme:dark){{body{{background:#141217;color:#F2EEF5}}}}
main{{max-width:440px;margin:64px auto;padding:0 16px}} h1{{font-size:21px}} p{{color:#8A919C}}</style></head>
<body><main><h1>{title}</h1><p>{body}</p></main></body></html>"""


def _msg(title, body):
    return MSG.format(title=html.escape(title), body=html.escape(body))


def _page(req_id, host, err=""):
    return PAGE.format(host=html.escape(host or "your app"), req=html.escape(req_id), site=SITE,
                       err=f'<p class=err>{html.escape(err)}</p>' if err else "")


def _redirect_ok(client, uri):
    return uri in client.get("redirect_uris", [])


def _check_key(key: str, lenient: bool = False) -> bool:
    """True when the key works. lenient: only a definite 401/403 counts as dead (a network blip must not end a connection)."""
    try:
        r = httpx.get(f"{API}/account", headers={"Authorization": f"Bearer {key}", "User-Agent": "woodstitch-mcp-oauth"}, timeout=8)
        return r.status_code not in (401, 403) if lenient else r.status_code == 200
    except Exception:
        return lenient


def _pending(rid):
    with _lock:
        p = _load("pending").get(rid or "")
    return p if p and p["t"] > time.time() - 1800 else None


def _finish(rid, key=None, deny=False):
    """Consume the pending request; return the redirect URL back to the client (code, or access_denied)."""
    with _lock:
        p = _load("pending"); pend = p.pop(rid, None); _save("pending", p)
        if not pend:
            return None
        q = pend["q"]
        params = {}
        if deny:
            params["error"] = "access_denied"
        else:
            code = secrets.token_urlsafe(32)
            c = _load("codes"); now = time.time()
            c = {k: v for k, v in c.items() if v["exp"] > now}
            c[_h(code)] = {"exp": now + CODE_TTL, "key": key, "client_id": q["client_id"], "redirect_uri": q["redirect_uri"],
                           "challenge": q["code_challenge"]}
            _save("codes", c)
            params["code"] = code
        if q.get("state"):
            params["state"] = q["state"]
    sep = "&" if "?" in q["redirect_uri"] else "?"
    return q["redirect_uri"] + sep + urllib.parse.urlencode(params)


# ------------------------------------------------------------------ ASGI handler
async def handle(scope, receive, send) -> bool:
    """Serve OAuth routes. Returns False when the path is not ours."""
    path = scope.get("path", "")
    method = scope.get("method", "GET")
    if method == "OPTIONS" and (path.startswith("/oauth/") or path.startswith("/.well-known/")):
        await _send(send, 204, b""); return True
    if path.startswith("/.well-known/oauth-protected-resource"):
        await _send(send, 200, protected_resource()); return True
    if path.startswith("/.well-known/oauth-authorization-server") or path.startswith("/.well-known/openid-configuration"):
        await _send(send, 200, as_metadata()); return True
    hdr = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
    qs = scope.get("query_string", b"").decode()
    HTML = "text/html; charset=utf-8"
    SEC = {"x-frame-options": "DENY", "content-security-policy": "frame-ancestors 'none'"}

    if path == "/oauth/register" and method == "POST":
        meta = _form(await _body(receive), hdr.get("content-type", "application/json"))
        uris = meta.get("redirect_uris") or []
        if not uris or not all(isinstance(u, str) and (u.startswith("https://") or u.startswith("http://localhost") or u.startswith("http://127.0.0.1")) for u in uris):
            await _send(send, 400, {"error": "invalid_redirect_uri"}); return True
        cid = "wsc_" + secrets.token_urlsafe(16)
        rec = {"client_id": cid, "client_name": str(meta.get("client_name") or "Claude")[:80], "redirect_uris": uris,
               "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
               "client_id_issued_at": int(time.time())}
        with _lock:
            c = _load("clients"); c[cid] = rec; _save("clients", c)
        await _send(send, 201, rec); return True

    if path == "/oauth/authorize" and method == "GET":
        q = {k: v[0] for k, v in urllib.parse.parse_qs(qs).items()}
        client = _load("clients").get(q.get("client_id", ""))
        if not client or not _redirect_ok(client, q.get("redirect_uri", "")):
            await _send(send, 400, _msg("Can't connect", "This connection request isn't recognised. Remove the Woodstitch connector in Claude and add it again."), HTML, SEC); return True
        if q.get("response_type") != "code" or q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
            await _send(send, 400, _msg("Can't connect", "This app asked in a way Woodstitch doesn't support (PKCE S256 required)."), HTML, SEC); return True
        rid = secrets.token_urlsafe(18)
        with _lock:
            p = _load("pending"); now = time.time()
            p = {k: v for k, v in p.items() if v["t"] > now - 1800}
            p[rid] = {"t": now, "q": q}; _save("pending", p)
        await _send(send, 302, b"", "text/plain", {"location": f"{SITE}/app/connect?r={rid}"}); return True

    # fallback: paste an API key
    if path == "/oauth/key":
        if method == "GET":
            rid = urllib.parse.parse_qs(qs).get("r", [""])[0]
            pend = _pending(rid)
            if not pend:
                await _send(send, 400, _msg("This sign-in expired", "Start the connection again from Claude."), HTML, SEC); return True
            await _send(send, 200, _page(rid, _redirect_host(pend["q"]["redirect_uri"])), HTML, SEC); return True
        f = _form(await _body(receive), hdr.get("content-type", ""))
        rid = f.get("req", ""); pend = _pending(rid)
        if not pend:
            await _send(send, 400, _msg("This sign-in expired", "Start the connection again from Claude."), HTML, SEC); return True
        k = (f.get("api_key") or "").strip()
        if not k.startswith(("ws_live_", "ws_test_")) or not _check_key(k):
            await _send(send, 200, _page(rid, _redirect_host(pend["q"]["redirect_uri"]), "That key wasn't recognised. Copy it again from woodstitch.com/app/api-keys."), HTML, SEC); return True
        await _send(send, 302, b"", "text/plain", {"location": _finish(rid, key=k)}); return True

    # internal: woodstitch.com/app/connect asks what is being connected, then grants or denies
    if path == "/oauth/internal/pending" and method == "GET":
        rid = urllib.parse.parse_qs(qs).get("r", [""])[0]
        if not _internal_ok(hdr, rid):
            await _send(send, 403, {"error": "forbidden"}); return True
        pend = _pending(rid)
        if not pend:
            await _send(send, 404, {"error": "expired"}); return True
        client = _load("clients").get(pend["q"]["client_id"], {})
        uri = pend["q"]["redirect_uri"]; host = _redirect_host(uri)
        await _send(send, 200, {"client_name": client.get("client_name", "Claude"), "redirect_host": host,
                                "loopback": host in ("localhost", "127.0.0.1")}); return True
    if path == "/oauth/internal/grant" and method == "POST":
        raw = (await _body(receive)).decode()
        if not _internal_ok(hdr, raw):
            await _send(send, 403, {"error": "forbidden"}); return True
        f = json.loads(raw or "{}")
        url = _finish(f.get("r", ""), key=f.get("key"), deny=bool(f.get("deny")))
        if not url:
            await _send(send, 404, {"error": "expired"}); return True
        await _send(send, 200, {"redirect": url}); return True

    if path == "/oauth/token" and method == "POST":
        f = _form(await _body(receive), hdr.get("content-type", ""))
        gt = f.get("grant_type")
        with _lock:
            if gt == "authorization_code":
                codes = _load("codes"); rec = codes.pop(_h(f.get("code", "")), None); _save("codes", codes)
                if not rec or rec["exp"] < time.time() or rec["client_id"] != f.get("client_id") or rec["redirect_uri"] != f.get("redirect_uri"):
                    await _send(send, 400, {"error": "invalid_grant"}); return True
                ver = f.get("code_verifier", "")
                chal = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
                if not ver or chal != rec["challenge"]:
                    await _send(send, 400, {"error": "invalid_grant", "error_description": "PKCE check failed"}); return True
                key, cid = rec["key"], rec["client_id"]
            elif gt == "refresh_token":
                toks = _load("refresh"); r = toks.pop(_h(f.get("refresh_token", "")), None)  # rotate: one use only
                if r and r.get("t", 0) < time.time() - REFRESH_TTL:
                    r = None
                if not r or (f.get("client_id") and f.get("client_id") != r["client_id"]):
                    await _send(send, 400, {"error": "invalid_grant"}); return True
                _save("refresh", toks)
                key, cid = r["key"], r["client_id"]
                if not _check_key(key, lenient=True):   # key revoked (e.g. "Revoke" in woodstitch.com/app/api-keys): connection ends
                    await _send(send, 400, {"error": "invalid_grant", "error_description": "access was revoked"}); return True
            else:
                await _send(send, 400, {"error": "unsupported_grant_type"}); return True
            access = "wsm_" + secrets.token_urlsafe(32); refresh = "wsr_" + secrets.token_urlsafe(32)
            t = _load("tokens"); now = time.time()
            t = {k: v for k, v in t.items() if v["exp"] > now}
            t[_h(access)] = {"key": key, "client_id": cid, "exp": now + ACCESS_TTL}; _save("tokens", t)
            r = _load("refresh"); r[_h(refresh)] = {"key": key, "client_id": cid, "t": now}; _save("refresh", r)
        await _send(send, 200, {"access_token": access, "token_type": "Bearer", "expires_in": ACCESS_TTL, "refresh_token": refresh, "scope": "woodstitch"})
        return True
    return False
