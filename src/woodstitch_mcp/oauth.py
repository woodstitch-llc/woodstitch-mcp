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
ACCESS_TTL = 365 * 86400
CODE_TTL = 600
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
PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Connect Woodstitch</title><style>
body{{margin:0;background:#F7F4F0;color:#17202B;font:16px/1.55 Manrope,Inter,system-ui,sans-serif}}
main{{max-width:460px;margin:48px auto;padding:0 16px}} .card{{background:#fff;border:1px solid #E3DAD2;border-radius:14px;padding:24px;margin:0 0 16px}}
h1{{font-size:24px;margin:0 0 6px}} p{{margin:0 0 14px;color:#5F6875}} label{{font-size:13px;font-weight:700;display:block;margin:0 0 6px}}
input{{width:100%;box-sizing:border-box;font:inherit;padding:10px 12px;border:1px solid #D5D9DF;border-radius:8px;margin:0 0 12px}}
button{{font:inherit;font-weight:700;border:0;border-radius:8px;padding:11px 16px;width:100%;cursor:pointer;background:#7E22CE;color:#fff}}
button.alt{{background:#17202B}} .err{{color:#B42318;font-weight:600}} small{{color:#8A919C}} a{{color:#7E22CE}}
</style></head><body><main>
<h1>Connect Woodstitch to {client}</h1>
<p>Paid US listeners judge your text-to-speech audio blind. Connecting lets {client} quote and run listening tests for you; nothing is charged without a quote you approve.</p>
{err}
<form class=card method=post><input type=hidden name=req value="{req}">
<label for=key>Use your API key</label><input id=key name=api_key placeholder="ws_live_..." autocomplete=off>
<button name=action value=key>Connect</button>
<p style="margin:10px 0 0"><small>Keys are at <a href="https://woodstitch.com/app/api-keys" target=_blank>woodstitch.com/app/api-keys</a>.</small></p></form>
<form class=card method=post><input type=hidden name=req value="{req}">
<label for=email>New to Woodstitch? Start with $25 of free credit</label><input id=email name=email type=email placeholder="you@company.com (optional)">
<button class=alt name=action value=trial>Create a trial account and connect</button></form>
<p><small>By connecting you agree to the <a href="https://woodstitch.com/legal/privacy" target=_blank>privacy policy</a>. Woodstitch LLC, Denver CO.</small></p>
</main></body></html>"""


def _page(req_id, client, err=""):
    return PAGE.format(client=html.escape(client or "Claude"), req=html.escape(req_id),
                       err=f'<p class=err>{html.escape(err)}</p>' if err else "")


def _redirect_ok(client, uri):
    return uri in client.get("redirect_uris", [])


def _check_key(key: str) -> bool:
    try:
        r = httpx.get(f"{API}/account", headers={"Authorization": f"Bearer {key}", "User-Agent": "woodstitch-mcp-oauth"}, timeout=20)
        return r.status_code == 200
    except Exception:
        return False


def _trial(email: str, client_name: str, ip: str):
    body = {"source": f"claude-connector:{client_name}"[:120]}
    if email:
        body["email"] = email
    try:
        r = httpx.post(f"{API}/start", json=body, headers={"User-Agent": "woodstitch-mcp-oauth", "X-Woodstitch-Client-IP": ip}, timeout=30)
        j = r.json()
        return j.get("api_key"), (None if j.get("api_key") else (j.get("error", {}) or {}).get("message") or f"HTTP {r.status_code}")
    except Exception as e:
        return None, str(e)


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
    ip = (hdr.get("x-forwarded-for") or "").split(",")[0].strip() or (scope.get("client") or ["", 0])[0]

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

    if path == "/oauth/authorize":
        if method == "GET":
            q = {k: v[0] for k, v in urllib.parse.parse_qs(scope.get("query_string", b"").decode()).items()}
            client = _load("clients").get(q.get("client_id", ""))
            if not client or not _redirect_ok(client, q.get("redirect_uri", "")):
                await _send(send, 400, "Unknown client or redirect URI. Remove and re-add the Woodstitch connector.", "text/plain"); return True
            if q.get("response_type") != "code" or q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
                await _send(send, 400, "PKCE S256 authorization-code flow required.", "text/plain"); return True
            rid = secrets.token_urlsafe(18)
            with _lock:
                p = _load("pending"); now = time.time()
                p = {k: v for k, v in p.items() if v["t"] > now - 1800}
                p[rid] = {"t": now, "q": q}; _save("pending", p)
            await _send(send, 200, _page(rid, client.get("client_name")), "text/html; charset=utf-8"); return True
        if method == "POST":
            f = _form(await _body(receive), hdr.get("content-type", ""))
            with _lock:
                pend = _load("pending").get(f.get("req", ""))
            if not pend:
                await _send(send, 400, "This sign-in page expired. Start the connection again from Claude.", "text/plain"); return True
            q = pend["q"]; client = _load("clients").get(q["client_id"], {})
            key, err = None, ""
            if f.get("action") == "key":
                k = (f.get("api_key") or "").strip()
                if not k.startswith(("ws_live_", "ws_test_")) or not _check_key(k):
                    err = "That key was not recognised. Copy it again from woodstitch.com/app/api-keys."
                else:
                    key = k
            else:
                key, e = _trial((f.get("email") or "").strip(), client.get("client_name", "Claude"), ip)
                if not key:
                    err = f"Could not create a trial account ({e}). Try again, or use an API key."
            if not key:
                await _send(send, 200, _page(f.get("req", ""), client.get("client_name"), err), "text/html; charset=utf-8"); return True
            code = secrets.token_urlsafe(32)
            with _lock:
                p = _load("pending"); p.pop(f.get("req", ""), None); _save("pending", p)
                c = _load("codes"); now = time.time()
                c = {k: v for k, v in c.items() if v["exp"] > now}
                c[_h(code)] = {"exp": now + CODE_TTL, "key": key, "client_id": q["client_id"], "redirect_uri": q["redirect_uri"],
                               "challenge": q["code_challenge"]}
                _save("codes", c)
            sep = "&" if "?" in q["redirect_uri"] else "?"
            loc = q["redirect_uri"] + sep + urllib.parse.urlencode({"code": code, **({"state": q["state"]} if q.get("state") else {})})
            await _send(send, 302, b"", "text/plain", {"location": loc}); return True

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
                if not r or (f.get("client_id") and f.get("client_id") != r["client_id"]):
                    await _send(send, 400, {"error": "invalid_grant"}); return True
                _save("refresh", toks)
                key, cid = r["key"], r["client_id"]
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
