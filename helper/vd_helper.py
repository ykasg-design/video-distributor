#!/usr/bin/env python3
"""Video Distributor local helper (Python stdlib only).

The publishing page (https://ykasg-design.github.io/video-distributor/publish.html)
is static, so it cannot hold the TikTok client secret. This helper runs on the
operator's own computer, keeps the secret and the access tokens there, and is the
only thing that talks to the TikTok API.

    python3 helper/vd_helper.py            # listens on http://127.0.0.1:8765

Secrets are read from $VD_SECRETS (default ~/.orca/bots/tiktok-2/secrets):
    tiktok-sandbox.env   TIKTOK_CLIENT_KEY / TIKTOK_CLIENT_SECRET / TIKTOK_REDIRECT_URI
    accounts/<user>.json tokens, same format as tools/tiktok_api.py
Nothing secret is ever sent to the browser: the page only gets an opaque session id.
"""
import base64, json, os, secrets, sys, threading, time, urllib.error, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SECRETS = Path(os.environ.get("VD_SECRETS", Path.home() / ".orca/bots/tiktok-2/secrets")).expanduser()
ENV_FILE = Path(os.environ.get("TIKTOK_ENV", SECRETS / "tiktok-sandbox.env"))
ACCTS = SECRETS / "accounts"
PORT = int(os.environ.get("VD_PORT", "8765"))
API = "https://open.tiktokapis.com"
SCOPES = "user.info.basic,video.upload,video.publish"
ALLOWED_ORIGINS = {"https://ykasg-design.github.io", "http://localhost:8000", "http://127.0.0.1:8000"}
MAX_UPLOAD = 4 * 1024 ** 3

STATES = {}    # oauth state -> expiry
SESSIONS = {}  # session id -> {"account": name, "expires": ts}
LOCK = threading.Lock()


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def env():
    d = {}
    for line in ENV_FILE.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def tt(method, url, data=None, token=None, form=False, raw=None, headers=None):
    h = dict(headers or {})
    body = raw
    if token:
        h["Authorization"] = "Bearer " + token
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            h["Content-Type"] = "application/json; charset=UTF-8"
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=300) as resp:
            txt = resp.read().decode() or "{}"
            st = resp.status
    except urllib.error.HTTPError as e:
        txt, st = e.read().decode(), e.code
    try:
        return st, json.loads(txt)
    except Exception:
        return st, {"raw": txt[:500]}


def save_account(tok):
    ACCTS.mkdir(parents=True, exist_ok=True, mode=0o700)
    tok["obtained_at"] = int(time.time())
    _, info = tt("GET", API + "/v2/user/info/?fields=open_id,display_name,avatar_url", token=tok["access_token"])
    user = (info.get("data") or {}).get("user") or {}
    _, ci = tt("POST", API + "/v2/post/publish/creator_info/query/", {}, token=tok["access_token"])
    user["creator_username"] = (ci.get("data") or {}).get("creator_username")
    name = user.get("creator_username") or user.get("display_name") or tok.get("open_id")
    name = "".join(c for c in name if c.isalnum() or c in "._-") or "account"
    tok["user"] = user
    p = ACCTS / f"{name}.json"
    p.write_text(json.dumps(tok, ensure_ascii=False, indent=1))
    os.chmod(p, 0o600)
    return name


def access_token(name):
    p = ACCTS / f"{name}.json"
    tok = json.loads(p.read_text())
    if time.time() > tok["obtained_at"] + tok.get("expires_in", 86400) - 300:
        e = env()
        st, new = tt("POST", API + "/v2/oauth/token/", {
            "client_key": e["TIKTOK_CLIENT_KEY"], "client_secret": e["TIKTOK_CLIENT_SECRET"],
            "grant_type": "refresh_token", "refresh_token": tok["refresh_token"]}, form=True)
        if "access_token" not in new:
            raise ApiError(401, "token_refresh_failed", "TikTok session expired, please connect again.")
        save_account(new)
        tok = json.loads(p.read_text())
    return tok["access_token"]


class ApiError(Exception):
    def __init__(self, status, code, message, extra=None):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra or {}


def tiktok_error(st, r):
    """Return (code, message, log_id) if a TikTok response is an error, else None."""
    err = r.get("error") or {}
    code = err.get("code")
    if st == 200 and code in (None, "", "ok"):
        return None
    return code or f"http_{st}", err.get("message") or r.get("raw") or "", err.get("log_id")


class Handler(BaseHTTPRequestHandler):
    server_version = "VDHelper/1.0"

    def log_message(self, fmt, *args):
        pass

    # ---- plumbing -------------------------------------------------------
    def origin_ok(self):
        o = self.headers.get("Origin")
        return o in ALLOWED_ORIGINS, o

    def cors(self, origin):
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def reply(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.cors(self.headers.get("Origin"))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def json_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1_000_000:
            raise ApiError(413, "too_large", "Request too large")
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise ApiError(400, "bad_json", "Invalid JSON")

    def session(self):
        auth = self.headers.get("Authorization", "")
        sid = auth[7:] if auth.startswith("Bearer ") else ""
        with LOCK:
            s = SESSIONS.get(sid)
            if not s or s["expires"] < time.time():
                SESSIONS.pop(sid, None)
                raise ApiError(401, "not_connected", "Not connected. Please continue with TikTok again.")
        return sid, s

    def do_OPTIONS(self):
        ok, origin = self.origin_ok()
        self.send_response(204 if ok else 403)
        if ok:
            self.cors(origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Post-Meta")
            self.send_header("Access-Control-Allow-Private-Network", "true")
            self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def dispatch(self, method):
        path = urllib.parse.urlparse(self.path).path
        ok, origin = self.origin_ok()
        if not ok and not (method == "GET" and path == "/health" and origin is None):
            return self.reply(403, {"error": {"code": "origin_not_allowed", "message": f"Origin {origin} not allowed"}})
        route = ROUTES.get((method, path))
        if not route:
            return self.reply(404, {"error": {"code": "not_found", "message": path}})
        try:
            self.reply(200, route(self))
        except ApiError as e:
            log("error", path, e.code, e.message)
            self.reply(e.status, {"error": {"code": e.code, "message": e.message, **e.extra}})
        except Exception as e:  # keep the helper alive, but never leak tokens in messages
            log("crash", path, type(e).__name__, e)
            self.reply(500, {"error": {"code": "helper_error", "message": type(e).__name__}})

    # ---- routes ---------------------------------------------------------
    def health(self):
        e = env()
        return {"ok": True, "app": "video-distributor-helper", "configured": bool(e.get("TIKTOK_CLIENT_KEY"))}

    def auth_start(self):
        e = env()
        state = secrets.token_urlsafe(24)
        with LOCK:
            now = time.time()
            for k in [k for k, v in STATES.items() if v < now]:
                del STATES[k]
            STATES[state] = now + 600
        q = {"client_key": e["TIKTOK_CLIENT_KEY"], "scope": SCOPES, "response_type": "code",
             "redirect_uri": e["TIKTOK_REDIRECT_URI"], "state": state, "disable_auto_auth": "1"}
        return {"url": "https://www.tiktok.com/v2/auth/authorize/?" + urllib.parse.urlencode(q), "state": state}

    def auth_exchange(self):
        b = self.json_body()
        state, code = b.get("state", ""), b.get("code", "")
        with LOCK:
            exp = STATES.pop(state, 0)
        if exp < time.time():
            raise ApiError(400, "bad_state", "Login link expired or was not started here. Please try again.")
        e = env()
        st, tok = tt("POST", API + "/v2/oauth/token/", {
            "client_key": e["TIKTOK_CLIENT_KEY"], "client_secret": e["TIKTOK_CLIENT_SECRET"], "code": code,
            "grant_type": "authorization_code", "redirect_uri": e["TIKTOK_REDIRECT_URI"]}, form=True)
        if "access_token" not in tok:
            raise ApiError(400, tok.get("error") or "exchange_failed", tok.get("error_description") or "Token exchange failed")
        name = save_account(tok)
        sid = secrets.token_urlsafe(32)
        with LOCK:
            SESSIONS[sid] = {"account": name, "expires": time.time() + 12 * 3600}
        log("connected", name, "scopes:", tok.get("scope"))
        return {"session": sid, "scope": tok.get("scope")}

    def me(self):
        _, s = self.session()
        token = access_token(s["account"])
        st, ci = tt("POST", API + "/v2/post/publish/creator_info/query/", {}, token=token)
        err = tiktok_error(st, ci)
        st2, ui = tt("GET", API + "/v2/user/info/?fields=open_id,display_name,avatar_url", token=token)
        user = (ui.get("data") or {}).get("user") or {}
        out = {"user": {"display_name": user.get("display_name"), "avatar_url": user.get("avatar_url")}}
        if err:
            out["creator_info_error"] = {"code": err[0], "message": err[1], "log_id": err[2]}
        else:
            out["creator_info"] = ci.get("data") or {}
        return out

    def logout(self):
        sid, _ = self.session()
        with LOCK:
            SESSIONS.pop(sid, None)
        return {"ok": True}

    def publish(self):
        _, s = self.session()
        try:
            meta = json.loads(base64.b64decode(self.headers.get("X-Post-Meta", "")).decode())
        except Exception:
            raise ApiError(400, "bad_meta", "Missing post settings")
        size = int(self.headers.get("Content-Length") or 0)
        if size <= 0 or size > MAX_UPLOAD:
            raise ApiError(400, "bad_video", "Video file is empty or larger than 4 GB")
        data = self.rfile.read(size)
        mode = meta.get("mode")
        chunk = size if size <= 64 * 1024 * 1024 else 10 * 1024 * 1024
        count = size // chunk
        src = {"source": "FILE_UPLOAD", "video_size": size, "chunk_size": chunk, "total_chunk_count": count}
        token = access_token(s["account"])
        if mode == "draft":
            st, r = tt("POST", API + "/v2/post/publish/inbox/video/init/", {"source_info": src}, token=token)
        elif mode == "direct":
            pi = meta.get("post_info") or {}
            post_info = {
                "title": str(pi.get("title", ""))[:2200],
                "privacy_level": pi.get("privacy_level"),
                "disable_comment": bool(pi.get("disable_comment")),
                "disable_duet": bool(pi.get("disable_duet")),
                "disable_stitch": bool(pi.get("disable_stitch")),
                "brand_content_toggle": bool(pi.get("brand_content_toggle")),
                "brand_organic_toggle": bool(pi.get("brand_organic_toggle")),
            }
            if not post_info["privacy_level"]:
                raise ApiError(400, "privacy_required", "Choose who can view this post")
            st, r = tt("POST", API + "/v2/post/publish/video/init/", {"post_info": post_info, "source_info": src}, token=token)
        else:
            raise ApiError(400, "bad_mode", "Unknown mode")
        err = tiktok_error(st, r)
        if err:
            raise ApiError(400 if st < 500 else 502, err[0], err[1], {"log_id": err[2], "stage": "init"})
        pid, up = r["data"]["publish_id"], r["data"]["upload_url"]
        log("init ok", mode, s["account"], pid, size, "bytes")
        for i in range(count):
            start = i * chunk
            end = size - 1 if i == count - 1 else start + chunk - 1
            st2, r2 = tt("PUT", up, raw=data[start:end + 1], headers={
                "Content-Type": "video/mp4", "Content-Length": str(end - start + 1),
                "Content-Range": f"bytes {start}-{end}/{size}"})
            if st2 not in (200, 201, 206):
                raise ApiError(502, "upload_failed", f"Upload chunk {i + 1}/{count} failed (HTTP {st2})",
                               {"stage": "upload", "publish_id": pid})
        return {"publish_id": pid, "mode": mode}

    def status(self):
        _, s = self.session()
        b = self.json_body()
        st, r = tt("POST", API + "/v2/post/publish/status/fetch/", {"publish_id": b.get("publish_id", "")},
                   token=access_token(s["account"]))
        err = tiktok_error(st, r)
        if err:
            raise ApiError(400, err[0], err[1], {"log_id": err[2]})
        return r.get("data") or {}


ROUTES = {
    ("GET", "/health"): Handler.health,
    ("POST", "/auth/start"): Handler.auth_start,
    ("POST", "/auth/exchange"): Handler.auth_exchange,
    ("GET", "/me"): Handler.me,
    ("POST", "/logout"): Handler.logout,
    ("POST", "/publish"): Handler.publish,
    ("POST", "/status"): Handler.status,
}

if __name__ == "__main__":
    if not ENV_FILE.exists():
        sys.exit(f"Missing {ENV_FILE}. Set VD_SECRETS or TIKTOK_ENV.")
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    log(f"Video Distributor helper on http://127.0.0.1:{PORT}  (secrets: {SECRETS})")
    dev = os.environ.get("VD_DEV_ACCOUNT")  # testing only: pre-open a session for an already saved account
    if dev and (ACCTS / f"{dev}.json").exists():
        sid = secrets.token_urlsafe(32)
        SESSIONS[sid] = {"account": dev, "expires": time.time() + 3600}
        log("dev session for", dev, "=", sid)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
