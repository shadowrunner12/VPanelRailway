"""
Simple VLESS-over-WebSocket gateway + single-admin panel.
Designed to run as a normal web service on Render / Railway free tiers.

Scope (intentionally kept small):
  - VLESS only, WebSocket transport only.
  - Single admin (one password, no accounts, no rate limiting).
  - Traffic is counted per link but never enforced (informational only).
  - No Telegram bot, no third-party API integrations, no auto-update checks.
"""

import asyncio
import base64
import hashlib
import html
import os
import secrets
import socket
import sqlite3
import time
import uuid as uuidlib
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# ──────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────

DB_PATH = os.environ.get("DB_PATH", "panel.db")
ADMIN_PASSWORD_DEFAULT = os.environ.get("ADMIN_PASSWORD", "admin")
SESSION_COOKIE = "session"
SESSION_TTL = 60 * 60 * 24 * 30  # 30 days
RELAY_BUF = 64 * 1024
UNLIMITED_QUOTA_BYTES = 0  # 0 == unlimited in our schema

app = FastAPI(title="VLESS Panel", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ──────────────────────────────────────────────────────────────────────────
# Storage: a single sqlite connection + in-memory caches.
# Traffic counters live in memory and are flushed to disk periodically,
# so a normal proxied packet never triggers a disk write.
# ──────────────────────────────────────────────────────────────────────────

_db = sqlite3.connect(DB_PATH, check_same_thread=False)
_db.execute("PRAGMA journal_mode=WAL")
DB_LOCK = asyncio.Lock()

LINKS: dict[str, dict] = {}
LINKS_LOCK = asyncio.Lock()
ADDRESSES: list[str] = []
ADDR_LOCK = asyncio.Lock()
AUTH = {"password_hash": ""}

# active connections, kept only for the max-connections-per-link check
CONNECTIONS: dict[str, dict] = {}
CONN_LOCK = asyncio.Lock()

DIRTY_LINKS: set[str] = set()  # uids with usage changes not yet flushed to disk


def init_db():
    _db.executescript(
        """
        CREATE TABLE IF NOT EXISTS links (
            uid TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            limit_bytes INTEGER NOT NULL DEFAULT 0,
            used_bytes INTEGER NOT NULL DEFAULT 0,
            max_connections INTEGER NOT NULL DEFAULT 0,
            expires_at TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT UNIQUE NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            expires_at REAL NOT NULL
        );
        """
    )
    _db.commit()


def load_state():
    cur = _db.execute("SELECT uid, label, limit_bytes, used_bytes, max_connections, expires_at, active, created_at FROM links")
    for row in cur.fetchall():
        uid, label, limit_bytes, used_bytes, max_conn, expires_at, active, created_at = row
        LINKS[uid] = {
            "uid": uid,
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": used_bytes,
            "max_connections": max_conn,
            "expires_at": expires_at,
            "active": bool(active),
            "created_at": created_at,
        }

    cur = _db.execute("SELECT address FROM addresses ORDER BY id")
    ADDRESSES.extend(r[0] for r in cur.fetchall())

    row = _db.execute("SELECT value FROM settings WHERE key='password_hash'").fetchone()
    if row is None:
        AUTH["password_hash"] = hash_password(ADMIN_PASSWORD_DEFAULT)
        _db.execute("INSERT INTO settings (key, value) VALUES ('password_hash', ?)", (AUTH["password_hash"],))
        _db.commit()
    else:
        AUTH["password_hash"] = row[0]


async def flush_dirty_links():
    """Persist in-memory usage counters for links that changed since the last flush."""
    async with LINKS_LOCK:
        if not DIRTY_LINKS:
            return
        uids = list(DIRTY_LINKS)
        DIRTY_LINKS.clear()
        rows = [(LINKS[u]["used_bytes"], u) for u in uids if u in LINKS]
    if not rows:
        return
    async with DB_LOCK:
        _db.executemany("UPDATE links SET used_bytes = ? WHERE uid = ?", rows)
        _db.commit()


async def periodic_flush():
    while True:
        await asyncio.sleep(30)
        try:
            await flush_dirty_links()
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────────
# Auth
# ──────────────────────────────────────────────────────────────────────────

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with DB_LOCK:
        _db.execute("INSERT INTO sessions (token, expires_at) VALUES (?, ?)", (token, time.time() + SESSION_TTL))
        _db.commit()
    return token


async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with DB_LOCK:
        row = _db.execute("SELECT expires_at FROM sessions WHERE token = ?", (token,)).fetchone()
    return bool(row and row[0] > time.time())


async def destroy_session(token: str | None):
    if not token:
        return
    async with DB_LOCK:
        _db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        _db.commit()


async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="not authenticated")


# ──────────────────────────────────────────────────────────────────────────
# Link helpers
# ──────────────────────────────────────────────────────────────────────────

def parse_expires_at(raw: str | None):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = (unit or "GB").upper()
    mult = {"MB": 1024**2, "GB": 1024**3, "TB": 1024**4}.get(unit, 1024**3)
    return int(value * mult)


def get_domain(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-host")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.headers.get("host", "localhost")


def get_client_ip(request_or_ws) -> str:
    headers = request_or_ws.headers
    fwd = headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    client = getattr(request_or_ws, "client", None)
    return client.host if client else "unknown"


def generate_vless_link(uid: str, label: str, address: str, sni_host: str | None = None, tag: str | None = None) -> str:
    """address is what the client actually connects to (your domain, or a clean IP).
    sni_host is what gets presented as the TLS SNI / WS Host header — this must stay
    your real domain even when address is a clean IP, or the TLS handshake and the
    platform's Host-based routing both break."""
    sni_host = sni_host or address
    path = f"/ws/{uid}"
    remark = f"VPN-{label}" + (f"-{tag}" if tag else "")
    return (
        f"vless://{uid}@{address}:443?encryption=none&security=tls&type=ws"
        f"&host={sni_host}&path={path}&sni={sni_host}&fp=chrome&alpn=http%2F1.1"
        f"#{remark.replace(' ', '_')}"
    )


def links_for_all_addresses(link: dict, domain: str, addresses: list[str]) -> list[str]:
    out = [generate_vless_link(link["uid"], link["label"], domain)]
    for addr in addresses:
        # connect to the clean IP/host, but keep SNI/Host pointed at the real domain
        out.append(generate_vless_link(link["uid"], link["label"], addr, sni_host=domain, tag=addr))
    return out


async def count_connections_for_link(uid: str) -> int:
    async with CONN_LOCK:
        return sum(1 for c in CONNECTIONS.values() if c["uid"] == uid)


# ──────────────────────────────────────────────────────────────────────────
# VLESS parsing + relay
# ──────────────────────────────────────────────────────────────────────────

async def parse_vless_header(first_chunk: bytes):
    """Parse a VLESS request header. Returns (address, port, remaining_payload).
    The UUID embedded in the header is not compared against anything — auth
    is the secret uid in the URL path, consistent with how the link is issued."""
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1 + 16  # version byte + uuid
    addon_len = first_chunk[pos]
    pos += 1 + addon_len
    pos += 1  # command byte
    port = int.from_bytes(first_chunk[pos:pos + 2], "big")
    pos += 2
    addr_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]
        pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]
        pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return address, port, first_chunk[pos:]


async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n
            DIRTY_LINKS.add(uid)


async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            await add_usage(link_uid, len(data))
            try:
                writer.write(data)
                await writer.drain()
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        try:
            if not writer.is_closing():
                writer.write_eof()
        except Exception:
            pass


async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            await add_usage(link_uid, len(data))
            try:
                # VLESS response prefix: version(0x00) + no addons(0x00), once.
                await websocket.send_bytes((b"\x00\x00" + data) if first else data)
                first = False
            except Exception:
                break
    except Exception:
        pass


@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
        if link is None or not link["active"]:
            await websocket.close(code=1008)
            return
        max_conn = link["max_connections"]

    expires_at = parse_expires_at(link.get("expires_at"))
    if expires_at is not None and expires_at < datetime.now(timezone.utc):
        await websocket.close(code=1008)
        return

    if max_conn > 0 and await count_connections_for_link(uuid) >= max_conn:
        await websocket.close(code=1008)
        return

    # Early data: some clients (v2rayNG etc, "?ed=2048" links) pack the first
    # VLESS request chunk into the Sec-WebSocket-Protocol header of the
    # upgrade request itself instead of sending it after accept().
    early_data_hdr = websocket.headers.get("sec-websocket-protocol")
    early_data = b""
    if early_data_hdr:
        try:
            padded = early_data_hdr + "=" * (-len(early_data_hdr) % 4)
            early_data = base64.urlsafe_b64decode(padded)
        except Exception:
            early_data = b""

    await websocket.accept(subprotocol=early_data_hdr if early_data_hdr else None)

    writer = None
    conn_id = secrets.token_urlsafe(8)
    client_ip = get_client_ip(websocket)

    try:
        if early_data:
            first_chunk = early_data
        else:
            first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
            if first_msg["type"] == "websocket.disconnect":
                return
            first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
            if not first_chunk:
                return

        try:
            address, port, initial_payload = await parse_vless_header(first_chunk)
        except ValueError:
            await websocket.close(code=1008, reason="invalid header")
            return

        async with CONN_LOCK:
            CONNECTIONS[conn_id] = {"uid": uuid, "ip": client_ip}

        await add_usage(uuid, len(first_chunk))

        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        try:
            sock = writer.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass

        if initial_payload:
            await add_usage(uuid, len(initial_payload))
            try:
                writer.write(initial_payload)
                await writer.drain()
            except Exception:
                pass

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

    except (WebSocketDisconnect, asyncio.TimeoutError, ConnectionError, OSError):
        pass
    except Exception:
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        async with CONN_LOCK:
            CONNECTIONS.pop(conn_id, None)


# ──────────────────────────────────────────────────────────────────────────
# Subscription endpoint — browsers get a landing page, VPN clients get the
# base64 subscription body. This is ordinary client-detection UX (the same
# thing any subscription-based proxy panel does), not traffic obfuscation.
# ──────────────────────────────────────────────────────────────────────────

KNOWN_CLIENT_MARKERS = [
    "hiddify", "napsternet", "v2rayng", "v2box", "nekoray", "nekobox",
    "sing-box", "singbox", "streisand", "karing", "shadowrocket",
    "quantumult", "surge", "loon", "clash", "stash", "verge", "okhttp",
]


def render_landing_page(link: dict, uid: str, domain: str) -> str:
    sub_url = f"https://{domain}/sub/{uid}"
    vless_url = generate_vless_link(uid, link["label"], domain)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(link['label'])}</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;background:#0f1117;color:#e6e6e6;display:flex;
min-height:100vh;align-items:center;justify-content:center;margin:0;padding:20px}}
.card{{background:#171a23;border-radius:16px;padding:32px;max-width:440px;width:100%;box-shadow:0 8px 30px rgba(0,0,0,.3)}}
h1{{font-size:20px;margin:0 0 6px}}
p{{color:#9aa0ac;font-size:14px;line-height:1.5}}
.box{{background:#0f1117;border:1px solid #262a35;border-radius:10px;padding:12px;font-family:monospace;
font-size:12px;word-break:break-all;margin:14px 0}}
button{{background:#5b6cff;color:#fff;border:0;border-radius:8px;padding:10px 16px;font-size:14px;
cursor:pointer;width:100%;margin-top:6px}}
button:hover{{background:#4756e0}}
.label{{font-size:12px;color:#9aa0ac;margin:14px 0 4px;text-transform:uppercase;letter-spacing:.04em}}
</style></head>
<body>
<div class="card">
<h1>{html.escape(link['label'])}</h1>
<p>Add this subscription link to a VLESS-capable client (v2rayNG, Hiddify, NekoBox, Streisand, etc.).</p>
<div class="label">Subscription URL</div>
<div class="box" id="sub">{html.escape(sub_url)}</div>
<button onclick="copy('sub')">Copy subscription link</button>
<div class="label">Single config (direct)</div>
<div class="box" id="cfg">{html.escape(vless_url)}</div>
<button onclick="copy('cfg')">Copy config</button>
</div>
<script>
function copy(id) {{
  navigator.clipboard.writeText(document.getElementById(id).textContent);
}}
</script>
</body></html>"""


@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="not found")
        link = dict(link)

    if not link["active"]:
        raise HTTPException(status_code=403, detail="disabled")

    expires_at = parse_expires_at(link.get("expires_at"))
    if expires_at is not None and expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="expired")

    domain = get_domain(request)
    ua = request.headers.get("user-agent", "").lower()
    accept = request.headers.get("accept", "").lower()

    is_known_client = any(m in ua for m in KNOWN_CLIENT_MARKERS)
    is_browser = (not is_known_client) and any(x in ua for x in ["mozilla", "chrome", "safari", "opera", "edge"]) and "text/html" in accept

    if is_browser:
        return HTMLResponse(content=render_landing_page(link, uid, domain))

    async with ADDR_LOCK:
        addresses = list(ADDRESSES)
    lines = links_for_all_addresses(link, domain, addresses)
    encoded = base64.b64encode("\n".join(lines).encode()).decode()

    total_bytes = link["limit_bytes"] if link["limit_bytes"] > 0 else UNLIMITED_QUOTA_BYTES
    expire_ts = int(expires_at.timestamp()) if expires_at else 0
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "profile-update-interval": "6",
        "profile-title": "base64:" + base64.b64encode(f"VPN-{link['label']}".encode()).decode(),
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={total_bytes}; expire={expire_ts}",
    }
    return Response(content=encoded, headers=headers)


# ──────────────────────────────────────────────────────────────────────────
# Panel API
# ──────────────────────────────────────────────────────────────────────────

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp


@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/api/me")
async def api_me(request: Request):
    return {"authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE))}


@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    async with DB_LOCK:
        _db.execute("UPDATE settings SET value = ? WHERE key = 'password_hash'", (AUTH["password_hash"],))
        _db.execute("DELETE FROM sessions")
        _db.commit()
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp


def link_public(link: dict, domain: str) -> dict:
    d = dict(link)
    d["vless_url"] = generate_vless_link(link["uid"], link["label"], domain)
    d["sub_url"] = f"https://{domain}/sub/{link['uid']}"
    return d


@app.get("/api/links")
async def list_links(request: Request, _=Depends(require_auth)):
    domain = get_domain(request)
    async with LINKS_LOCK:
        links = [link_public(l, domain) for l in LINKS.values()]
    links.sort(key=lambda l: l["created_at"], reverse=True)
    return {"links": links}


@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = str(body.get("label") or "link").strip()[:64] or "link"
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = str(body.get("limit_unit") or "GB")
    limit_bytes = parse_size_to_bytes(limit_value, limit_unit) if limit_value > 0 else 0
    max_connections = int(body.get("max_connections") or 0)
    days_valid = int(body.get("days_valid") or 0)
    expires_at = None
    if days_valid > 0:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=days_valid)).isoformat()

    uid = str(uuidlib.uuid4())
    row = {
        "uid": uid,
        "label": label,
        "limit_bytes": limit_bytes,
        "used_bytes": 0,
        "max_connections": max_connections,
        "expires_at": expires_at,
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    async with LINKS_LOCK:
        LINKS[uid] = row
    async with DB_LOCK:
        _db.execute(
            "INSERT INTO links (uid, label, limit_bytes, used_bytes, max_connections, expires_at, active, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (uid, label, limit_bytes, 0, max_connections, expires_at, 1, row["created_at"]),
        )
        _db.commit()
    return link_public(row, get_domain(request))


@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="not found")
        if "active" in body:
            link["active"] = bool(body["active"])
        if "label" in body:
            link["label"] = str(body["label"]).strip()[:64] or link["label"]
        if "max_connections" in body:
            link["max_connections"] = int(body["max_connections"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = str(body.get("limit_unit") or "GB")
            link["limit_bytes"] = parse_size_to_bytes(limit_value, limit_unit) if limit_value > 0 else 0
        if "days_valid" in body:
            days_valid = int(body.get("days_valid") or 0)
            link["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=days_valid)).isoformat() if days_valid > 0 else None
        if "reset_usage" in body and body["reset_usage"]:
            link["used_bytes"] = 0
        snapshot = dict(link)
    async with DB_LOCK:
        _db.execute(
            "UPDATE links SET label=?, limit_bytes=?, used_bytes=?, max_connections=?, expires_at=?, active=? WHERE uid=?",
            (snapshot["label"], snapshot["limit_bytes"], snapshot["used_bytes"], snapshot["max_connections"],
             snapshot["expires_at"], int(snapshot["active"]), uid),
        )
        _db.commit()
    return link_public(snapshot, get_domain(request))


@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
        DIRTY_LINKS.discard(uid)
    async with DB_LOCK:
        _db.execute("DELETE FROM links WHERE uid=?", (uid,))
        _db.commit()
    return {"ok": True}


@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with ADDR_LOCK:
        return {"addresses": list(ADDRESSES)}


def _split_addresses_blob(raw: str) -> list[str]:
    # accepts one-per-line, comma-separated, or a mix of both
    parts = []
    for line in raw.splitlines():
        parts.extend(p.strip() for p in line.split(","))
    return [p for p in parts if p]


@app.post("/api/addresses")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    # "addresses" (bulk, newline/comma separated) and "address" (single) both accepted
    raw = body.get("addresses")
    if raw is None:
        raw = body.get("address") or ""
    candidates = _split_addresses_blob(str(raw))
    if not candidates:
        raise HTTPException(status_code=400, detail="at least one address required")
    async with ADDR_LOCK:
        added = 0
        for address in candidates:
            if address not in ADDRESSES:
                ADDRESSES.append(address)
                added += 1
        if added:
            async with DB_LOCK:
                _db.executemany("INSERT OR IGNORE INTO addresses (address) VALUES (?)", [(a,) for a in candidates])
                _db.commit()
        return {"addresses": list(ADDRESSES), "added": added}


@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with ADDR_LOCK:
        if 0 <= index < len(ADDRESSES):
            addr = ADDRESSES.pop(index)
            async with DB_LOCK:
                _db.execute("DELETE FROM addresses WHERE address=?", (addr,))
                _db.commit()
        return {"addresses": list(ADDRESSES)}


@app.delete("/api/addresses")
async def delete_all_addresses(_=Depends(require_auth)):
    async with ADDR_LOCK:
        ADDRESSES.clear()
    async with DB_LOCK:
        _db.execute("DELETE FROM addresses")
        _db.commit()
    return {"addresses": []}


def _parse_ip_file(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


@app.post("/api/addresses/import/{source}")
async def import_addresses(source: str, _=Depends(require_auth)):
    if source != "railway":
        raise HTTPException(status_code=400, detail="unknown source")
    candidates = _parse_ip_file("railway_ips.txt")
    async with ADDR_LOCK:
        added = 0
        for c in candidates:
            if c not in ADDRESSES:
                ADDRESSES.append(c)
                added += 1
        if added:
            async with DB_LOCK:
                _db.executemany("INSERT OR IGNORE INTO addresses (address) VALUES (?)", [(c,) for c in candidates])
                _db.commit()
        return {"addresses": list(ADDRESSES), "added": added}


# ──────────────────────────────────────────────────────────────────────────
# Static-ish pages
# ──────────────────────────────────────────────────────────────────────────

HOME_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Service</title>
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="font-family:system-ui,sans-serif;background:#0f1117;color:#e6e6e6;
display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">
<div style="text-align:center">
<h2 style="font-weight:500">Service running</h2>
</div>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
async def root():
    return HOME_HTML


@app.get("/health")
async def health():
    return {"status": "ok"}


LOGIN_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f1117;color:#e6e6e6;display:flex;min-height:100vh;
align-items:center;justify-content:center;margin:0}
.card{background:#171a23;padding:32px;border-radius:16px;width:280px}
h1{font-size:18px;margin:0 0 18px}
input{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #262a35;
background:#0f1117;color:#e6e6e6;margin-bottom:12px;font-size:14px}
button{width:100%;padding:10px;border-radius:8px;border:0;background:#5b6cff;color:#fff;
font-size:14px;cursor:pointer}
button:hover{background:#4756e0}
.err{color:#ff6b6b;font-size:13px;margin-bottom:10px;min-height:16px}
</style></head>
<body>
<form class="card" id="f">
<h1>Sign in</h1>
<div class="err" id="err"></div>
<input type="password" id="pw" placeholder="Password" autofocus>
<button type="submit">Sign in</button>
</form>
<script>
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = document.getElementById('pw').value;
  const res = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({password: pw})});
  if (res.ok) { window.location = '/dashboard'; }
  else { document.getElementById('err').textContent = 'Invalid password'; }
});
</script>
</body></html>"""


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return LOGIN_HTML


DASHBOARD_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Panel</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{font-family:system-ui,sans-serif;background:#0f1117;color:#e6e6e6;margin:0}
header{display:flex;justify-content:space-between;align-items:center;padding:16px 24px;
border-bottom:1px solid #1f232e}
header h1{font-size:16px;font-weight:600;margin:0}
main{max-width:960px;margin:0 auto;padding:24px}
.row{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
h2{font-size:15px;margin:28px 0 12px}
button{background:#5b6cff;color:#fff;border:0;border-radius:8px;padding:8px 14px;font-size:13px;cursor:pointer}
button.secondary{background:#232735}
button.danger{background:#a33}
button:hover{opacity:.9}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:10px;border-bottom:1px solid #1f232e}
th{color:#9aa0ac;font-weight:500;font-size:12px;text-transform:uppercase}
.pill{padding:2px 8px;border-radius:99px;font-size:11px}
.pill.on{background:#1e3a2a;color:#4ade80}
.pill.off{background:#3a1e1e;color:#f87171}
.actions button{margin-right:6px;padding:5px 10px;font-size:12px}
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);align-items:center;justify-content:center}
.modal-bg.show{display:flex}
.modal{background:#171a23;border-radius:14px;padding:24px;width:360px;max-width:90vw}
.modal h3{margin:0 0 16px;font-size:15px}
.modal label{font-size:12px;color:#9aa0ac;display:block;margin:10px 0 4px}
.modal input,.modal select{width:100%;padding:8px;border-radius:8px;border:1px solid #262a35;
background:#0f1117;color:#e6e6e6;font-size:13px}
.modal .btns{display:flex;gap:8px;margin-top:18px}
.addr-list{display:flex;flex-direction:column;gap:6px;margin-bottom:12px}
.addr-item{display:flex;justify-content:space-between;align-items:center;background:#171a23;
padding:8px 12px;border-radius:8px;font-size:13px;font-family:monospace}
.small{font-size:12px;color:#9aa0ac}
</style></head>
<body>
<header>
<h1>VPN Panel</h1>
<button class="secondary" onclick="logout()">Logout</button>
</header>
<main>
<div class="row">
<h2 style="margin:0">Links</h2>
<button onclick="openLinkModal()">+ Add link</button>
</div>
<table id="linksTable">
<thead><tr><th>Label</th><th>Used</th><th>Limit</th><th>Status</th><th>Expires</th><th>Actions</th></tr></thead>
<tbody></tbody>
</table>

<h2>Clean IP / alternative addresses</h2>
<div class="row">
<span class="small">Appended as extra config lines in every subscription.</span>
<div>
<button class="secondary" onclick="importRailway()">Import railway_ips.txt</button>
<button class="danger" onclick="clearAddresses()">Clear all</button>
</div>
</div>
<div class="addr-list" id="addrList"></div>
<div style="display:flex;gap:8px;align-items:flex-start">
<textarea id="newAddr" rows="3" placeholder="One per line, e.g.&#10;1.2.3.4&#10;5.6.7.8&#10;clean.example.com"
style="flex:1;padding:8px;border-radius:8px;border:1px solid #262a35;background:#171a23;color:#e6e6e6;
font-family:monospace;font-size:13px;resize:vertical"></textarea>
<button onclick="addAddress()">Add</button>
</div>
</main>

<div class="modal-bg" id="linkModalBg">
<div class="modal">
<h3 id="linkModalTitle">New link</h3>
<input type="hidden" id="editUid">
<label>Label</label>
<input id="lLabel" placeholder="e.g. my-phone">
<label>Traffic limit (0 = unlimited)</label>
<div style="display:flex;gap:8px">
<input id="lLimit" type="number" min="0" value="0" style="flex:2">
<select id="lLimitUnit" style="flex:1"><option>GB</option><option>MB</option><option>TB</option></select>
</div>
<label>Max simultaneous connections (0 = unlimited)</label>
<input id="lMaxConn" type="number" min="0" value="0">
<label>Valid for (days, 0 = never expires)</label>
<input id="lDays" type="number" min="0" value="0">
<div class="btns">
<button class="secondary" onclick="closeLinkModal()">Cancel</button>
<button onclick="saveLink()">Save</button>
</div>
</div>
</div>

<div class="modal-bg" id="viewModalBg">
<div class="modal" style="width:420px">
<h3>Config</h3>
<label>Subscription URL</label>
<input id="viewSub" readonly onclick="this.select()">
<label>Direct config</label>
<input id="viewCfg" readonly onclick="this.select()">
<div class="btns">
<button class="secondary" onclick="closeViewModal()">Close</button>
<button onclick="copyView()">Copy config</button>
</div>
</div>
</div>

<script>
async function api(path, opts) {
  const res = await fetch(path, Object.assign({headers:{'Content-Type':'application/json'}}, opts || {}));
  if (res.status === 401) { window.location = '/login'; throw new Error('unauth'); }
  return res.json();
}

function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B','KB','MB','GB','TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(1) + ' ' + u[i];
}

async function loadLinks() {
  const data = await api('/api/links');
  const tbody = document.querySelector('#linksTable tbody');
  tbody.innerHTML = '';
  for (const l of data.links) {
    const limit = l.limit_bytes > 0 ? fmtBytes(l.limit_bytes) : 'Unlimited';
    const expires = l.expires_at ? new Date(l.expires_at).toLocaleDateString() : 'Never';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${l.label}</td>
      <td>${fmtBytes(l.used_bytes)}</td>
      <td>${limit}</td>
      <td><span class="pill ${l.active ? 'on' : 'off'}">${l.active ? 'Active' : 'Disabled'}</span></td>
      <td>${expires}</td>
      <td class="actions">
        <button class="secondary" onclick='viewLink(${JSON.stringify(l)})'>View</button>
        <button class="secondary" onclick='editLink(${JSON.stringify(l)})'>Edit</button>
        <button class="secondary" onclick="toggleLink('${l.uid}', ${!l.active})">${l.active ? 'Disable' : 'Enable'}</button>
        <button class="danger" onclick="deleteLink('${l.uid}')">Delete</button>
      </td>`;
    tbody.appendChild(tr);
  }
}

function openLinkModal() {
  document.getElementById('linkModalTitle').textContent = 'New link';
  document.getElementById('editUid').value = '';
  document.getElementById('lLabel').value = '';
  document.getElementById('lLimit').value = 0;
  document.getElementById('lMaxConn').value = 0;
  document.getElementById('lDays').value = 0;
  document.getElementById('linkModalBg').classList.add('show');
}
function closeLinkModal() { document.getElementById('linkModalBg').classList.remove('show'); }

function editLink(l) {
  document.getElementById('linkModalTitle').textContent = 'Edit link';
  document.getElementById('editUid').value = l.uid;
  document.getElementById('lLabel').value = l.label;
  document.getElementById('lLimit').value = 0;
  document.getElementById('lMaxConn').value = l.max_connections;
  document.getElementById('lDays').value = 0;
  document.getElementById('linkModalBg').classList.add('show');
}

async function saveLink() {
  const uid = document.getElementById('editUid').value;
  const body = {
    label: document.getElementById('lLabel').value,
    limit_value: Number(document.getElementById('lLimit').value),
    limit_unit: document.getElementById('lLimitUnit').value,
    max_connections: Number(document.getElementById('lMaxConn').value),
    days_valid: Number(document.getElementById('lDays').value),
  };
  if (uid) {
    await api('/api/links/' + uid, {method: 'PATCH', body: JSON.stringify(body)});
  } else {
    await api('/api/links', {method: 'POST', body: JSON.stringify(body)});
  }
  closeLinkModal();
  loadLinks();
}

async function toggleLink(uid, active) {
  await api('/api/links/' + uid, {method: 'PATCH', body: JSON.stringify({active})});
  loadLinks();
}

async function deleteLink(uid) {
  if (!confirm('Delete this link? This cannot be undone.')) return;
  await api('/api/links/' + uid, {method: 'DELETE'});
  loadLinks();
}

function viewLink(l) {
  document.getElementById('viewSub').value = l.sub_url;
  document.getElementById('viewCfg').value = l.vless_url;
  document.getElementById('viewModalBg').classList.add('show');
}
function closeViewModal() { document.getElementById('viewModalBg').classList.remove('show'); }
function copyView() { navigator.clipboard.writeText(document.getElementById('viewCfg').value); }

async function loadAddresses() {
  const data = await api('/api/addresses');
  const box = document.getElementById('addrList');
  box.innerHTML = '';
  data.addresses.forEach((a, i) => {
    const div = document.createElement('div');
    div.className = 'addr-item';
    div.innerHTML = `<span>${a}</span><button class="danger" onclick="deleteAddress(${i})">Remove</button>`;
    box.appendChild(div);
  });
}

async function addAddress() {
  const input = document.getElementById('newAddr');
  const addresses = input.value.trim();
  if (!addresses) return;
  const res = await api('/api/addresses', {method: 'POST', body: JSON.stringify({addresses})});
  input.value = '';
  loadAddresses();
  if (res.added > 1) alert('Added ' + res.added + ' address(es).');
}

async function deleteAddress(i) {
  await api('/api/addresses/' + i, {method: 'DELETE'});
  loadAddresses();
}

async function clearAddresses() {
  if (!confirm('Remove all alternative addresses?')) return;
  await api('/api/addresses', {method: 'DELETE'});
  loadAddresses();
}

async function importRailway() {
  const res = await api('/api/addresses/import/railway', {method: 'POST'});
  loadAddresses();
  alert('Imported ' + res.added + ' new address(es).');
}

async function logout() {
  await api('/api/logout', {method: 'POST'});
  window.location = '/login';
}

(async function init() {
  const me = await api('/api/me');
  if (!me.authenticated) { window.location = '/login'; return; }
  loadLinks();
  loadAddresses();
})();
</script>
</body></html>"""


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    return DASHBOARD_HTML


# ──────────────────────────────────────────────────────────────────────────
# Lifecycle
# ──────────────────────────────────────────────────────────────────────────

async def keep_alive():
    """Self-ping every 9 minutes so free-tier hosts don't spin the service
    down from inactivity. This mirrors normal uptime-monitor traffic and is
    not tightened beyond what's needed for that purpose."""
    await asyncio.sleep(30)
    domain = os.environ.get("SELF_URL")  # optional explicit override
    while True:
        try:
            import httpx
            url = domain or f"http://127.0.0.1:{os.environ.get('PORT', '8000')}/health"
            async with httpx.AsyncClient(timeout=10) as client:
                await client.get(url)
        except Exception:
            pass
        await asyncio.sleep(9 * 60)


@app.on_event("startup")
async def startup():
    init_db()
    load_state()
    asyncio.create_task(periodic_flush())
    asyncio.create_task(keep_alive())


@app.on_event("shutdown")
async def shutdown():
    try:
        await flush_dirty_links()
    except Exception:
        pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
