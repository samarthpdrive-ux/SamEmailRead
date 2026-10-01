#!/usr/bin/env python3
"""Render-ready Outlook/Hotmail Graph reader API.

The service stores encrypted refresh tokens and exposes two credential types:

* ADMIN_API_KEY: may register/list/remove accounts.
* Per-account API keys: may read only the mailbox they were issued for.

Mail is fetched on demand from Microsoft Graph. SQLite is used by default;
Render should mount a persistent disk at /var/data (see render.yaml).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, jsonify, request


APP_NAME = "outlook-mail-api"
GRAPH_URL = "https://graph.microsoft.com/v1.0"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
REQUEST_TIMEOUT = float(os.getenv("GRAPH_TIMEOUT_SECONDS", "20"))
MAX_LIMIT = 50
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

BASE_DIR = Path(__file__).resolve().parent


def resolve_database_path() -> Path:
    configured = Path(os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "outlook_api.db")))
    try:
        configured.parent.mkdir(parents=True, exist_ok=True)
        return configured
    except (PermissionError, OSError):
        # Render free services have no persistent disk. Fall back to the app's
        # writable ephemeral filesystem instead of failing during boot.
        fallback = BASE_DIR / "data" / "outlook_api.db"
        fallback.parent.mkdir(parents=True, exist_ok=True)
        print(f"Warning: cannot write {configured}; using temporary {fallback}")
        return fallback


DATABASE_PATH = resolve_database_path()

app = Flask(__name__)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_error(message: str, status: int = 400):
    return jsonify({"ok": False, "error": message}), status


def database() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    conn = database()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            client_id TEXT NOT NULL,
            refresh_token_enc TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'pending',
            error_msg TEXT,
            last_sync TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            last_used TEXT,
            revoked_at TEXT,
            FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            message_id TEXT NOT NULL,
            subject TEXT,
            from_name TEXT,
            from_address TEXT,
            received_at TEXT,
            preview TEXT,
            folder TEXT,
            is_read INTEGER NOT NULL DEFAULT 0,
            has_attachments INTEGER NOT NULL DEFAULT 0,
            is_new INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            UNIQUE(account_id, message_id),
            FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_emails_account_received
            ON emails(account_id, received_at DESC);
        CREATE INDEX IF NOT EXISTS idx_api_keys_hash
            ON api_keys(key_hash, revoked_at);
        """
    )
    conn.commit()
    conn.close()


def encryption() -> Fernet:
    """Return the token encryption key.

    APP_ENCRYPTION_KEY should be a Fernet key generated with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    For local development only, SECRET_KEY is deterministically converted to a
    Fernet key so the app can start without another setting.
    """
    configured = os.getenv("APP_ENCRYPTION_KEY", "").strip()
    if configured:
        try:
            return Fernet(configured.encode())
        except Exception as exc:
            raise RuntimeError("APP_ENCRYPTION_KEY is not a valid Fernet key") from exc
    seed = os.getenv("SECRET_KEY", "local-development-key-change-me").encode()
    derived = base64.urlsafe_b64encode(hashlib.sha256(seed).digest())
    return Fernet(derived)


def encrypt(value: str) -> str:
    return encryption().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    try:
        return encryption().decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Unable to decrypt refresh token; APP_ENCRYPTION_KEY changed") from exc


def hash_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def get_admin_key() -> str:
    return os.getenv("ADMIN_API_KEY", "").strip()


def supplied_key() -> str:
    value = request.headers.get("X-API-Key", "").strip()
    if value:
        return value
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def admin_authorized() -> bool:
    admin = get_admin_key()
    return bool(admin and supplied_key() and hmac.compare_digest(supplied_key(), admin))


def require_admin(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not get_admin_key():
            return json_error("ADMIN_API_KEY is not configured on this service", 503)
        if not admin_authorized():
            return json_error("Admin API key required", 401)
        return view(*args, **kwargs)

    return wrapped


def valid_email(value: Any) -> bool:
    return isinstance(value, str) and len(value.strip()) <= 320 and bool(EMAIL_RE.fullmatch(value.strip()))


def parse_account_line(value: str) -> tuple[str, str, str]:
    """Parse email----password----client_id----refresh_token.

    The password is deliberately discarded. The mail API only needs the
    Microsoft application client ID and Graph refresh token.
    """
    raw = (value or "").strip()
    for delimiter in ("----", "|"):
        parts = raw.split(delimiter, 3)
        if len(parts) == 4:
            email, _password, client_id, refresh_token = (part.strip() for part in parts)
            return email.lower(), client_id, refresh_token
    raise ValueError("Use email----password----client_id----refresh_token")


def account_public(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "email": row["email"],
        "status": row["status"],
        "enabled": bool(row["enabled"]),
        "last_sync": row["last_sync"],
        "created_at": row["created_at"],
        "error": row["error_msg"],
    }


def make_api_key() -> str:
    return "om_" + secrets.token_urlsafe(32)


def create_account_key(conn: sqlite3.Connection, account_id: int, label: str = "") -> str:
    raw = make_api_key()
    conn.execute(
        "INSERT INTO api_keys(account_id,key_hash,label,created_at) VALUES(?,?,?,?,?)",
        (account_id, hash_key(raw), label[:100], utc_now()),
    )
    return raw


def account_for_request(email: str) -> Optional[sqlite3.Row]:
    key = supplied_key()
    if not key:
        return None
    conn = database()
    row = conn.execute(
        """SELECT a.* FROM accounts a JOIN api_keys k ON k.account_id=a.id
           WHERE lower(a.email)=lower(?) AND k.key_hash=? AND k.revoked_at IS NULL AND a.enabled=1""",
        (email, hash_key(key)),
    ).fetchone()
    if row:
        conn.execute("UPDATE api_keys SET last_used=? WHERE key_hash=?", (utc_now(), hash_key(key)))
        conn.commit()
    conn.close()
    return row


def require_account(email: str):
    row = account_for_request(email)
    if not row:
        return None, json_error("A valid account API key is required for this mailbox", 401)
    return row, None


def exchange_refresh_token(client_id: str, refresh_token: str) -> tuple[str, Optional[str], int]:
    attempts = [
        {"client_id": client_id, "grant_type": "refresh_token", "refresh_token": refresh_token,
         "scope": "https://graph.microsoft.com/Mail.Read offline_access openid profile"},
        {"client_id": client_id, "grant_type": "refresh_token", "refresh_token": refresh_token,
         "scope": "https://graph.microsoft.com/.default offline_access"},
    ]
    last_error = "Microsoft token exchange failed"
    for data in attempts:
        try:
            response = requests.post(TOKEN_URL, data=data, timeout=REQUEST_TIMEOUT)
            payload = response.json() if response.content else {}
            if response.ok and payload.get("access_token"):
                return payload["access_token"], payload.get("refresh_token"), int(payload.get("expires_in", 3600))
            last_error = payload.get("error_description") or payload.get("error") or response.text[:200]
        except requests.RequestException as exc:
            last_error = str(exc)[:200]
    raise RuntimeError(last_error)


def graph_messages(access_token: str, limit: int) -> list[dict[str, Any]]:
    headers = {"Authorization": f"Bearer {access_token}"}
    folders = [("inbox", "Inbox"), ("junkemail", "Junk")]
    messages: list[dict[str, Any]] = []
    errors: list[str] = []
    select = "id,subject,from,receivedDateTime,bodyPreview,isRead,hasAttachments"

    for folder_id, label in folders:
        url = f"{GRAPH_URL}/me/mailFolders/{folder_id}/messages"
        params = {"$top": limit, "$select": select, "$orderby": "receivedDateTime desc"}
        try:
            response = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
            if not response.ok:
                errors.append(f"{label}:{response.status_code}")
                continue
            for item in response.json().get("value", []):
                sender = (item.get("from") or {}).get("emailAddress") or {}
                messages.append({
                    "message_id": item.get("id"),
                    "subject": item.get("subject") or "(no subject)",
                    "from_name": sender.get("name") or "",
                    "from_address": sender.get("address") or "",
                    "received_at": item.get("receivedDateTime") or "",
                    "preview": " ".join((item.get("bodyPreview") or "").split())[:500],
                    "folder": label,
                    "is_read": 1 if item.get("isRead") else 0,
                    "has_attachments": 1 if item.get("hasAttachments") else 0,
                })
        except requests.RequestException as exc:
            errors.append(f"{label}:{str(exc)[:100]}")
    if not messages and errors:
        raise RuntimeError("; ".join(errors))
    messages.sort(key=lambda item: item.get("received_at") or "", reverse=True)
    return messages[: limit * 2]


def graph_body(access_token: str, message_id: str) -> dict[str, Any]:
    url = f"{GRAPH_URL}/me/messages/{quote(message_id, safe='')}"
    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {access_token}"},
        params={"$select": "body,subject,from,receivedDateTime,hasAttachments"},
        timeout=REQUEST_TIMEOUT,
    )
    if not response.ok:
        raise RuntimeError(f"Graph body request failed ({response.status_code})")
    item = response.json()
    sender = (item.get("from") or {}).get("emailAddress") or {}
    body = item.get("body") or {}
    return {
        "content": body.get("content") or "",
        "content_type": body.get("contentType") or "text",
        "subject": item.get("subject") or "(no subject)",
        "from_name": sender.get("name") or "",
        "from_address": sender.get("address") or "",
        "received_at": item.get("receivedDateTime") or "",
        "has_attachments": bool(item.get("hasAttachments")),
    }


def sync_account(account: sqlite3.Row, limit: int) -> tuple[int, int, str]:
    """Exchange the refresh token, fetch Graph mail, and persist observations."""
    access_token, rotated_refresh, _ = exchange_refresh_token(
        account["client_id"], decrypt(account["refresh_token_enc"])
    )
    messages = graph_messages(access_token, limit)
    conn = database()
    if rotated_refresh:
        conn.execute(
            "UPDATE accounts SET refresh_token_enc=? WHERE id=?",
            (encrypt(rotated_refresh), account["id"]),
        )
    existing_ids = {
        row[0]
        for row in conn.execute(
            "SELECT message_id FROM emails WHERE account_id=?", (account["id"],)
        ).fetchall()
    }
    new_count = 0
    for item in messages:
        conn.execute(
            """INSERT INTO emails(account_id,message_id,subject,from_name,from_address,
               received_at,preview,folder,is_read,has_attachments,is_new,first_seen)
               VALUES(?,?,?,?,?,?,?,?,?,?,1,?)
               ON CONFLICT(account_id,message_id) DO UPDATE SET
                 subject=excluded.subject, from_name=excluded.from_name,
                 from_address=excluded.from_address, received_at=excluded.received_at,
                 preview=excluded.preview, folder=excluded.folder,
                 is_read=excluded.is_read, has_attachments=excluded.has_attachments""",
            (account["id"], item["message_id"], item["subject"], item["from_name"],
             item["from_address"], item["received_at"], item["preview"], item["folder"],
             item["is_read"], item["has_attachments"], utc_now()),
        )
        if item["message_id"] not in existing_ids:
            new_count += 1
    conn.execute(
        """DELETE FROM emails WHERE account_id=? AND id NOT IN
           (SELECT id FROM emails WHERE account_id=? ORDER BY received_at DESC LIMIT ?)""",
        (account["id"], account["id"], limit * 2 + 20),
    )
    conn.execute(
        "UPDATE accounts SET status='ok', error_msg=NULL, last_sync=? WHERE id=?",
        (utc_now(), account["id"]),
    )
    conn.commit()
    conn.close()
    return new_count, len(messages), access_token


def parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).lower() in {"1", "true", "yes", "on"}


def present_email(row: sqlite3.Row, include_body: bool = False, body: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    result = {
        "id": row["message_id"],
        "subject": row["subject"],
        "from": {"name": row["from_name"], "address": row["from_address"]},
        "received_at": row["received_at"],
        "preview": row["preview"],
        "folder": row["folder"],
        "is_read": bool(row["is_read"]),
        "is_new": bool(row["is_new"]),
        "has_attachments": bool(row["has_attachments"]),
    }
    if include_body:
        result["body"] = body
    return result


def read_mailbox(account: sqlite3.Row, limit: int, new_only: bool, include_body: bool) -> dict[str, Any]:
    try:
        new_count, fetched_count, body_token = sync_account(account, limit)
    except Exception as exc:
        conn = database()
        conn.execute("UPDATE accounts SET status='error', error_msg=? WHERE id=?", (str(exc)[:500], account["id"]))
        conn.commit()
        conn.close()
        raise
    conn = database()
    where = "account_id=?"
    params: list[Any] = [account["id"]]
    if new_only:
        where += " AND is_new=1"
    rows = conn.execute(
        f"SELECT * FROM emails WHERE {where} ORDER BY received_at DESC, first_seen DESC LIMIT ?",
        (*params, limit),
    ).fetchall()
    items = []
    for row in rows:
        body = None
        if body_token:
            try:
                body = graph_body(body_token, row["message_id"])
            except Exception as exc:
                body = {"error": str(exc)[:200]}
        items.append(present_email(row, include_body, body))
    conn.close()
    return {
        "ok": True,
        "email": account["email"],
        "checked_at": utc_now(),
        "new_count": new_count,
        "fetched_count": fetched_count,
        "new_only": new_only,
        "messages": items,
    }


@app.after_request
def cors(response):
    allowed = os.getenv("CORS_ORIGINS", "*")
    response.headers["Access-Control-Allow-Origin"] = allowed
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    return response


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"ok": True, "service": APP_NAME, "time": utc_now()})


@app.route("/", methods=["GET", "HEAD"])
def root():
    return jsonify({"ok": True, "service": APP_NAME, "health": "/healthz"})


@app.route("/v1/accounts", methods=["POST"])
@require_admin
def register_account():
    data = request.get_json(silent=True) or request.form.to_dict()
    account_line = str(data.get("account_line", "")).strip()
    if account_line:
        try:
            email, client_id, refresh_token = parse_account_line(account_line)
        except ValueError as exc:
            return json_error(str(exc))
    else:
        email = str(data.get("email", "")).strip().lower()
        client_id = str(data.get("client_id", "")).strip()
        refresh_token = str(data.get("refresh_token", data.get("token", ""))).strip()
    label = str(data.get("label", "")).strip()
    if not valid_email(email):
        return json_error("A valid email is required")
    if not client_id or not refresh_token:
        return json_error("client_id and refresh_token are required")

    conn = database()
    existing = conn.execute("SELECT * FROM accounts WHERE email=?", (email,)).fetchone()
    if existing:
        conn.execute(
            "UPDATE accounts SET client_id=?, refresh_token_enc=?, enabled=1, status='pending', error_msg=NULL WHERE id=?",
            (client_id, encrypt(refresh_token), existing["id"]),
        )
        account_id = existing["id"]
        action = "updated"
    else:
        cur = conn.execute(
            "INSERT INTO accounts(email,client_id,refresh_token_enc,created_at) VALUES(?,?,?,?)",
            (email, client_id, encrypt(refresh_token), utc_now()),
        )
        account_id = cur.lastrowid
        action = "created"
    api_key = create_account_key(conn, account_id, label)
    conn.commit()
    row = conn.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
    conn.close()
    return jsonify({
        "ok": True,
        "action": action,
        "account": account_public(row),
        "api_key": api_key,
        "read_url": f"/read/{quote(email, safe='')}",
        "warning": "Save api_key now. It is shown only in this response.",
    }), 201 if action == "created" else 200


@app.route("/v1/accounts", methods=["GET"])
@require_admin
def list_accounts():
    conn = database()
    rows = conn.execute("SELECT * FROM accounts ORDER BY email").fetchall()
    result = []
    for row in rows:
        item = account_public(row)
        item["active_keys"] = conn.execute(
            "SELECT COUNT(*) FROM api_keys WHERE account_id=? AND revoked_at IS NULL", (row["id"],)
        ).fetchone()[0]
        result.append(item)
    conn.close()
    return jsonify({"ok": True, "accounts": result})


@app.route("/v1/accounts/<path:email>", methods=["DELETE"])
@require_admin
def delete_account(email: str):
    conn = database()
    cur = conn.execute("DELETE FROM accounts WHERE lower(email)=lower(?)", (email,))
    conn.commit()
    conn.close()
    if not cur.rowcount:
        return json_error("Account not found", 404)
    return jsonify({"ok": True, "deleted": email})


@app.route("/v1/accounts/<path:email>/rotate-key", methods=["POST"])
@require_admin
def rotate_account_key(email: str):
    conn = database()
    account = conn.execute("SELECT * FROM accounts WHERE lower(email)=lower(?)", (email,)).fetchone()
    if not account:
        conn.close()
        return json_error("Account not found", 404)
    conn.execute(
        "UPDATE api_keys SET revoked_at=? WHERE account_id=? AND revoked_at IS NULL",
        (utc_now(), account["id"]),
    )
    raw = create_account_key(conn, account["id"], "rotated")
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "email": account["email"], "api_key": raw,
                    "warning": "Save api_key now. Previous mailbox keys are revoked."})


@app.route("/v1/read", methods=["GET"])
def read_query():
    email = request.args.get("email", "").strip()
    if not email:
        return json_error("Use /v1/read?email=person@example.com or /read/<email>")
    return read_for_email(email)


@app.route("/read/<path:email>", methods=["GET"])
@app.route("/v1/read/<path:email>", methods=["GET"])
@app.route("/read=<path:email>", methods=["GET"])
def read_path(email: str):
    return read_for_email(email)


def read_for_email(email: str):
    if not valid_email(email):
        return json_error("Invalid email address")
    account, error = require_account(email)
    if error:
        return error
    try:
        limit = min(max(int(request.args.get("limit", 20)), 1), MAX_LIMIT)
    except (TypeError, ValueError):
        return json_error("limit must be an integer between 1 and 50")
    new_only = parse_bool(request.args.get("new_only"), False)
    include_body = parse_bool(request.args.get("include_body"), False)
    try:
        return jsonify(read_mailbox(account, limit, new_only, include_body))
    except Exception as exc:
        return json_error(f"Mailbox read failed: {str(exc)[:300]}", 502)


@app.route("/v1/read/<path:email>/mark-seen", methods=["POST"])
def mark_seen(email: str):
    if not valid_email(email):
        return json_error("Invalid email address")
    account, error = require_account(email)
    if error:
        return error
    conn = database()
    cur = conn.execute("UPDATE emails SET is_new=0 WHERE account_id=?", (account["id"],))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "email": account["email"], "marked_seen": cur.rowcount})


@app.route("/manager", methods=["GET"])
def manager():
    # The admin key is entered in the browser and sent only as a request header.
    return """<!doctype html>
<html><head><meta charset='utf-8'><title>Outlook API manager</title>
<style>body{font:16px system-ui;max-width:760px;margin:40px auto;padding:0 16px}input,button{font:inherit;padding:9px;margin:5px 0;width:100%;box-sizing:border-box}button{cursor:pointer}pre{background:#f4f4f4;padding:12px;white-space:pre-wrap}</style></head>
<body><h1>Outlook API manager</h1>
<p>Register a mailbox. The refresh token is encrypted before it is stored. The password field in an account line is ignored and never stored. The returned account API key is displayed once.</p>
<form id='form'><input id='admin' type='password' placeholder='ADMIN_API_KEY' required>
<textarea id='account_line' rows='5' placeholder='email----password----client_id----refresh_token'></textarea>
<p>Or enter the fields separately:</p>
<input id='email' type='email' placeholder='email@example.com'>
<input id='client_id' placeholder='Microsoft application client_id'>
<input id='refresh_token' placeholder='Microsoft Graph refresh_token'>
<input id='label' placeholder='Optional label'><button>Add or update mailbox</button></form><pre id='out'></pre>
<script>const byId=id=>document.getElementById(id);byId('form').onsubmit=async e=>{e.preventDefault();const line=byId('account_line').value.trim();const body=line?{account_line:line,label:byId('label').value}:{email:byId('email').value,client_id:byId('client_id').value,refresh_token:byId('refresh_token').value,label:byId('label').value};const r=await fetch('/v1/accounts',{method:'POST',headers:{'Content-Type':'application/json','X-API-Key':byId('admin').value},body:JSON.stringify(body)});byId('out').textContent=JSON.stringify(await r.json(),null,2)}</script></body></html>"""


@app.errorhandler(404)
def not_found(_):
    return json_error("Not found", 404)


@app.errorhandler(405)
def method_not_allowed(_):
    return json_error("Method not allowed", 405)


init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
