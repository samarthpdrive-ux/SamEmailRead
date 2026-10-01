#!/usr/bin/env python3
"""
Outlook / Hotmail Multi-Account Local Web Monitor - Graph Edition
=================================================================
Private local web app (http://127.0.0.1:5000)

All polling uses Microsoft Graph only (Inbox + Junk):
- Poll All Now, Auto-poll, single Check, Re-proxy & Poll Errors

Features:
- Bulk import (auto-detects |, ----, or : delimiters and either OAuth field order)
- Parallel Graph polling with configurable concurrency (10-100)
- Residential proxy support (host:port:user:pass)
- Automatic proxy rotation on failure
- Live new email feed + full body via Graph
- Professional Japanese black-white-red theme
"""

import os
import sys
import json
import time
import random
import sqlite3
import threading
import traceback
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from flask import (
        Flask, render_template, request, jsonify, redirect, url_for,
        flash, g
    )
    import requests
except ImportError:
    print("\nMissing libraries. Run:\n    pip install flask requests\n")
    input("Press Enter to exit...")
    sys.exit(1)


# ====================== CONFIG ======================
HOST = "127.0.0.1"
PORT = 5000
DB_PATH = Path(__file__).parent / "monitor.db"
PROXIES_FILE = Path(__file__).parent / "proxies.txt"
SETTINGS_FILE = Path(__file__).parent / "settings.json"

POLL_INTERVAL_MINUTES = 30
MAX_EMAILS_PER_ACCOUNT = 100
REQUEST_TIMEOUT = 15  # per network call – keep under the 20s account timeout
DEFAULT_MAX_WORKERS = 15

TOKEN_URL_V2 = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
TOKEN_URL_V1 = "https://login.microsoftonline.com/common/oauth2/token"
GRAPH = "https://graph.microsoft.com/v1.0"
IMAP_HOST = "outlook.office365.com"

app = Flask(__name__)
app.secret_key = "local-outlook-monitor-pro-2026"

poller_state = {
    "running": False,
    "last_full_poll": None,
    "current_account": None,
    "progress": "Idle",
    "stop_requested": False,
    "processed": 0,
    "total": 0,
}


# ====================== SETTINGS & PROXIES ======================
def load_settings():
    defaults = {"max_workers": DEFAULT_MAX_WORKERS, "poll_interval": POLL_INTERVAL_MINUTES}
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                defaults.update(data)
        except Exception:
            pass
    return defaults


def save_settings(data):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_proxies():
    proxies = []
    if PROXIES_FILE.exists():
        with open(PROXIES_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 4:
                    host, port, user, password = parts[0], parts[1], parts[2], ":".join(parts[3:])
                    proxies.append({
                        "raw": line,
                        "http": f"http://{user}:{password}@{host}:{port}",
                        "https": f"http://{user}:{password}@{host}:{port}",
                    })
                elif len(parts) == 2:  # host:port only
                    host, port = parts
                    proxies.append({
                        "raw": line,
                        "http": f"http://{host}:{port}",
                        "https": f"http://{host}:{port}",
                    })
    return proxies


def save_proxies(text):
    with open(PROXIES_FILE, "w", encoding="utf-8") as f:
        f.write(text.strip() + "\n")


def get_random_proxy(proxies):
    if not proxies:
        return None
    return random.choice(proxies)


# ====================== DATABASE ======================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT,
        refresh_token TEXT NOT NULL,
        client_id TEXT NOT NULL,
        access_token TEXT,
        token_expires_at TEXT,
        status TEXT DEFAULT 'pending',
        error_msg TEXT,
        last_check TEXT,
        last_new_count INTEGER DEFAULT 0,
        total_seen INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        enabled INTEGER DEFAULT 1,
        note TEXT DEFAULT ''
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
        is_read INTEGER DEFAULT 0,
        has_attachments INTEGER DEFAULT 0,
        is_new INTEGER DEFAULT 1,
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(account_id, message_id),
        FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_emails_account ON emails(account_id);
    CREATE INDEX IF NOT EXISTS idx_emails_received ON emails(received_at DESC);
    CREATE INDEX IF NOT EXISTS idx_emails_new ON emails(is_new);
    """)
    # Migration: add note column if missing (older DBs)
    try:
        cols = [r[1] for r in db.execute("PRAGMA table_info(accounts)").fetchall()]
        if "note" not in cols:
            db.execute("ALTER TABLE accounts ADD COLUMN note TEXT DEFAULT ''")
    except Exception:
        pass
    db.commit()
    db.close()


@app.context_processor
def inject_globals():
    return dict(poller=poller_state, settings=load_settings())


# ====================== ACCOUNT IMPORT / CREDENTIAL NORMALIZATION ======================
EMAIL_RE = re.compile(r"^[^\s@|]+@[^\s@|]+\.[^\s@|]+$")


def looks_like_client_id(value: str) -> bool:
    """Microsoft OAuth application/client IDs are UUID/GUID values."""
    value = (value or "").strip()
    try:
        parsed = uuid.UUID(value)
        return str(parsed).lower() == value.lower()
    except (ValueError, AttributeError, TypeError):
        return False


def looks_like_refresh_token(value: str) -> bool:
    """Loose check only; refresh-token formats can change over time."""
    value = (value or "").strip()
    return len(value) >= 40 and not looks_like_client_id(value) and " " not in value


def normalize_oauth_credentials(client_id: str, refresh_token: str):
    """
    Return (client_id, refresh_token, swapped).

    This repairs rows saved by older builds when a new-format line
    email|password|client_id|refresh_token was imported as if it were the
    legacy email|password|refresh_token|client_id layout.
    """
    client_id = (client_id or "").strip()
    refresh_token = (refresh_token or "").strip()
    if looks_like_refresh_token(client_id) and looks_like_client_id(refresh_token):
        return refresh_token, client_id, True
    return client_id, refresh_token, False


def parse_account_line(line: str):
    """
    Parse supported 4-field account layouts using any of these delimiters:
      |
      ----
      :

    OAuth fields may be in either order:
      email<sep>password<sep>client_id<sep>refresh_token
      email<sep>password<sep>refresh_token<sep>client_id

    Returns (account_dict, detected_order, error_message).
    """
    delimiters = ("----", "|", ":")
    attempted = False
    format_errors = []

    for delimiter in delimiters:
        if delimiter not in line:
            continue

        # Split only the first two columns up front. Then identify the GUID-shaped
        # client_id from the remainder. This is safer for refresh tokens that may
        # themselves contain the selected delimiter.
        first = line.split(delimiter, 2)
        if len(first) != 3:
            continue
        attempted = True
        email, password, remainder = [p.strip() for p in first]
        email = email.replace(r"\@", "@")

        if not EMAIL_RE.match(email):
            format_errors.append(f"invalid email address for '{delimiter}' format")
            continue

        candidates = []

        # client_id before refresh_token. Keep any further delimiter characters
        # inside the refresh token instead of creating extra columns.
        client_first = remainder.split(delimiter, 1)
        if len(client_first) == 2:
            third, fourth = [p.strip() for p in client_first]
            if looks_like_client_id(third) and looks_like_refresh_token(fourth):
                candidates.append((third, fourth, "client_id|refresh_token"))

        # refresh_token before client_id. Split from the right so delimiter
        # characters inside the refresh token are preserved.
        refresh_first = remainder.rsplit(delimiter, 1)
        if len(refresh_first) == 2:
            third, fourth = [p.strip() for p in refresh_first]
            if looks_like_refresh_token(third) and looks_like_client_id(fourth):
                candidates.append((fourth, third, "refresh_token|client_id"))

        # Remove duplicate candidate in the unlikely case both constructions
        # resolve to the same values/order.
        unique = []
        for item in candidates:
            if item not in unique:
                unique.append(item)
        candidates = unique

        if len(candidates) == 1:
            client_id, refresh_token, detected = candidates[0]
            return {
                "email": email,
                "password": password,
                "refresh_token": refresh_token,
                "client_id": client_id,
            }, detected, None

        if len(candidates) > 1:
            return None, None, f"ambiguous OAuth fields using '{delimiter}' delimiter"

        format_errors.append(
            f"could not identify a GUID/UUID client_id and refresh token using '{delimiter}' delimiter"
        )

    if not attempted:
        return None, None, "expected 4 fields separated by |, ----, or :"
    return None, None, format_errors[0] if format_errors else "invalid account format"


# ====================== TOKEN + EMAIL HELPERS ======================
def exchange_token(client_id: str, refresh_token: str, proxy=None, prefer_graph=False):
    client_id, refresh_token, _ = normalize_oauth_credentials(client_id, refresh_token)
    client_id = client_id.strip()
    refresh_token = refresh_token.strip()
    proxies_dict = {"http": proxy["http"], "https": proxy["https"]} if proxy else None

    # Use only the client ID supplied with this account. Refresh tokens are
    # application-bound credentials; guessing unrelated client IDs makes failures
    # harder to diagnose and can redeem a token under the wrong application.
    client_ids_to_try = [client_id] if client_id else []

    attempts = []

    def add_graph_attempts(cid):
        attempts.append({
            "url": TOKEN_URL_V2,
            "data": {
                "client_id": cid,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": "https://graph.microsoft.com/Mail.Read offline_access openid profile",
            },
            "method": "graph",
        })
        attempts.append({
            "url": TOKEN_URL_V2,
            "data": {
                "client_id": cid,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": "https://graph.microsoft.com/.default offline_access",
            },
            "method": "graph",
        })
        attempts.append({
            "url": TOKEN_URL_V1,
            "data": {
                "client_id": cid,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "resource": "https://graph.microsoft.com",
            },
            "method": "graph",
        })
        attempts.append({
            "url": TOKEN_URL_V2,
            "data": {
                "client_id": cid,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": "Mail.Read offline_access",
            },
            "method": "graph",
        })

    def add_imap_attempts(cid):
        attempts.append({
            "url": TOKEN_URL_V2,
            "data": {
                "client_id": cid,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
            },
            "method": "imap",
        })
        attempts.append({
            "url": TOKEN_URL_V1,
            "data": {
                "client_id": cid,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "resource": "https://outlook.office365.com",
            },
            "method": "imap",
        })

    for cid in client_ids_to_try:
        if prefer_graph:
            add_graph_attempts(cid)
        else:
            add_imap_attempts(cid)
            add_graph_attempts(cid)

    # If prefer_graph, also try IMAP as last resort only for token validity check - no, skip IMAP for pure graph mode
    if not prefer_graph:
        for cid in client_ids_to_try:
            pass  # already added

    last_error = "All methods failed"
    for att in attempts:
        try:
            r = requests.post(att["url"], data=att["data"], timeout=REQUEST_TIMEOUT, proxies=proxies_dict)
            if r.status_code == 200:
                j = r.json()
                token = j.get("access_token")
                if token:
                    return token, j.get("refresh_token"), j.get("expires_in", 3600), att["method"], None
            else:
                try:
                    err = r.json()
                    last_error = err.get("error_description") or err.get("error") or r.text[:160]
                except Exception:
                    last_error = r.text[:160]
        except Exception as e:
            last_error = str(e)[:160]

    return None, None, 0, None, last_error


def fetch_recent_emails_graph(access_token: str, top: int = 40, proxy=None):
    """Fetch from both Inbox and Junk Email folders (treated equally)."""
    headers = {"Authorization": f"Bearer {access_token}"}
    proxies_dict = {"http": proxy["http"], "https": proxy["https"]} if proxy else None

    def pull_folder(folder_id, folder_label):
        url = (
            f"{GRAPH}/me/mailFolders/{folder_id}/messages"
            f"?$top={top}&$select=id,subject,from,receivedDateTime,bodyPreview,isRead,hasAttachments"
            f"&$orderby=receivedDateTime desc"
        )
        r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, proxies=proxies_dict)
        if r.status_code != 200:
            return [], f"{folder_label}:{r.status_code}"
        out = []
        for m in r.json().get("value", []):
            from_info = m.get("from", {}).get("emailAddress", {})
            out.append({
                "message_id": m.get("id"),
                "subject": m.get("subject") or "(no subject)",
                "from_name": from_info.get("name") or "",
                "from_address": from_info.get("address") or "",
                "received_at": (m.get("receivedDateTime") or "")[:19].replace("T", " "),
                "preview": (m.get("bodyPreview") or "").replace("\n", " ").strip()[:250],
                "is_read": 1 if m.get("isRead") else 0,
                "has_attachments": 1 if m.get("hasAttachments") else 0,
                "folder": folder_label,
            })
        return out, None

    messages = []
    errors = []

    # Inbox
    inbox_msgs, err = pull_folder("inbox", "Inbox")
    if err:
        errors.append(err)
    else:
        messages.extend(inbox_msgs)

    # Junk — try well-known name first, then discover by displayName
    junk_msgs, err = pull_folder("junkemail", "Junk")
    if err:
        try:
            r = requests.get(
                f"{GRAPH}/me/mailFolders?$top=50",
                headers=headers, timeout=REQUEST_TIMEOUT, proxies=proxies_dict
            )
            if r.status_code == 200:
                for f in r.json().get("value", []):
                    name = (f.get("displayName") or "").lower()
                    if "junk" in name or "spam" in name:
                        junk_msgs, err2 = pull_folder(f["id"], "Junk")
                        if not err2:
                            err = None
                        break
        except Exception as e:
            errors.append(f"JunkDiscover:{str(e)[:60]}")
        if err:
            errors.append(err)
    if junk_msgs:
        messages.extend(junk_msgs)

    if not messages and errors:
        return [], " | ".join(errors)

    # Newest first — Inbox + Junk mixed
    messages.sort(key=lambda x: x.get("received_at") or "", reverse=True)
    return messages[: top * 2], None


def fetch_message_body_graph(access_token: str, message_id: str, proxy=None):
    """Fetch full body of one message via Microsoft Graph."""
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{GRAPH}/me/messages/{message_id}?$select=body,subject,from,receivedDateTime,hasAttachments"
    proxies_dict = {"http": proxy["http"], "https": proxy["https"]} if proxy else None
    try:
        r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, proxies=proxies_dict)
        if r.status_code != 200:
            return None, f"Graph {r.status_code}: {r.text[:120]}"
        data = r.json()
        body = data.get("body", {})
        return {
            "subject": data.get("subject") or "(no subject)",
            "content": body.get("content") or "",
            "contentType": body.get("contentType") or "text",
            "from_name": (data.get("from") or {}).get("emailAddress", {}).get("name") or "",
            "from_address": (data.get("from") or {}).get("emailAddress", {}).get("address") or "",
            "received_at": (data.get("receivedDateTime") or "")[:19].replace("T", " "),
            "has_attachments": data.get("hasAttachments", False),
        }, None
    except Exception as e:
        return None, str(e)[:150]


def fetch_recent_emails_imap(email_addr: str, access_token: str, top: int = 40, proxy=None):
    """Fetch from Inbox + Junk/Spam via IMAP."""
    import imaplib
    import email as email_lib
    from email.header import decode_header

    def generate_auth_string(user, token):
        return f"user={user}\x01auth=Bearer {token}\x01\x01"

    def decode_subj(subject):
        try:
            decoded = decode_header(subject or "")
            return "".join(
                p.decode(enc or "utf-8", errors="replace") if isinstance(p, bytes) else p
                for p, enc in decoded
            )
        except Exception:
            return subject or "(no subject)"

    messages = []
    # Common folder names on Outlook.com / Hotmail
    folders_to_try = ["INBOX", "Junk Email", "Junk", "Spam"]

    try:
        mail = imaplib.IMAP4_SSL(IMAP_HOST, 993)
        mail.authenticate("XOAUTH2", lambda x: generate_auth_string(email_addr, access_token))

        # Discover actual junk folder name from server LIST
        try:
            typ, folder_list = mail.list()
            if typ == "OK" and folder_list:
                for line in folder_list:
                    s = line.decode(errors="ignore") if isinstance(line, bytes) else str(line)
                    low = s.lower()
                    if "junk" in low or "spam" in low:
                        # folder name is usually the last quoted part
                        if '"' in s:
                            fname = s.split('"')[-2]
                            if fname and fname not in folders_to_try:
                                folders_to_try.append(fname)
        except Exception:
            pass

        for folder in folders_to_try:
            try:
                # INBOX usually without quotes; others with quotes
                sel = folder if folder.upper() == "INBOX" else f'"{folder}"'
                status, _ = mail.select(sel, readonly=True)
                if status != "OK":
                    continue
                status, data = mail.search(None, "ALL")
                if status != "OK" or not data or not data[0]:
                    continue
                mail_ids = data[0].split()
                mail_ids = mail_ids[-top:] if len(mail_ids) > top else mail_ids
                mail_ids.reverse()
                folder_label = "Junk" if folder.lower() != "inbox" else "Inbox"

                for mid in mail_ids:
                    try:
                        status, msg_data = mail.fetch(mid, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)] FLAGS)")
                        if status != "OK" or not msg_data:
                            continue
                        raw = msg_data[0][1]
                        msg = email_lib.message_from_bytes(raw) if isinstance(raw, bytes) else None
                        if not msg:
                            continue
                        subject = decode_subj(msg.get("Subject", "(no subject)"))
                        from_ = msg.get("From", "")
                        from_name, from_address = "", from_
                        if "<" in from_ and ">" in from_:
                            from_name = from_.split("<")[0].strip().strip('"')
                            from_address = from_.split("<")[1].split(">")[0].strip()
                        flags = str(msg_data[0][0])
                        messages.append({
                            "message_id": f"{folder_label}-" + (mid.decode() if isinstance(mid, bytes) else str(mid)),
                            "subject": subject or "(no subject)",
                            "from_name": from_name,
                            "from_address": from_address,
                            "received_at": (msg.get("Date") or "")[:25],
                            "preview": "",
                            "is_read": 1 if "\\Seen" in flags else 0,
                            "has_attachments": 0,
                            "folder": folder_label,
                        })
                    except Exception:
                        continue
            except Exception:
                continue

        try:
            mail.logout()
        except Exception:
            pass

        messages.sort(key=lambda x: x.get("received_at") or "", reverse=True)
        return messages[:top * 2], None
    except Exception as e:
        return [], f"IMAP: {str(e)[:140]}"


def fetch_recent_emails(access_token, method, email_addr="", top=40, proxy=None):
    if method == "graph":
        return fetch_recent_emails_graph(access_token, top, proxy)
    return fetch_recent_emails_imap(email_addr, access_token, top, proxy)


# ====================== ACCOUNT PROCESSING ======================
def process_one_account(acc_row, proxies=None, max_retries=2, graph_only=True):
    """
    Process one account using Microsoft Graph only (no IMAP).
    Used by Poll All, Auto-poll, single Check, and Graph Fetch.
    """
    acc_id = acc_row["id"]
    email = acc_row["email"]
    result = {"email": email, "new_count": 0, "status": "ok", "error": None}

    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row

    proxy = get_random_proxy(proxies) if proxies else None
    tried_proxies = set()

    client_id, refresh_token, repaired = normalize_oauth_credentials(
        acc_row["client_id"], acc_row["refresh_token"]
    )
    if repaired:
        db.execute(
            "UPDATE accounts SET client_id=?, refresh_token=?, status='pending', error_msg=NULL WHERE id=?",
            (client_id, refresh_token, acc_id)
        )
        db.commit()

    for attempt in range(max_retries + 1):
        if proxy:
            tried_proxies.add(proxy["raw"])

        # Always request a Graph-scoped access token
        access_token, new_refresh, expires_in, method, err = exchange_token(
            client_id, refresh_token, proxy, prefer_graph=True
        )
        if err or not access_token:
            if attempt < max_retries and proxies:
                available = [p for p in proxies if p["raw"] not in tried_proxies]
                proxy = random.choice(available) if available else get_random_proxy(proxies)
                continue
            result["status"] = "token_error"
            result["error"] = err or "No Graph token"
            db.execute(
                "UPDATE accounts SET status=?, error_msg=?, last_check=? WHERE id=?",
                (result["status"], (result["error"] or "")[:280], datetime.now(timezone.utc).isoformat(), acc_id)
            )
            db.commit()
            db.close()
            return result

        # Save token
        new_exp = (datetime.now(timezone.utc) + timedelta(seconds=int(expires_in) - 60)).isoformat()
        if new_refresh:
            refresh_token = new_refresh
            db.execute(
                "UPDATE accounts SET access_token=?, refresh_token=?, token_expires_at=?, status='ok', error_msg=NULL WHERE id=?",
                (access_token, new_refresh, new_exp, acc_id)
            )
        else:
            db.execute(
                "UPDATE accounts SET access_token=?, token_expires_at=?, status='ok', error_msg=NULL WHERE id=?",
                (access_token, new_exp, acc_id)
            )
        db.commit()

        # Graph-only fetch (Inbox + Junk)
        messages, err = fetch_recent_emails_graph(access_token, top=MAX_EMAILS_PER_ACCOUNT, proxy=proxy)
        if err:
            if "401" in str(err):
                err = (
                    "Graph 401 Unauthorized – this refresh token has no Microsoft Graph "
                    "(Mail.Read) permission. Re-auth with Graph consent or use a token that includes Graph."
                )
            if attempt < max_retries and proxies:
                available = [p for p in proxies if p["raw"] not in tried_proxies]
                proxy = random.choice(available) if available else get_random_proxy(proxies)
                continue
            result["status"] = "fetch_error"
            result["error"] = err
            db.execute(
                "UPDATE accounts SET status=?, error_msg=?, last_check=? WHERE id=?",
                (result["status"], err[:280], datetime.now(timezone.utc).isoformat(), acc_id)
            )
            db.commit()
            db.close()
            return result

        # Store new emails — Junk/Spam treated the same as Inbox (all is_new=1)
        new_count = 0
        for msg in messages:
            try:
                subj = msg["subject"] or "(no subject)"
                # Light tag only for visibility; does not affect sorting
                if msg.get("folder") == "Junk" and not subj.startswith("[Junk]"):
                    subj = "[Junk] " + subj
                # Normalize date to YYYY-MM-DD HH:MM:SS for consistent sorting
                recv = (msg.get("received_at") or "").strip()
                if "T" in recv:
                    recv = recv.replace("T", " ")[:19]
                elif len(recv) > 19:
                    recv = recv[:19]
                cur = db.execute(
                    """INSERT OR IGNORE INTO emails
                       (account_id, message_id, subject, from_name, from_address,
                        received_at, preview, is_read, has_attachments, is_new)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (acc_id, msg["message_id"], subj, msg["from_name"],
                     msg["from_address"], recv, msg["preview"],
                     msg["is_read"], msg["has_attachments"])
                )
                if cur.rowcount > 0:
                    new_count += 1
            except Exception:
                pass

        # Keep only recent
        db.execute("""
            DELETE FROM emails WHERE account_id = ? AND id NOT IN (
                SELECT id FROM emails WHERE account_id = ?
                ORDER BY received_at DESC LIMIT ?
            )
        """, (acc_id, acc_id, MAX_EMAILS_PER_ACCOUNT + 15))

        db.execute(
            """UPDATE accounts SET status='ok', error_msg=NULL, last_check=?,
               last_new_count=?, total_seen = total_seen + ? WHERE id=?""",
            (datetime.now(timezone.utc).isoformat(), new_count, new_count, acc_id)
        )
        db.commit()
        db.close()

        result["new_count"] = new_count
        result["status"] = "ok"
        return result

    db.close()
    return result


# ====================== PARALLEL POLLER ======================
def mark_account_error(acc_id, error_msg):
    """Force an account into error status (used for timeouts / skips)."""
    try:
        db = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.execute(
            "UPDATE accounts SET status=?, error_msg=?, last_check=? WHERE id=?",
            ("timeout_error" if "timeout" in error_msg.lower() else "fetch_error",
             error_msg[:280],
             datetime.now(timezone.utc).isoformat(),
             acc_id)
        )
        db.commit()
        db.close()
    except Exception as e:
        print("mark_account_error failed:", e)


def run_parallel_poll(accounts, max_workers=15, max_retries=0):
    """
    Poll accounts in parallel with hard 20s per-account timeout.
    Stuck accounts are immediately moved to ERRORS and do not block the rest.
    Guarantees Healthy + Errors == Total at the end.
    """
    from concurrent.futures import wait, FIRST_COMPLETED

    proxies = load_proxies()
    total = len(accounts)
    poller_state["running"] = True
    poller_state["total"] = total
    poller_state["processed"] = 0
    poller_state["last_full_poll"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    poller_state["progress"] = f"Starting parallel poll (0/{total})"

    processed_ids = set()
    ACCOUNT_TIMEOUT = 20  # hard timeout per account

    def worker(acc):
        if poller_state["stop_requested"]:
            return None
        try:
            res = process_one_account(acc, proxies=proxies, max_retries=max_retries, graph_only=True)
            return acc["id"], res
        except Exception as e:
            mark_account_error(acc["id"], f"Worker exception: {str(e)[:200]}")
            return acc["id"], None

    executor = ThreadPoolExecutor(max_workers=max_workers)
    future_to_acc = {executor.submit(worker, acc): acc for acc in accounts}
    pending = set(future_to_acc.keys())

    try:
        while pending and not poller_state["stop_requested"]:
            # Wait up to 20s for any future to complete
            done, pending = wait(pending, timeout=ACCOUNT_TIMEOUT, return_when=FIRST_COMPLETED)

            if not done:
                # Nothing finished in 20s → every still-pending future is timed out
                for fut in list(pending):
                    acc = future_to_acc[fut]
                    if acc["id"] not in processed_ids:
                        mark_account_error(acc["id"], "Timeout: no response within 20 seconds")
                        processed_ids.add(acc["id"])
                        print(f"Timeout → ERROR: {acc['email']}")
                    fut.cancel()
                pending.clear()
                break

            for fut in done:
                acc = future_to_acc[fut]
                try:
                    result = fut.result(timeout=0.1)
                    if result:
                        acc_id, _ = result
                        processed_ids.add(acc_id)
                except Exception as e:
                    if acc["id"] not in processed_ids:
                        mark_account_error(acc["id"], f"Exception: {str(e)[:200]}")
                        processed_ids.add(acc["id"])

                poller_state["processed"] = len(processed_ids)
                poller_state["current_account"] = acc["email"]
                poller_state["progress"] = f"Polling {len(processed_ids)}/{total} • {acc['email']}"

            # Also timeout any futures that have been running too long overall
            # (handled by the empty-done case above)
    finally:
        # Do NOT wait for remaining threads – just shut down
        executor.shutdown(wait=False, cancel_futures=True)

    # Final safety nets – guarantee every account has a final status
    for acc in accounts:
        if acc["id"] not in processed_ids:
            mark_account_error(acc["id"], "Skipped / never processed during poll")
            print(f"Skipped → ERROR: {acc['email']}")

    try:
        db = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.execute(
            """UPDATE accounts SET status='fetch_error', error_msg='No status after poll', last_check=?
               WHERE enabled=1 AND (status IS NULL OR status='pending' OR status='')""",
            (datetime.now(timezone.utc).isoformat(),)
        )
        db.commit()
        db.close()
    except Exception as e:
        print("Post-poll consistency fix failed:", e)

    poller_state["current_account"] = None
    poller_state["progress"] = "Idle – last full poll finished"
    poller_state["running"] = False
    poller_state["processed"] = total


def background_poller():
    while True:
        if poller_state["stop_requested"]:
            poller_state["running"] = False
            poller_state["progress"] = "Stopped"
            break
        try:
            settings = load_settings()
            db = sqlite3.connect(DB_PATH, check_same_thread=False)
            db.row_factory = sqlite3.Row
            accounts = db.execute("SELECT * FROM accounts WHERE enabled = 1 ORDER BY id").fetchall()
            db.close()

            if accounts:
                # Auto-poll: 1 attempt only. Any failure → ERROR immediately
                run_parallel_poll(
                    accounts,
                    max_workers=settings.get("max_workers", DEFAULT_MAX_WORKERS),
                    max_retries=0
                )
            else:
                poller_state["progress"] = "No accounts enabled"
                time.sleep(30)
                continue
        except Exception as e:
            poller_state["progress"] = f"Error: {e}"
            print(traceback.format_exc())

        # Wait for next interval
        interval = load_settings().get("poll_interval", POLL_INTERVAL_MINUTES)
        for _ in range(interval * 60):
            if poller_state["stop_requested"]:
                break
            time.sleep(1)


# ====================== ROUTES ======================
@app.route("/")
def index():
    db = get_db()
    # Preserve original import order (id ASC)
    accounts = db.execute("""
        SELECT a.*,
               (SELECT COUNT(*) FROM emails e WHERE e.account_id = a.id AND e.is_new = 1) as new_emails
        FROM accounts a
        ORDER BY a.id ASC
    """).fetchall()
    stats = db.execute("""
        SELECT COUNT(*) as total,
               SUM(CASE WHEN status = 'ok' THEN 1 ELSE 0 END) as healthy,
               SUM(CASE WHEN status LIKE '%error%' THEN 1 ELSE 0 END) as errors,
               SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled
        FROM accounts
    """).fetchone()
    # Newest first — Inbox + Junk mixed together by date
    recent_new = db.execute("""
        SELECT e.*, a.email FROM emails e
        JOIN accounts a ON a.id = e.account_id
        WHERE e.is_new = 1
        ORDER BY
            CASE WHEN e.received_at IS NULL OR e.received_at = '' THEN 0 ELSE 1 END DESC,
            e.received_at DESC,
            e.first_seen DESC
        LIMIT 100
    """).fetchall()
    healthy_accounts = [a for a in accounts if a["status"] == "ok"]
    error_accounts = [a for a in accounts if a["status"] and "error" in a["status"]]
    return render_template(
        "index.html",
        accounts=accounts,
        stats=stats,
        recent_new=recent_new,
        healthy_accounts=healthy_accounts,
        error_accounts=error_accounts,
    )


@app.route("/settings", methods=["GET", "POST"])
def settings_page():
    settings = load_settings()
    proxy_text = PROXIES_FILE.read_text(encoding="utf-8") if PROXIES_FILE.exists() else ""
    if request.method == "POST":
        try:
            max_workers = int(request.form.get("max_workers", 15))
            max_workers = max(5, min(100, max_workers))
            poll_interval = int(request.form.get("poll_interval", 30))
            poll_interval = max(5, min(120, poll_interval))
            save_settings({"max_workers": max_workers, "poll_interval": poll_interval})
            save_proxies(request.form.get("proxies_text", ""))
            flash("Settings saved successfully.", "success")
            return redirect(url_for("settings_page"))
        except Exception as e:
            flash(f"Error: {e}", "danger")
    proxy_count = len(load_proxies())
    return render_template("settings.html", settings=settings, proxy_text=proxy_text, proxy_count=proxy_count)


@app.route("/import", methods=["GET", "POST"])
def import_accounts():
    if request.method == "POST":
        try:
            raw = request.form.get("accounts_text", "")
            db = get_db()
            added = skipped = 0
            detected_new = detected_legacy = 0
            import_errors = []
            for line_no, raw_line in enumerate(raw.splitlines(), start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                account, detected, parse_error = parse_account_line(line)
                if parse_error:
                    skipped += 1
                    if len(import_errors) < 8:
                        import_errors.append(f"Line {line_no}: {parse_error}")
                    continue

                email = account["email"]
                password = account["password"]
                refresh_token = account["refresh_token"]
                client_id = account["client_id"]
                if detected == "client_id|refresh_token":
                    detected_new += 1
                else:
                    detected_legacy += 1

                try:
                    cur = db.execute(
                        """INSERT OR IGNORE INTO accounts
                           (email, password, refresh_token, client_id, status, error_msg)
                           VALUES (?, ?, ?, ?, 'pending', NULL)""",
                        (email, password, refresh_token, client_id)
                    )
                    if cur.rowcount > 0:
                        added += 1
                    else:
                        db.execute(
                            """UPDATE accounts
                               SET password=?, refresh_token=?, client_id=?, status='pending', error_msg=NULL
                               WHERE email=?""",
                            (password, refresh_token, client_id, email)
                        )
                        added += 1
                except Exception as exc:
                    skipped += 1
                    if len(import_errors) < 8:
                        import_errors.append(f"Line {line_no}: database error: {str(exc)[:80]}")
            db.commit()
            summary = (
                f"Imported / updated {added} accounts. Skipped {skipped}. "
                f"Detected {detected_new} client_id-first and {detected_legacy} refresh_token-first rows."
            )
            flash(summary, "success" if skipped == 0 else "warning")
            for msg in import_errors:
                flash(msg, "danger")
            return redirect(url_for("index"))
        except Exception as e:
            flash(f"Import failed: {e}", "danger")
    return render_template("import.html")


@app.route("/account/<int:acc_id>")
def account_detail(acc_id):
    db = get_db()
    acc = db.execute("SELECT * FROM accounts WHERE id = ?", (acc_id,)).fetchone()
    if not acc:
        flash("Account not found", "danger")
        return redirect(url_for("index"))
    emails = db.execute(
        "SELECT * FROM emails WHERE account_id = ? ORDER BY received_at DESC LIMIT 100", (acc_id,)
    ).fetchall()
    return render_template("account.html", account=acc, emails=emails)


@app.route("/force_check/<int:acc_id>", methods=["POST"])
def force_check(acc_id):
    """Single-account poll using Graph only (same as all other poll paths)."""
    db = get_db()
    acc = db.execute("SELECT * FROM accounts WHERE id = ?", (acc_id,)).fetchone()
    if acc:
        proxies = load_proxies()
        result = process_one_account(acc, proxies=proxies, max_retries=2, graph_only=True)
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.args.get("ajax"):
            return jsonify({
                "ok": result.get("status") == "ok",
                "email": acc["email"],
                "status": result.get("status"),
                "error": result.get("error"),
                "new_count": result.get("new_count", 0),
            })
        if result.get("status") == "ok":
            flash(f"Graph poll OK for {acc['email']} ({result.get('new_count', 0)} new).", "success")
        else:
            flash(f"Graph poll failed for {acc['email']}: {result.get('error')}", "danger")
    else:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.args.get("ajax"):
            return jsonify({"ok": False, "error": "not found"}), 404
    return redirect(request.referrer or url_for("index"))


@app.route("/force_check_graph/<int:acc_id>", methods=["POST"])
def force_check_graph(acc_id):
    """Alias of force_check — everything uses Graph now."""
    return force_check(acc_id)


@app.route("/poll_all_now", methods=["POST"])
def poll_all_now():
    if poller_state.get("running"):
        flash("A poll is already running.", "warning")
        return redirect(url_for("index"))

    def run():
        db = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.row_factory = sqlite3.Row
        accounts = db.execute("SELECT * FROM accounts WHERE enabled = 1 ORDER BY id").fetchall()
        db.close()
        settings = load_settings()
        # Poll once only. Any error → immediately mark as ERROR (no retries)
        run_parallel_poll(accounts, max_workers=settings.get("max_workers", DEFAULT_MAX_WORKERS), max_retries=0)

    threading.Thread(target=run, daemon=True).start()
    flash("Full parallel poll started (1 attempt per account).", "success")
    return redirect(url_for("index"))


@app.route("/start_poller", methods=["POST"])
def start_poller():
    if not poller_state["running"]:
        poller_state["stop_requested"] = False
        threading.Thread(target=background_poller, daemon=True).start()
        flash("Auto monitoring started.", "success")
    return redirect(url_for("index"))


@app.route("/stop_poller", methods=["POST"])
def stop_poller():
    poller_state["stop_requested"] = True
    flash("Stop requested.", "warning")
    return redirect(url_for("index"))


@app.route("/stop_and_reset_poll", methods=["POST"])
def stop_and_reset_poll():
    """
    Stop any ongoing poll and reset poller state to idle.
    Keeps all email accounts and proxies loaded and ready.
    """
    poller_state["stop_requested"] = True
    poller_state["running"] = False
    poller_state["current_account"] = None
    poller_state["progress"] = "Idle – ready"
    poller_state["processed"] = 0
    poller_state["total"] = 0
    flash("All polls stopped. Accounts and proxies are still loaded and ready.", "success")
    return redirect(url_for("index"))


@app.route("/full_reset", methods=["POST"])
def full_reset():
    """
    Stop everything and clear accounts + proxies + emails.
    Returns to the very beginning (user must import accounts and proxies again).
    """
    poller_state["stop_requested"] = True
    poller_state["running"] = False
    poller_state["current_account"] = None
    poller_state["progress"] = "Idle – fresh start"
    poller_state["processed"] = 0
    poller_state["total"] = 0
    poller_state["last_full_poll"] = None

    # Clear database
    db = get_db()
    db.execute("DELETE FROM emails")
    db.execute("DELETE FROM accounts")
    db.commit()

    # Clear proxies file
    try:
        if PROXIES_FILE.exists():
            PROXIES_FILE.write_text("", encoding="utf-8")
    except Exception:
        pass

    # Reset settings to defaults
    save_settings({"max_workers": DEFAULT_MAX_WORKERS, "poll_interval": POLL_INTERVAL_MINUTES})

    flash("Full reset done. Please import proxies and email accounts again.", "warning")
    return redirect(url_for("settings_page"))




@app.route("/bulk_delete", methods=["POST"])
def bulk_delete():
    """Delete selected accounts completely (and their stored emails)."""
    ids = request.form.getlist("account_ids")
    if not ids:
        flash("No accounts selected.", "warning")
        return redirect(url_for("index"))
    db = get_db()
    deleted = 0
    for raw in ids:
        try:
            acc_id = int(raw)
        except ValueError:
            continue
        db.execute("DELETE FROM emails WHERE account_id = ?", (acc_id,))
        cur = db.execute("DELETE FROM accounts WHERE id = ?", (acc_id,))
        deleted += cur.rowcount
    db.commit()
    flash(f"Removed {deleted} account(s).", "info")
    return redirect(url_for("index"))


@app.route("/bulk_note", methods=["POST"])
def bulk_note():
    """Set or clear a note/tag on selected accounts."""
    ids = request.form.getlist("account_ids")
    note = (request.form.get("note") or "").strip()[:200]
    if not ids:
        flash("No accounts selected.", "warning")
        return redirect(url_for("index"))
    db = get_db()
    updated = 0
    for raw in ids:
        try:
            acc_id = int(raw)
        except ValueError:
            continue
        cur = db.execute("UPDATE accounts SET note = ? WHERE id = ?", (note, acc_id))
        updated += cur.rowcount
    db.commit()
    if note:
        flash(f"Note set on {updated} account(s).", "success")
    else:
        flash(f"Note cleared on {updated} account(s).", "success")
    return redirect(url_for("index"))


@app.route("/set_note/<int:acc_id>", methods=["POST"])
def set_note(acc_id):
    note = (request.form.get("note") or "").strip()[:200]
    db = get_db()
    db.execute("UPDATE accounts SET note = ? WHERE id = ?", (note, acc_id))
    db.commit()
    flash("Note saved.", "success")
    return redirect(url_for("index"))

@app.route("/toggle/<int:acc_id>", methods=["POST"])
def toggle_account(acc_id):
    db = get_db()
    db.execute("UPDATE accounts SET enabled = 1 - enabled WHERE id = ?", (acc_id,))
    db.commit()
    return redirect(url_for("index"))


@app.route("/delete/<int:acc_id>", methods=["POST"])
def delete_account(acc_id):
    db = get_db()
    db.execute("DELETE FROM emails WHERE account_id = ?", (acc_id,))
    db.execute("DELETE FROM accounts WHERE id = ?", (acc_id,))
    db.commit()
    flash("Account deleted.", "info")
    return redirect(url_for("index"))


@app.route("/mark_all_seen", methods=["POST"])
def mark_all_seen():
    db = get_db()
    db.execute("UPDATE emails SET is_new = 0")
    db.commit()
    flash("All marked as seen.", "success")
    return redirect(url_for("index"))


@app.route("/api/stats")
def api_stats():
    """Live stats for auto-refresh of the summary cards."""
    db = get_db()
    stats = db.execute("""
        SELECT COUNT(*) as total,
               SUM(CASE WHEN status = 'ok' THEN 1 ELSE 0 END) as healthy,
               SUM(CASE WHEN status LIKE '%error%' THEN 1 ELSE 0 END) as errors,
               SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled
        FROM accounts
    """).fetchone()
    return jsonify({
        "total": stats["total"] or 0,
        "healthy": stats["healthy"] or 0,
        "errors": stats["errors"] or 0,
        "enabled": stats["enabled"] or 0,
    })


@app.route("/api/account_emails/<int:acc_id>")
def api_account_emails(acc_id):
    """Return emails of one account for the dynamic right panel."""
    db = get_db()
    acc = db.execute("SELECT email, status FROM accounts WHERE id = ?", (acc_id,)).fetchone()
    if not acc:
        return jsonify({"error": "not found"}), 404
    emails = db.execute(
        "SELECT message_id, subject, from_name, from_address, received_at, preview, is_new FROM emails WHERE account_id = ? ORDER BY received_at DESC LIMIT 100",
        (acc_id,)
    ).fetchall()
    return jsonify({
        "email": acc["email"],
        "status": acc["status"],
        "emails": [dict(e) for e in emails]
    })


@app.route("/api/message_body/<int:acc_id>/<path:message_id>")
def api_message_body(acc_id, message_id):
    """Fetch full body of a specific message (on demand)."""
    db = get_db()
    acc = db.execute("SELECT * FROM accounts WHERE id = ?", (acc_id,)).fetchone()
    if not acc:
        return jsonify({"error": "Account not found"}), 404

    # Graph-scoped token only
    proxies = load_proxies()
    proxy = get_random_proxy(proxies) if proxies else None
    client_id, refresh_token, repaired = normalize_oauth_credentials(
        acc["client_id"], acc["refresh_token"]
    )
    if repaired:
        db.execute(
            "UPDATE accounts SET client_id=?, refresh_token=?, status='pending', error_msg=NULL WHERE id=?",
            (client_id, refresh_token, acc_id)
        )
        db.commit()

    access_token, new_refresh, expires_in, method, err = exchange_token(
        client_id, refresh_token, proxy, prefer_graph=True
    )
    if err or not access_token:
        return jsonify({"error": f"Graph token error: {err}"}), 400

    if new_refresh:
        new_exp = (datetime.now(timezone.utc) + timedelta(seconds=int(expires_in) - 60)).isoformat()
        db.execute(
            "UPDATE accounts SET access_token=?, refresh_token=?, token_expires_at=? WHERE id=?",
            (access_token, new_refresh, new_exp, acc_id)
        )
        db.commit()

    # Always try Graph body first
    body_data, err = fetch_message_body_graph(access_token, message_id, proxy)
    if not err and body_data:
        return jsonify(body_data)

    # Fallback: local preview
    row = db.execute(
        "SELECT subject, from_name, from_address, received_at, preview FROM emails WHERE account_id=? AND message_id=?",
        (acc_id, message_id)
    ).fetchone()
    if not row:
        return jsonify({
            "error": (err or "Full body unavailable") +
            " — Token may lack Graph Mail.Read. Re-auth with Graph consent."
        }), 400
    return jsonify({
        "subject": row["subject"],
        "content": row["preview"] or "(Preview only – full body needs a working Graph token.)",
        "contentType": "text",
        "from_name": row["from_name"],
        "from_address": row["from_address"],
        "received_at": row["received_at"],
        "has_attachments": False,
    })


@app.route("/poll_errors_now", methods=["POST"])
def poll_errors_now():
    """Assign new proxies and re-poll only accounts that currently have error status."""
    if poller_state.get("running"):
        flash("A poll is already running. Please wait.", "warning")
        return redirect(url_for("index"))

    def run():
        db = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.row_factory = sqlite3.Row
        accounts = db.execute(
            "SELECT * FROM accounts WHERE enabled = 1 AND status LIKE '%error%' ORDER BY id"
        ).fetchall()
        db.close()
        if not accounts:
            return
        settings = load_settings()
        # 1 attempt only. Any failure stays in ERROR
        run_parallel_poll(
            accounts,
            max_workers=settings.get("max_workers", DEFAULT_MAX_WORKERS),
            max_retries=0
        )

    threading.Thread(target=run, daemon=True).start()
    flash("Re-polling ERROR accounts (1 attempt each, fresh proxies)…", "success")
    return redirect(url_for("index"))


@app.route("/export_email_pass")
def export_email_pass():
    """Download all accounts as email:password .txt"""
    db = get_db()
    rows = db.execute("SELECT email, password FROM accounts ORDER BY id ASC").fetchall()
    lines = []
    for r in rows:
        email = r["email"] or ""
        password = r["password"] or ""
        lines.append(f"{email}:{password}")
    content = "\n".join(lines)
    from flask import Response
    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=accounts_email_pass.txt"}
    )


@app.route("/export_original_format/<field_order>")
def export_original_format(field_order):
    """Download all current accounts in one of the supported four-field import formats."""
    formats = {
        # Keep the original route keys for backward compatibility with the
        # previous build's dashboard links.
        "client_refresh": {
            "fields": ("email", "password", "client_id", "refresh_token"),
            "delimiter": "|",
            "filename": "accounts_pipe_client_refresh.txt",
        },
        "refresh_client": {
            "fields": ("email", "password", "refresh_token", "client_id"),
            "delimiter": "|",
            "filename": "accounts_pipe_refresh_client.txt",
        },
        "dash_client_refresh": {
            "fields": ("email", "password", "client_id", "refresh_token"),
            "delimiter": "----",
            "filename": "accounts_dash_client_refresh.txt",
        },
        "dash_refresh_client": {
            "fields": ("email", "password", "refresh_token", "client_id"),
            "delimiter": "----",
            "filename": "accounts_dash_refresh_client.txt",
        },
        "colon_client_refresh": {
            "fields": ("email", "password", "client_id", "refresh_token"),
            "delimiter": ":",
            "filename": "accounts_colon_client_refresh.txt",
        },
        "colon_refresh_client": {
            "fields": ("email", "password", "refresh_token", "client_id"),
            "delimiter": ":",
            "filename": "accounts_colon_refresh_client.txt",
        },
    }

    selected = formats.get(field_order)
    if selected is None:
        return "Unsupported export format", 400

    db = get_db()
    rows = db.execute(
        "SELECT email, password, client_id, refresh_token FROM accounts ORDER BY id ASC"
    ).fetchall()

    lines = []
    for row in rows:
        values = [(row[field] or "") for field in selected["fields"]]
        lines.append(selected["delimiter"].join(values))

    content = "\n".join(lines)
    from flask import Response
    return Response(
        content,
        mimetype="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{selected["filename"]}"'
        },
    )


@app.route("/api/status")
def api_status():
    return jsonify(poller_state)


# ====================== MAIN ======================
if __name__ == "__main__":
    init_db()
    print("\n" + "=" * 60)
    print("  Outlook Multi-Monitor  •  Professional Edition")
    print("=" * 60)
    print(f"  Open →  http://127.0.0.1:{PORT}")
    print("=" * 60 + "\n")

    # Do NOT auto-start polling. User must click "Start Auto" or "Poll All Now".
    poller_state["stop_requested"] = True
    poller_state["running"] = False
    poller_state["progress"] = "Idle – click Poll All Now or Start Auto"
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)
