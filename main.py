import os
import re
import json
import time
import hashlib
import secrets
import sqlite3
import socket
import asyncio
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# NZX OSINT TOOL
# Backend: FastAPI
# Files required:
#   main.py
#   index.html
# ============================================================

APP_NAME = "NZX OSINT TOOL"

PORT = int(os.getenv("PORT", "10000"))
DB_PATH = os.getenv("DB_PATH", "nzx.db")

GRAVATAR_API_KEY = os.getenv("GRAVATAR_API_KEY", "").strip()

# Optional external APIs.
# Leave empty if you don't have them.
ABSTRACT_PHONE_API_KEY = os.getenv("ABSTRACT_PHONE_API_KEY", "").strip()
ABSTRACT_EMAIL_API_KEY = os.getenv("ABSTRACT_EMAIL_API_KEY", "").strip()

NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
GRAVATAR_URL = "https://api.gravatar.com/v3/profiles"

USER_AGENT = "NZX-OSINT-TOOL/1.0"

app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DATABASE
# ============================================================

db_lock = asyncio.Lock()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            avatar TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS chains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ============================================================
# SESSION
# ============================================================

SESSIONS = {}


def hash_password(password: str):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def create_session(user_id: int):
    token = secrets.token_urlsafe(40)
    SESSIONS[token] = {
        "user_id": user_id,
        "created_at": time.time()
    }
    return token


def get_session(request: Request):
    token = request.cookies.get("nzx_session")

    if not token:
        return None

    session = SESSIONS.get(token)

    if not session:
        return None

    # 30 days
    if time.time() - session["created_at"] > 60 * 60 * 24 * 30:
        SESSIONS.pop(token, None)
        return None

    return session


def get_current_user(request: Request):
    session = get_session(request)

    if not session:
        return None

    conn = db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    conn.close()

    return dict(user) if user else None


# ============================================================
# BASIC
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def index():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return HTMLResponse(
            "<h1>NZX OSINT TOOL</h1><p>index.html not found</p>",
            status_code=500
        )


@app.get("/api/health")
async def health():
    return {
        "ok": True,
        "app": APP_NAME,
        "time": now(),
        "gravatar": bool(GRAVATAR_API_KEY),
        "phone_provider": bool(ABSTRACT_PHONE_API_KEY),
        "email_provider": bool(ABSTRACT_EMAIL_API_KEY)
    }


# ============================================================
# AUTH
# ============================================================

@app.post("/api/register")
async def register(request: Request):
    data = await request.json()

    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if len(username) < 3:
        raise HTTPException(400, "Username must contain at least 3 characters")

    if not re.match(
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        email
    ):
        raise HTTPException(400, "Invalid email")

    if len(password) < 6:
        raise HTTPException(400, "Password must contain at least 6 characters")

    conn = db()

    exists = conn.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?",
        (username, email)
    ).fetchone()

    if exists:
        conn.close()
        raise HTTPException(409, "Username or email already exists")

    cur = conn.execute(
        """
        INSERT INTO users
        (username, email, password_hash, avatar, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            username,
            email,
            hash_password(password),
            "",
            now()
        )
    )

    conn.commit()
    user_id = cur.lastrowid
    conn.close()

    token = create_session(user_id)

    response = JSONResponse({
        "ok": True,
        "user": {
            "id": user_id,
            "username": username,
            "email": email,
            "avatar": ""
        }
    })

    response.set_cookie(
        "nzx_session",
        token,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 30
    )

    return response


@app.post("/api/login")
async def login(request: Request):
    data = await request.json()

    login_value = str(data.get("login", "")).strip()
    password = str(data.get("password", ""))

    conn = db()

    user = conn.execute(
        """
        SELECT * FROM users
        WHERE username = ? OR email = ?
        """,
        (login_value, login_value.lower())
    ).fetchone()

    conn.close()

    if not user:
        raise HTTPException(401, "Invalid login or password")

    if user["password_hash"] != hash_password(password):
        raise HTTPException(401, "Invalid login or password")

    token = create_session(user["id"])

    response = JSONResponse({
        "ok": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "avatar": user["avatar"] or ""
        }
    })

    response.set_cookie(
        "nzx_session",
        token,
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 30
    )

    return response


@app.post("/api/logout")
async def logout(request: Request):
    token = request.cookies.get("nzx_session")

    if token:
        SESSIONS.pop(token, None)

    response = JSONResponse({"ok": True})
    response.delete_cookie("nzx_session")

    return response


@app.get("/api/me")
async def me(request: Request):
    user = get_current_user(request)

    if not user:
        return {
            "authenticated": False,
            "user": None
        }

    return {
        "authenticated": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "avatar": user["avatar"] or ""
        }
    }


@app.post("/api/profile")
async def profile(request: Request):
    user = get_current_user(request)

    if not user:
        raise HTTPException(401, "Login required")

    data = await request.json()

    username = str(
        data.get("username", user["username"])
    ).strip()

    avatar = str(
        data.get("avatar", user["avatar"] or "")
    ).strip()

    if len(username) < 3:
        raise HTTPException(400, "Invalid username")

    conn = db()

    duplicate = conn.execute(
        "SELECT id FROM users WHERE username = ? AND id != ?",
        (username, user["id"])
    ).fetchone()

    if duplicate:
        conn.close()
        raise HTTPException(409, "Username already exists")

    conn.execute(
        """
        UPDATE users
        SET username = ?, avatar = ?
        WHERE id = ?
        """,
        (username, avatar, user["id"])
    )

    conn.commit()
    conn.close()

    return {
        "ok": True,
        "username": username,
        "avatar": avatar
    }


# ============================================================
# USER SEARCH
# ============================================================

@app.get("/api/users/search")
async def search_users(q: str = ""):
    q = q.strip()

    if not q:
        return {"results": []}

    conn = db()

    rows = conn.execute(
        """
        SELECT id, username, avatar, created_at
        FROM users
        WHERE username LIKE ?
        ORDER BY username
        LIMIT 30
        """,
        (f"%{q}%",)
    ).fetchall()

    conn.close()

    return {
        "results": [
            {
                "id": x["id"],
                "username": x["username"],
                "avatar": x["avatar"] or "",
                "created_at": x["created_at"]
            }
            for x in rows
        ]
    }


# ============================================================
# CHAINS
# ============================================================

@app.get("/api/chains")
async def get_chains(request: Request):
    user = get_current_user(request)

    if not user:
        raise HTTPException(401, "Login required")

    conn = db()

    rows = conn.execute(
        """
        SELECT id, name, data, created_at, updated_at
        FROM chains
        WHERE user_id = ?
        ORDER BY updated_at DESC
        """,
        (user["id"],)
    ).fetchall()

    conn.close()

    result = []

    for row in rows:
        try:
            parsed = json.loads(row["data"])
        except Exception:
            parsed = {}

        result.append({
            "id": row["id"],
            "name": row["name"],
            "data": parsed,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"]
        })

    return {"chains": result}


@app.post("/api/chains")
async def create_chain(request: Request):
    user = get_current_user(request)

    if not user:
        raise HTTPException(401, "Login required")

    data = await request.json()

    name = str(data.get("name", "")).strip() or "Untitled Chain"
    chain_data = data.get("data", {})

    conn = db()

    cur = conn.execute(
        """
        INSERT INTO chains
        (user_id, name, data, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            user["id"],
            name,
            json.dumps(chain_data, ensure_ascii=False),
            now(),
            now()
        )
    )

    conn.commit()
    chain_id = cur.lastrowid
    conn.close()

    return {
        "ok": True,
        "id": chain_id
    }


@app.put("/api/chains/{chain_id}")
async def update_chain(chain_id: int, request: Request):
    user = get_current_user(request)

    if not user:
        raise HTTPException(401, "Login required")

    data = await request.json()

    name = str(data.get("name", "")).strip() or "Untitled Chain"
    chain_data = data.get("data", {})

    conn = db()

    result = conn.execute(
        """
        UPDATE chains
        SET name = ?, data = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
        """,
        (
            name,
            json.dumps(chain_data, ensure_ascii=False),
            now(),
            chain_id,
            user["id"]
        )
    )

    conn.commit()
    conn.close()

    if result.rowcount == 0:
        raise HTTPException(404, "Chain not found")

    return {"ok": True}


@app.delete("/api/chains/{chain_id}")
async def delete_chain(chain_id: int, request: Request):
    user = get_current_user(request)

    if not user:
        raise HTTPException(401, "Login required")

    conn = db()

    result = conn.execute(
        """
        DELETE FROM chains
        WHERE id = ? AND user_id = ?
        """,
        (chain_id, user["id"])
    )

    conn.commit()
    conn.close()

    if result.rowcount == 0:
        raise HTTPException(404, "Chain not found")

    return {"ok": True}


# ============================================================
# EMAIL
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def email_parts(email):
    email = email.strip().lower()

    if "@" not in email:
        return None, None

    local, domain = email.rsplit("@", 1)

    return local, domain


async def dns_mx(domain):
    """
    Uses Google's DNS-over-HTTPS resolver.
    This checks whether DNS has MX records.
    It does NOT prove that an individual mailbox exists.
    """

    url = (
        "https://dns.google/resolve"
        f"?name={quote(domain)}&type=MX"
    )

    try:
        async with httpx.AsyncClient(
            timeout=8,
            headers={"User-Agent": USER_AGENT}
        ) as client:

            response = await client.get(url)

        if response.status_code != 200:
            return {
                "status": "UNKNOWN",
                "reason": "DNS provider unavailable"
            }

        payload = response.json()

        answers = payload.get("Answer", [])

        mx = []

        for answer in answers:
            value = str(answer.get("data", "")).strip()

            if value:
                mx.append(value)

        if mx:
            return {
                "status": "FOUND",
                "reason": "MX records exist",
                "records": mx
            }

        return {
            "status": "NOT_FOUND",
            "reason": "No MX records found",
            "records": []
        }

    except Exception as e:
        return {
            "status": "UNKNOWN",
            "reason": str(e),
            "records": []
        }


async def gravatar_lookup(email):
    clean = email.strip().lower()

    email_hash = hashlib.sha256(
        clean.encode("utf-8")
    ).hexdigest()

    result = {
        "service": "Gravatar",
        "status": "UNKNOWN",
        "url": f"https://gravatar.com/{email_hash}",
        "avatar": (
            f"https://0.gravatar.com/avatar/{email_hash}"
        ),
        "profile": None,
        "hash": email_hash
    }

    try:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json"
        }

        if GRAVATAR_API_KEY:
            headers["Authorization"] = (
                f"Bearer {GRAVATAR_API_KEY}"
            )

        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=True,
            headers=headers
        ) as client:

            response = await client.get(
                f"{GRAVATAR_URL}/{email_hash}"
            )

        if response.status_code == 200:
            payload = response.json()

            result["status"] = "FOUND"
            result["profile"] = payload

            if payload.get("profile_url"):
                result["url"] = payload["profile_url"]

            if payload.get("avatar_url"):
                result["avatar"] = payload["avatar_url"]

        elif response.status_code == 404:
            result["status"] = "NOT_FOUND"

        elif response.status_code == 429:
            result["status"] = "UNKNOWN"
            result["reason"] = "Rate limit exceeded"

        else:
            result["status"] = "UNKNOWN"
            result["reason"] = f"HTTP {response.status_code}"

    except Exception as e:
        result["status"] = "UNKNOWN"
        result["reason"] = str(e)

    return result


async def abstract_email_check(email):
    if not ABSTRACT_EMAIL_API_KEY:
        return {
            "service": "Email Intelligence",
            "status": "UNKNOWN",
            "reason": "API key not configured"
        }

    # Abstract Email Validation API.
    url = (
        "https://emailvalidation.abstractapi.com/v1/"
        f"?api_key={quote(ABSTRACT_EMAIL_API_KEY)}"
        f"&email={quote(email)}"
    )

    try:
        async with httpx.AsyncClient(
            timeout=12,
            headers={"User-Agent": USER_AGENT}
        ) as client:

            response = await client.get(url)

        if response.status_code != 200:
            return {
                "service": "Email Intelligence",
                "status": "UNKNOWN",
                "reason": f"HTTP {response.status_code}"
            }

        payload = response.json()

        deliverability = (
            payload.get("is_smtp_valid", {})
            .get("value")
        )

        if deliverability is True:
            status = "FOUND"
            reason = "SMTP validation indicates the domain/mail system accepts validation"
        elif deliverability is False:
            status = "NOT_FOUND"
            reason = "SMTP validation failed"
        else:
            status = "UNKNOWN"
            reason = "Provider did not return a definitive result"

        return {
            "service": "Email Intelligence",
            "status": status,
            "reason": reason,
            "raw": payload
        }

    except Exception as e:
        return {
            "service": "Email Intelligence",
            "status": "UNKNOWN",
            "reason": str(e)
        }


@app.post("/api/osint/email")
async def osint_email(request: Request):
    data = await request.json()

    email = str(data.get("email", "")).strip().lower()

    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Invalid email address")

    local, domain = email_parts(email)

    started = time.time()

    results = []

    # 1. Syntax
    results.append({
        "service": "Email Syntax",
        "status": "FOUND",
        "reason": "Email format is syntactically valid"
    })

    # 2. Domain
    results.append({
        "service": "Domain",
        "status": "FOUND",
        "value": domain,
        "reason": "Domain extracted from email"
    })

    # 3. MX
    mx = await dns_mx(domain)

    results.append({
        "service": "DNS / MX",
        "status": mx["status"],
        "reason": mx.get("reason", ""),
        "records": mx.get("records", [])
    })

    # 4. Gravatar
    gravatar = await gravatar_lookup(email)
    results.append(gravatar)

    # 5. Optional email intelligence provider
    provider = await abstract_email_check(email)
    results.append(provider)

    return {
        "ok": True,
        "query": email,
        "local": local,
        "domain": domain,
        "elapsed_ms": round(
            (time.time() - started) * 1000
        ),
        "results": results,
        "summary": {
            "found": sum(
                1 for x in results
                if x.get("status") == "FOUND"
            ),
            "not_found": sum(
                1 for x in results
                if x.get("status") == "NOT_FOUND"
            ),
            "unknown": sum(
                1 for x in results
                if x.get("status") == "UNKNOWN"
            )
        }
    }


# ============================================================
# PHONE
# ============================================================

def normalize_phone(phone):
    phone = phone.strip()

    if phone.startswith("00"):
        phone = "+" + phone[2:]

    cleaned = re.sub(
        r"[^\d+]",
        "",
        phone
    )

    if cleaned.startswith("+"):
        cleaned = "+" + re.sub(
            r"\D",
            "",
            cleaned[1:]
        )
    else:
        cleaned = re.sub(r"\D", "", cleaned)

    return cleaned


async def abstract_phone_lookup(phone):
    if not ABSTRACT_PHONE_API_KEY:
        return {
            "service": "Phone Intelligence",
            "status": "UNKNOWN",
            "reason": "API key not configured"
        }

    url = (
        "https://phonevalidation.abstractapi.com/v1/"
        f"?api_key={quote(ABSTRACT_PHONE_API_KEY)}"
        f"&phone={quote(phone)}"
    )

    try:
        async with httpx.AsyncClient(
            timeout=12,
            headers={"User-Agent": USER_AGENT}
        ) as client:

            response = await client.get(url)

        if response.status_code != 200:
            return {
                "service": "Phone Intelligence",
                "status": "UNKNOWN",
                "reason": f"HTTP {response.status_code}"
            }

        payload = response.json()

        valid = payload.get("valid")

        if valid is True:
            status = "FOUND"
            reason = "Provider considers the number valid"
        elif valid is False:
            status = "NOT_FOUND"
            reason = "Provider considers the number invalid"
        else:
            status = "UNKNOWN"
            reason = "Provider returned no definitive validation"

        return {
            "service": "Phone Intelligence",
            "status": status,
            "reason": reason,
            "country": payload.get("country"),
            "country_code": payload.get("country_code"),
            "type": payload.get("type"),
            "carrier": payload.get("carrier"),
            "raw": payload
        }

    except Exception as e:
        return {
            "service": "Phone Intelligence",
            "status": "UNKNOWN",
            "reason": str(e)
        }


@app.post("/api/osint/phone")
async def osint_phone(request: Request):
    data = await request.json()

    original = str(data.get("phone", "")).strip()

    if not original:
        raise HTTPException(400, "Phone is required")

    phone = normalize_phone(original)

    digits = re.sub(r"\D", "", phone)

    results = []

    if 7 <= len(digits) <= 15:
        results.append({
            "service": "Phone Format",
            "status": "FOUND",
            "reason": "Number has a plausible international length",
            "value": phone
        })
    else:
        results.append({
            "service": "Phone Format",
            "status": "NOT_FOUND",
            "reason": "Number length is outside the normal international range",
            "value": phone
        })

    # Do NOT claim carrier/operator/etc. without a real provider.
    provider = await abstract_phone_lookup(phone)
    results.append(provider)

    return {
        "ok": True,
        "query": original,
        "normalized": phone,
        "results": results
    }


# ============================================================
# MAP
# ============================================================

@app.get("/api/map/search")
async def map_search(q: str = ""):
    q = q.strip()

    if not q:
        raise HTTPException(400, "Search query required")

    params = {
        "q": q,
        "format": "jsonv2",
        "addressdetails": 1,
        "limit": 8,
        "accept-language": "en"
    }

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json"
    }

    try:
        async with httpx.AsyncClient(
            timeout=12,
            headers=headers
        ) as client:

            response = await client.get(
                NOMINATIM_URL,
                params=params
            )

        if response.status_code != 200:
            return {
                "ok": False,
                "error": f"Map provider HTTP {response.status_code}"
            }

        payload = response.json()

        results = []

        for item in payload:
            results.append({
                "place_id": item.get("place_id"),
                "display_name": item.get("display_name"),
                "lat": float(item["lat"]),
                "lon": float(item["lon"]),
                "type": item.get("type"),
                "class": item.get("class"),
                "importance": item.get("importance"),
                "address": item.get("address", {})
            })

        return {
            "ok": True,
            "query": q,
            "results": results
        }

    except Exception as e:
        return {
            "ok": False,
            "error": str(e)
        }


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        reload=False
    )
