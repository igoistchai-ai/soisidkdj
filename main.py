import os
import re
import json
import sqlite3
import hashlib
import secrets
import asyncio
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# NZX OSINT TOOL
# Backend — single-file FastAPI server
# ============================================================

app = FastAPI(title="NZX OSINT TOOL")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB = "nzx.db"


# ============================================================
# DATABASE
# ============================================================

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()

    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            avatar TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    con.execute("""
        CREATE TABLE IF NOT EXISTS chains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    con.commit()
    con.close()


init_db()


# ============================================================
# HELPERS
# ============================================================

def now():
    return datetime.now(timezone.utc).isoformat()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def valid_email(email):
    return bool(
        re.match(
            r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$",
            email.strip()
        )
    )


def clean_username(value):
    return re.sub(r"[^a-zA-Z0-9_.-]", "", value.strip())[:32]


def token():
    return secrets.token_urlsafe(32)


# Simple in-memory sessions.
# Fine for a small demo / single Render instance.
SESSIONS = {}


def get_user(request: Request):
    t = request.cookies.get("nzx_session")

    if not t:
        return None

    uid = SESSIONS.get(t)

    if not uid:
        return None

    con = db()
    user = con.execute(
        "SELECT id, username, email, avatar, created_at FROM users WHERE id=?",
        (uid,)
    ).fetchone()
    con.close()

    return dict(user) if user else None


# ============================================================
# FRONTEND
# ============================================================

@app.get("/")
async def index():
    return FileResponse("index.html")


# ============================================================
# AUTH
# ============================================================

@app.post("/api/register")
async def register(request: Request):
    data = await request.json()

    username = clean_username(str(data.get("username", "")))
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if len(username) < 3:
        return JSONResponse(
            {"ok": False, "error": "Username должен содержать минимум 3 символа"},
            status_code=400
        )

    if not valid_email(email):
        return JSONResponse(
            {"ok": False, "error": "Некорректный email"},
            status_code=400
        )

    if len(password) < 6:
        return JSONResponse(
            {"ok": False, "error": "Пароль минимум 6 символов"},
            status_code=400
        )

    con = db()

    try:
        cur = con.execute(
            """
            INSERT INTO users
            (username,email,password_hash,avatar,created_at)
            VALUES (?,?,?,?,?)
            """,
            (
                username,
                email,
                hash_password(password),
                "",
                now()
            )
        )

        uid = cur.lastrowid
        con.commit()

    except sqlite3.IntegrityError:
        con.close()
        return JSONResponse(
            {"ok": False, "error": "Username или email уже используется"},
            status_code=409
        )

    con.close()

    t = token()
    SESSIONS[t] = uid

    response = JSONResponse({
        "ok": True,
        "user": {
            "id": uid,
            "username": username,
            "email": email,
            "avatar": ""
        }
    })

    response.set_cookie(
        "nzx_session",
        t,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 24 * 30
    )

    return response


@app.post("/api/login")
async def login(request: Request):
    data = await request.json()

    login_value = str(data.get("login", "")).strip().lower()
    password = str(data.get("password", ""))

    con = db()

    user = con.execute(
        """
        SELECT id, username, email, avatar, created_at
        FROM users
        WHERE lower(username)=? OR lower(email)=?
        """,
        (login_value, login_value)
    ).fetchone()

    con.close()

    if not user:
        return JSONResponse(
            {"ok": False, "error": "Пользователь не найден"},
            status_code=401
        )

    con = db()
    check = con.execute(
        "SELECT password_hash FROM users WHERE id=?",
        (user["id"],)
    ).fetchone()
    con.close()

    if not check or check["password_hash"] != hash_password(password):
        return JSONResponse(
            {"ok": False, "error": "Неверный пароль"},
            status_code=401
        )

    t = token()
    SESSIONS[t] = user["id"]

    response = JSONResponse({
        "ok": True,
        "user": dict(user)
    })

    response.set_cookie(
        "nzx_session",
        t,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 24 * 30
    )

    return response


@app.post("/api/logout")
async def logout(request: Request):
    t = request.cookies.get("nzx_session")

    if t:
        SESSIONS.pop(t, None)

    response = JSONResponse({"ok": True})
    response.delete_cookie("nzx_session")

    return response


@app.get("/api/me")
async def me(request: Request):
    user = get_user(request)

    return {
        "ok": True,
        "logged": bool(user),
        "user": user
    }


@app.post("/api/profile")
async def profile(request: Request):
    user = get_user(request)

    if not user:
        return JSONResponse(
            {"ok": False, "error": "Не авторизован"},
            status_code=401
        )

    data = await request.json()

    username = clean_username(
        str(data.get("username", user["username"]))
    )

    avatar = str(data.get("avatar", ""))[:1000]

    if len(username) < 3:
        return JSONResponse(
            {"ok": False, "error": "Слишком короткий username"},
            status_code=400
        )

    con = db()

    try:
        con.execute(
            """
            UPDATE users
            SET username=?, avatar=?
            WHERE id=?
            """,
            (username, avatar, user["id"])
        )
        con.commit()

    except sqlite3.IntegrityError:
        con.close()
        return JSONResponse(
            {"ok": False, "error": "Этот username уже занят"},
            status_code=409
        )

    con.close()

    return {
        "ok": True,
        "username": username,
        "avatar": avatar
    }


# ============================================================
# PUBLIC USER SEARCH
# ============================================================

@app.get("/api/users/search")
async def search_users(request: Request):
    q = request.query_params.get("q", "").strip()

    if len(q) < 2:
        return {"ok": True, "users": []}

    con = db()

    rows = con.execute(
        """
        SELECT id, username, avatar, created_at
        FROM users
        WHERE username LIKE ?
        ORDER BY username
        LIMIT 30
        """,
        (f"%{q}%",)
    ).fetchall()

    con.close()

    return {
        "ok": True,
        "users": [dict(x) for x in rows]
    }


# ============================================================
# CHAINS
# ============================================================

@app.get("/api/chains")
async def chains(request: Request):
    user = get_user(request)

    if not user:
        return JSONResponse(
            {"ok": False, "error": "Не авторизован"},
            status_code=401
        )

    con = db()

    rows = con.execute(
        """
        SELECT id,name,data,created_at,updated_at
        FROM chains
        WHERE user_id=?
        ORDER BY updated_at DESC
        """,
        (user["id"],)
    ).fetchall()

    con.close()

    result = []

    for row in rows:
        item = dict(row)

        try:
            item["data"] = json.loads(item["data"])
        except Exception:
            item["data"] = {}

        result.append(item)

    return {
        "ok": True,
        "chains": result
    }


@app.post("/api/chains")
async def save_chain(request: Request):
    user = get_user(request)

    if not user:
        return JSONResponse(
            {"ok": False, "error": "Не авторизован"},
            status_code=401
        )

    data = await request.json()

    name = str(data.get("name", "Untitled Chain")).strip()[:80]
    graph = data.get("data", {})

    con = db()

    cur = con.execute(
        """
        INSERT INTO chains
        (user_id,name,data,created_at,updated_at)
        VALUES (?,?,?,?,?)
        """,
        (
            user["id"],
            name,
            json.dumps(graph, ensure_ascii=False),
            now(),
            now()
        )
    )

    cid = cur.lastrowid

    con.commit()
    con.close()

    return {
        "ok": True,
        "id": cid
    }


@app.put("/api/chains/{chain_id}")
async def update_chain(chain_id: int, request: Request):
    user = get_user(request)

    if not user:
        return JSONResponse(
            {"ok": False, "error": "Не авторизован"},
            status_code=401
        )

    data = await request.json()

    name = str(data.get("name", "Untitled Chain")).strip()[:80]
    graph = data.get("data", {})

    con = db()

    cur = con.execute(
        """
        UPDATE chains
        SET name=?,data=?,updated_at=?
        WHERE id=? AND user_id=?
        """,
        (
            name,
            json.dumps(graph, ensure_ascii=False),
            now(),
            chain_id,
            user["id"]
        )
    )

    con.commit()
    con.close()

    if cur.rowcount == 0:
        return JSONResponse(
            {"ok": False, "error": "Цепочка не найдена"},
            status_code=404
        )

    return {"ok": True}


@app.delete("/api/chains/{chain_id}")
async def delete_chain(chain_id: int, request: Request):
    user = get_user(request)

    if not user:
        return JSONResponse(
            {"ok": False, "error": "Не авторизован"},
            status_code=401
        )

    con = db()

    con.execute(
        "DELETE FROM chains WHERE id=? AND user_id=?",
        (chain_id, user["id"])
    )

    con.commit()
    con.close()

    return {"ok": True}


# ============================================================
# EMAIL OSINT
# ============================================================

async def email_gravatar(email):
    normalized = email.strip().lower()

    h = hashlib.md5(
        normalized.encode()
    ).hexdigest()

    url = f"https://www.gravatar.com/avatar/{h}?d=404"

    try:
        async with httpx.AsyncClient(
            timeout=8,
            follow_redirects=True
        ) as client:

            r = await client.get(url)

            return {
                "service": "GRAVATAR",
                "status": "FOUND" if r.status_code == 200 else "NOT FOUND",
                "url": f"https://www.gravatar.com/avatar/{h}"
            }

    except Exception:
        return {
            "service": "GRAVATAR",
            "status": "UNKNOWN",
            "url": ""
        }


async def email_domain(email):
    domain = email.split("@")[-1].lower()

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                "https://dns.google/resolve",
                params={
                    "name": domain,
                    "type": "MX"
                },
                headers={
                    "Accept": "application/dns-json"
                }
            )

        data = r.json()

        answers = data.get("Answer", [])

        return {
            "service": "DOMAIN / MX",
            "status": "FOUND" if answers else "NOT FOUND",
            "url": ""
        }

    except Exception:
        return {
            "service": "DOMAIN / MX",
            "status": "UNKNOWN",
            "url": ""
        }


async def email_public_checks(email):
    """
    Only checks services that expose a public,
    non-authenticated signal.

    We deliberately don't attempt to bypass account
    recovery pages, CAPTCHA, rate limits or privacy controls.
    """

    results = []

    results.append({
        "service": "EMAIL FORMAT",
        "status": "FOUND" if valid_email(email) else "NOT FOUND",
        "url": ""
    })

    if not valid_email(email):
        return results

    a, b = await asyncio.gather(
        email_gravatar(email),
        email_domain(email)
    )

    results.extend([a, b])

    return results


@app.post("/api/osint/email")
async def email_osint(request: Request):
    data = await request.json()

    email = str(data.get("email", "")).strip().lower()

    if not email:
        return JSONResponse(
            {"ok": False, "error": "Введите email"},
            status_code=400
        )

    if len(email) > 254:
        return JSONResponse(
            {"ok": False, "error": "Слишком длинный email"},
            status_code=400
        )

    results = await email_public_checks(email)

    return {
        "ok": True,
        "query": email,
        "results": results
    }


# ============================================================
# PHONE CHECK
# ============================================================

@app.post("/api/osint/phone")
async def phone_check(request: Request):
    data = await request.json()

    phone = str(data.get("phone", "")).strip()

    digits = re.sub(r"\D", "", phone)

    if len(digits) < 7 or len(digits) > 15:
        return {
            "ok": True,
            "phone": phone,
            "valid": False,
            "status": "INVALID",
            "message": "Количество цифр не соответствует международному диапазону"
        }

    normalized = "+" + digits

    return {
        "ok": True,
        "phone": phone,
        "normalized": normalized,
        "valid": True,
        "status": "FORMAT OK",
        "message": (
            "Номер имеет допустимую международную длину. "
            "Это не подтверждает, что номер реально активен."
        )
    }


# ============================================================
# MAP / ADDRESS SEARCH
# ============================================================

@app.get("/api/map/search")
async def map_search(request: Request):
    q = request.query_params.get("q", "").strip()

    if len(q) < 2:
        return {
            "ok": True,
            "results": []
        }

    url = "https://nominatim.openstreetmap.org/search"

    try:
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.get(
                url,
                params={
                    "q": q,
                    "format": "jsonv2",
                    "addressdetails": 1,
                    "limit": 10
                },
                headers={
                    "User-Agent": "NZX-OSINT-TOOL/1.0"
                }
            )

        if r.status_code != 200:
            return {
                "ok": False,
                "error": "Map provider unavailable"
            }

        raw = r.json()

        results = []

        for item in raw:
            results.append({
                "display_name": item.get("display_name", ""),
                "lat": float(item.get("lat", 0)),
                "lon": float(item.get("lon", 0)),
                "type": item.get("type", ""),
                "category": item.get("category", ""),
                "address": item.get("address", {})
            })

        return {
            "ok": True,
            "results": results
        }

    except Exception as e:
        return {
            "ok": False,
            "error": str(e)
        }


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
async def health():
    return {
        "ok": True,
        "service": "NZX OSINT TOOL",
        "time": now()
    }


# ============================================================
# RENDER
# ============================================================

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "10000"))

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port
    )
