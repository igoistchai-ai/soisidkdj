import os
import re
import sqlite3
import hashlib
import secrets
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# ============================================================
# CONFIG
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.getenv("DB_PATH", str(BASE_DIR / "nzx.db"))
PORT = int(os.getenv("PORT", "10000"))

ABSTRACT_PHONE_API_KEY = os.getenv("ABSTRACT_PHONE_API_KEY", "").strip()
ABSTRACT_EMAIL_API_KEY = os.getenv("ABSTRACT_EMAIL_API_KEY", "").strip()

app = FastAPI(title="NZX OSINT TOOL")

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

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            avatar TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS chains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ============================================================
# HELPERS
# ============================================================

def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()


def valid_phone_format(phone: str):
    cleaned = re.sub(r"[()\s\-]", "", phone)

    if not cleaned.startswith("+"):
        return False, cleaned

    digits = cleaned[1:]

    if not digits.isdigit():
        return False, cleaned

    if not 8 <= len(digits) <= 15:
        return False, cleaned

    return True, cleaned


def clean_email(email: str):
    return email.strip().lower()


# ============================================================
# BASIC
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def home():
    html_file = BASE_DIR / "index.html"

    if not html_file.exists():
        return HTMLResponse(
            "<h1>NZX OSINT TOOL</h1><p>index.html not found</p>",
            status_code=500
        )

    return HTMLResponse(
        html_file.read_text(encoding="utf-8")
    )


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "NZX OSINT TOOL"
    }


# ============================================================
# PHONE OSINT
# ============================================================

@app.post("/api/osint/phone")
async def phone_osint(phone: str = Form(...)):
    """
    Real phone validation.

    We NEVER invent:
      - city
      - region
      - carrier
      - validity

    If provider doesn't return something, it becomes UNKNOWN.
    """

    valid_format, normalized = valid_phone_format(phone)

    if not valid_format:
        return {
            "success": True,
            "phone": phone,
            "valid": False,
            "region": "UNKNOWN",
            "city": "UNKNOWN",
            "country": "UNKNOWN",
            "carrier": "UNKNOWN",
            "line_type": "UNKNOWN",
            "source": "local-format-check",
            "provider_status": "INVALID_FORMAT"
        }

    result = {
        "success": True,
        "phone": normalized,
        "valid": None,
        "region": "UNKNOWN",
        "city": "UNKNOWN",
        "country": "UNKNOWN",
        "carrier": "UNKNOWN",
        "line_type": "UNKNOWN",
        "source": "none",
        "provider_status": "NO_PROVIDER"
    }

    # --------------------------------------------------------
    # ABSTRACT API
    # --------------------------------------------------------

    if ABSTRACT_PHONE_API_KEY:
        try:
            url = "https://phonevalidation.abstractapi.com/v1/"

            params = {
                "api_key": ABSTRACT_PHONE_API_KEY,
                "phone": normalized
            }

            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    url,
                    params=params
                )

            if response.status_code == 200:
                data = response.json()

                result["source"] = "abstractapi"
                result["provider_status"] = "OK"

                # Actual API fields only.
                if "valid" in data:
                    result["valid"] = data.get("valid")

                country = data.get("country") or {}

                if isinstance(country, dict):
                    result["country"] = (
                        country.get("name")
                        or country.get("code")
                        or "UNKNOWN"
                    )

                    result["region"] = (
                        country.get("name")
                        or country.get("code")
                        or "UNKNOWN"
                    )

                elif country:
                    result["country"] = str(country)
                    result["region"] = str(country)

                result["carrier"] = (
                    data.get("carrier")
                    or "UNKNOWN"
                )

                result["line_type"] = (
                    data.get("type")
                    or data.get("line_type")
                    or "UNKNOWN"
                )

                # Some providers may expose city/location.
                # We only use it if actually returned.
                result["city"] = (
                    data.get("city")
                    or data.get("location")
                    or "UNKNOWN"
                )

            elif response.status_code == 401:
                result["provider_status"] = "API_KEY_REJECTED"

            elif response.status_code == 403:
                result["provider_status"] = "FORBIDDEN"

            elif response.status_code == 429:
                result["provider_status"] = "RATE_LIMITED"

            else:
                result["provider_status"] = (
                    f"PROVIDER_HTTP_{response.status_code}"
                )

        except httpx.TimeoutException:
            result["provider_status"] = "PROVIDER_TIMEOUT"

        except Exception:
            result["provider_status"] = "PROVIDER_ERROR"

    # --------------------------------------------------------
    # NO API KEY
    # --------------------------------------------------------

    else:
        result["provider_status"] = "NO_API_KEY"

    return result


# ============================================================
# EMAIL OSINT
# ============================================================

@app.post("/api/osint/email")
async def email_osint(email: str = Form(...)):
    email = clean_email(email)

    syntax_valid = bool(
        re.match(
            r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$",
            email
        )
    )

    if not syntax_valid:
        return {
            "success": True,
            "email": email,
            "valid": False,
            "domain": "UNKNOWN",
            "mx": "UNKNOWN",
            "source": "local-format-check"
        }

    domain = email.split("@", 1)[1]

    result = {
        "success": True,
        "email": email,
        "valid": None,
        "domain": domain,
        "mx": "UNKNOWN",
        "disposable": "UNKNOWN",
        "source": "none",
        "provider_status": "NO_PROVIDER"
    }

    # DNS MX lookup using Google DNS over HTTPS.
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                "https://dns.google/resolve",
                params={
                    "name": domain,
                    "type": "MX"
                }
            )

        if response.status_code == 200:
            data = response.json()

            answers = data.get("Answer", [])

            result["mx"] = "FOUND" if answers else "NOT FOUND"
            result["source"] = "google-dns"
            result["provider_status"] = "OK"

        else:
            result["provider_status"] = (
                f"DNS_HTTP_{response.status_code}"
            )

    except Exception:
        result["provider_status"] = "DNS_ERROR"

    return result


# ============================================================
# MAP SEARCH
# ============================================================

@app.get("/api/map/search")
async def map_search(q: str):
    q = q.strip()

    if not q:
        return {
            "success": False,
            "results": []
        }

    headers = {
        "User-Agent": "NZX-OSINT-TOOL/1.0"
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(
                "https://nominatim.openstreetmap.org/search",
                params={
                    "q": q,
                    "format": "jsonv2",
                    "addressdetails": 1,
                    "limit": 10
                },
                headers=headers
            )

        if response.status_code != 200:
            return {
                "success": False,
                "results": []
            }

        data = response.json()

        results = []

        for item in data:
            address = item.get("address", {})

            results.append({
                "display_name": item.get(
                    "display_name",
                    "UNKNOWN"
                ),
                "lat": item.get("lat"),
                "lon": item.get("lon"),
                "type": item.get("type"),
                "city": (
                    address.get("city")
                    or address.get("town")
                    or address.get("village")
                    or "UNKNOWN"
                ),
                "country": address.get(
                    "country",
                    "UNKNOWN"
                ),
                "postcode": address.get(
                    "postcode",
                    "UNKNOWN"
                )
            })

        return {
            "success": True,
            "results": results
        }

    except Exception:
        return {
            "success": False,
            "results": []
        }


# ============================================================
# AUTH
# ============================================================

@app.post("/api/register")
async def register(
    username: str = Form(...),
    email: str = Form(""),
    password: str = Form(...)
):
    username = username.strip()
    email = clean_email(email)

    if len(username) < 3:
        raise HTTPException(
            status_code=400,
            detail="Username is too short"
        )

    if len(password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 6 characters"
        )

    conn = db()

    try:
        cur = conn.execute(
            """
            INSERT INTO users
            (username,email,password_hash)
            VALUES (?,?,?)
            """,
            (
                username,
                email or None,
                hash_password(password)
            )
        )

        conn.commit()

        return {
            "success": True,
            "user_id": cur.lastrowid
        }

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Username or email already exists"
        )

    finally:
        conn.close()


@app.post("/api/login")
async def login(
    username: str = Form(...),
    password: str = Form(...)
):
    conn = db()

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE username=?
        """,
        (username.strip(),)
    ).fetchone()

    conn.close()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    if user["password_hash"] != hash_password(password):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    token = secrets.token_urlsafe(32)

    return {
        "success": True,
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "avatar": user["avatar"]
        }
    }


# ============================================================
# USER SEARCH
# ============================================================

@app.get("/api/users/search")
async def search_users(q: str):
    q = q.strip()

    if not q:
        return []

    conn = db()

    users = conn.execute(
        """
        SELECT id, username, avatar
        FROM users
        WHERE username LIKE ?
        ORDER BY username
        LIMIT 30
        """,
        (f"%{q}%",)
    ).fetchall()

    conn.close()

    return [
        {
            "id": user["id"],
            "username": user["username"],
            "avatar": user["avatar"]
        }
        for user in users
    ]


# ============================================================
# PROFILE
# ============================================================

class ProfileUpdate(BaseModel):
    username: str
    email: Optional[str] = ""
    avatar: Optional[str] = ""


@app.post("/api/profile")
async def update_profile(
    data: ProfileUpdate
):
    return {
        "success": True,
        "profile": {
            "username": data.username,
            "email": data.email,
            "avatar": data.avatar
        }
    }


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT
    )
