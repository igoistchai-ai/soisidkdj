import os
import re
import json
import uuid
import sqlite3
import hashlib
import secrets
from pathlib import Path
from datetime import datetime

import httpx
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles


# ============================================================
# NZX OSINT TOOL
# MAIN BACKEND
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.getenv("DB_PATH", str(BASE_DIR / "nzx.db"))

PHONE_API_KEY = os.getenv("ABSTRACT_PHONE_API_KEY", "").strip()
EMAIL_API_KEY = os.getenv("ABSTRACT_EMAIL_API_KEY", "").strip()

PORT = int(os.getenv("PORT", "10000"))

AVATAR_DIR = BASE_DIR / "avatars"
AVATAR_DIR.mkdir(exist_ok=True)


app = FastAPI(
    title="NZX OSINT TOOL",
    version="3.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount(
    "/avatars",
    StaticFiles(directory=str(AVATAR_DIR)),
    name="avatars"
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
            password TEXT NOT NULL,
            avatar TEXT,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ============================================================
# HELPERS
# ============================================================

def now():
    return datetime.utcnow().isoformat()


def response_ok(data=None):
    return JSONResponse({
        "ok": True,
        "data": data
    })


def response_error(message, code=400, extra=None):
    payload = {
        "ok": False,
        "error": message
    }

    if extra:
        payload["details"] = extra

    return JSONResponse(payload, status_code=code)


def clean_email(email):
    return email.strip().lower()


def valid_email(email):
    return bool(
        re.match(
            r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
            email
        )
    )


def normalize_phone(phone):
    phone = phone.strip()

    # сохраняем +
    if phone.startswith("+"):
        return "+" + re.sub(r"\D", "", phone[1:])

    return re.sub(r"\D", "", phone)


def get_current_user(request: Request):
    token = request.cookies.get("nzx_session")

    if not token:
        return None

    conn = db()

    row = conn.execute("""
        SELECT users.*
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token = ?
    """, (token,)).fetchone()

    conn.close()

    return row


# ============================================================
# FRONTEND
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def index():
    path = BASE_DIR / "index.html"

    if not path.exists():
        return HTMLResponse(
            "<h1>NZX OSINT TOOL</h1><p>index.html not found</p>",
            status_code=500
        )

    return HTMLResponse(
        path.read_text(encoding="utf-8")
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
async def health():
    return {
        "ok": True,
        "name": "NZX OSINT TOOL",
        "phone_api": bool(PHONE_API_KEY),
        "email_api": bool(EMAIL_API_KEY)
    }


# ============================================================
# AUTH
# ============================================================

@app.post("/api/register")
async def register(request: Request):

    try:
        body = await request.json()
    except Exception:
        return response_error("Invalid JSON")

    username = str(body.get("username", "")).strip()
    email = clean_email(str(body.get("email", "")))
    password = str(body.get("password", ""))

    if len(username) < 3:
        return response_error("Username must contain at least 3 characters")

    if len(password) < 4:
        return response_error("Password must contain at least 4 characters")

    if email and not valid_email(email):
        return response_error("Invalid email")

    conn = db()

    try:
        conn.execute("""
            INSERT INTO users
            (username, email, password, avatar, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            username,
            email or None,
            hashlib.sha256(password.encode()).hexdigest(),
            None,
            now()
        ))

        conn.commit()

    except sqlite3.IntegrityError:
        conn.close()
        return response_error(
            "Username or email already exists",
            409
        )

    conn.close()

    return response_ok({
        "message": "Account created"
    })


@app.post("/api/login")
async def login(request: Request):

    try:
        body = await request.json()
    except Exception:
        return response_error("Invalid JSON")

    login_value = str(body.get("login", "")).strip()
    password = str(body.get("password", ""))

    password_hash = hashlib.sha256(
        password.encode()
    ).hexdigest()

    conn = db()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE (username = ? OR email = ?)
        AND password = ?
    """, (
        login_value,
        login_value.lower(),
        password_hash
    )).fetchone()

    if not user:
        conn.close()
        return response_error(
            "Invalid login or password",
            401
        )

    token = secrets.token_urlsafe(48)

    conn.execute("""
        INSERT INTO sessions
        (token, user_id, created_at)
        VALUES (?, ?, ?)
    """, (
        token,
        user["id"],
        now()
    ))

    conn.commit()
    conn.close()

    response = JSONResponse({
        "ok": True,
        "data": {
            "username": user["username"]
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
        conn = db()

        conn.execute(
            "DELETE FROM sessions WHERE token = ?",
            (token,)
        )

        conn.commit()
        conn.close()

    response = JSONResponse({
        "ok": True
    })

    response.delete_cookie("nzx_session")

    return response


@app.get("/api/me")
async def me(request: Request):

    user = get_current_user(request)

    if not user:
        return response_ok({
            "authenticated": False
        })

    avatar = user["avatar"]

    if avatar:
        avatar = "/avatars/" + avatar

    return response_ok({
        "authenticated": True,
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "avatar": avatar
    })


# ============================================================
# PROFILE / AVATAR
# ============================================================

@app.post("/api/profile")
async def profile(request: Request):

    user = get_current_user(request)

    if not user:
        return response_error(
            "Authentication required",
            401
        )

    try:
        body = await request.json()
    except Exception:
        return response_error("Invalid JSON")

    username = str(
        body.get("username", user["username"])
    ).strip()

    email = clean_email(
        str(body.get("email", user["email"] or ""))
    )

    if len(username) < 3:
        return response_error("Invalid username")

    if email and not valid_email(email):
        return response_error("Invalid email")

    conn = db()

    try:
        conn.execute("""
            UPDATE users
            SET username = ?, email = ?
            WHERE id = ?
        """, (
            username,
            email or None,
            user["id"]
        ))

        conn.commit()

    except sqlite3.IntegrityError:
        conn.close()
        return response_error(
            "Username or email already used",
            409
        )

    conn.close()

    return response_ok()


@app.post("/api/profile/avatar")
async def upload_avatar(
    request: Request,
    file: UploadFile = File(...)
):

    user = get_current_user(request)

    if not user:
        return response_error(
            "Authentication required",
            401
        )

    if not file.filename:
        return response_error("No file selected")

    extension = Path(file.filename).suffix.lower()

    allowed = {
        ".png",
        ".jpg",
        ".jpeg",
        ".webp"
    }

    if extension not in allowed:
        return response_error(
            "Only PNG, JPG, JPEG and WEBP are allowed"
        )

    data = await file.read()

    if len(data) > 5 * 1024 * 1024:
        return response_error(
            "Maximum avatar size is 5 MB"
        )

    filename = (
        str(user["id"])
        + "_"
        + uuid.uuid4().hex
        + extension
    )

    path = AVATAR_DIR / filename

    path.write_bytes(data)

    conn = db()

    old_avatar = user["avatar"]

    conn.execute("""
        UPDATE users
        SET avatar = ?
        WHERE id = ?
    """, (
        filename,
        user["id"]
    ))

    conn.commit()
    conn.close()

    # remove previous avatar
    if old_avatar:
        try:
            old_path = AVATAR_DIR / old_avatar
            if old_path.exists():
                old_path.unlink()
        except Exception:
            pass

    return response_ok({
        "avatar": "/avatars/" + filename
    })


# ============================================================
# USER SEARCH
# ============================================================

@app.get("/api/users/search")
async def search_users(q: str = ""):

    q = q.strip()

    if len(q) < 1:
        return response_ok([])

    conn = db()

    rows = conn.execute("""
        SELECT id, username, avatar, created_at
        FROM users
        WHERE username LIKE ?
        ORDER BY username
        LIMIT 30
    """, (
        "%" + q + "%",
    )).fetchall()

    conn.close()

    result = []

    for row in rows:

        avatar = row["avatar"]

        if avatar:
            avatar = "/avatars/" + avatar

        result.append({
            "id": row["id"],
            "username": row["username"],
            "avatar": avatar
        })

    return response_ok(result)


# ============================================================
# PHONE OSINT
# ============================================================

@app.post("/api/osint/phone")
async def check_phone(request: Request):

    try:
        body = await request.json()
    except Exception:
        return response_error("Invalid JSON")

    original = str(body.get("phone", "")).strip()

    if not original:
        return response_error(
            "Enter a phone number"
        )

    phone = normalize_phone(original)

    digits = re.sub(r"\D", "", phone)

    if len(digits) < 7 or len(digits) > 15:
        return response_error(
            "Invalid phone number length"
        )

    # --------------------------------------------------------
    # API KEY NOT CONFIGURED
    # --------------------------------------------------------

    if not PHONE_API_KEY:

        return response_ok({
            "status": "UNKNOWN",
            "message": "Phone API key is not configured",
            "phone": phone,
            "valid": None,
            "country": "UNKNOWN",
            "region": "UNKNOWN",
            "carrier": "UNKNOWN",
            "line_type": "UNKNOWN",
            "location": "UNKNOWN"
        })

    # --------------------------------------------------------
    # ABSTRACT PHONE API
    # --------------------------------------------------------

    url = "https://phonevalidation.abstractapi.com/v1/"

    params = {
        "api_key": PHONE_API_KEY,
        "phone": phone
    }

    try:

        async with httpx.AsyncClient(
            timeout=15,
            follow_redirects=True
        ) as client:

            r = await client.get(
                url,
                params=params
            )

            try:
                data = r.json()
            except Exception:
                data = {}

    except Exception as e:

        return response_error(
            "Phone API connection failed",
            502,
            {
                "message": str(e)
            }
        )

    # --------------------------------------------------------
    # AUTH ERROR
    # --------------------------------------------------------

    if r.status_code == 401:

        return response_ok({
            "status": "API_ERROR",
            "error_code": 401,
            "message": (
                "Phone API key is invalid or not authorized"
            ),
            "phone": phone
        })

    if r.status_code == 422:

        return response_ok({
            "status": "API_ERROR",
            "error_code": 422,
            "message": (
                "Phone API rejected the request or quota "
                "was reached"
            ),
            "phone": phone,
            "api_response": data
        })

    if r.status_code >= 400:

        return response_ok({
            "status": "API_ERROR",
            "error_code": r.status_code,
            "message": "Phone API returned an error",
            "phone": phone,
            "api_response": data
        })

    # --------------------------------------------------------
    # ABSTRACT RESPONSE
    # --------------------------------------------------------

    country = data.get("country")

    if isinstance(country, dict):
        country_name = (
            country.get("name")
            or country.get("country_name")
            or "UNKNOWN"
        )

        country_code = (
            country.get("code")
            or country.get("country_code")
            or "UNKNOWN"
        )
    else:
        country_name = (
            data.get("country_name")
            or "UNKNOWN"
        )

        country_code = (
            data.get("country_code")
            or "UNKNOWN"
        )

    location = (
        data.get("registered_location")
        or data.get("location")
        or "UNKNOWN"
    )

    region = (
        data.get("region")
        or data.get("state")
        or location
        or "UNKNOWN"
    )

    carrier = (
        data.get("carrier")
        or (
            data.get("phone_carrier", {}).get("name")
            if isinstance(data.get("phone_carrier"), dict)
            else None
        )
        or "UNKNOWN"
    )

    line_type = (
        data.get("line_type")
        or data.get("type")
        or (
            data.get("phone_carrier", {}).get("line_type")
            if isinstance(data.get("phone_carrier"), dict)
            else None
        )
        or "UNKNOWN"
    )

    international = (
        data.get("international_format")
        or data.get("phone_format", {}).get("international")
        if isinstance(data.get("phone_format"), dict)
        else None
    )

    if not international:
        international = phone

    return response_ok({

        "status": "FOUND",

        "phone": phone,

        "valid": data.get("valid"),

        "country": country_name,

        "country_code": country_code,

        "region": region,

        "location": location,

        "carrier": carrier,

        "line_type": line_type,

        "risk_score": data.get("risk_score"),

        "international_format": international,

        "local_format": (
            data.get("local_format")
            or (
                data.get("phone_format", {}).get("national")
                if isinstance(data.get("phone_format"), dict)
                else None
            )
        ),

        "raw": data
    })


# ============================================================
# EMAIL / GMAIL OSINT
# ============================================================

@app.post("/api/osint/email")
async def check_email(request: Request):

    try:
        body = await request.json()
    except Exception:
        return response_error("Invalid JSON")

    email = clean_email(
        str(body.get("email", ""))
    )

    if not email:
        return response_error(
            "Enter an email address"
        )

    if not valid_email(email):
        return response_error(
            "Invalid email format"
        )

    # basic domain
    domain = email.split("@", 1)[1]

    result = {
        "status": "UNKNOWN",
        "email": email,
        "domain": domain,
        "format": True,
        "mx": None,
        "smtp": None,
        "deliverability": None,
        "disposable": None,
        "quality_score": None,
        "message": ""
    }

    # --------------------------------------------------------
    # ABSTRACT EMAIL API
    # --------------------------------------------------------

    if EMAIL_API_KEY:

        url = "https://emailvalidation.abstractapi.com/v1/"

        params = {
            "api_key": EMAIL_API_KEY,
            "email": email
        }

        try:

            async with httpx.AsyncClient(
                timeout=15,
                follow_redirects=True
            ) as client:

                r = await client.get(
                    url,
                    params=params
                )

                try:
                    data = r.json()
                except Exception:
                    data = {}

        except Exception as e:

            result["status"] = "API_ERROR"
            result["message"] = (
                "Email API connection failed"
            )
            result["details"] = str(e)

            return response_ok(result)

        if r.status_code == 401:

            result["status"] = "API_ERROR"
            result["message"] = (
                "Email API key is invalid or not authorized"
            )
            result["error_code"] = 401

            return response_ok(result)

        if r.status_code >= 400:

            result["status"] = "API_ERROR"
            result["error_code"] = r.status_code
            result["message"] = (
                "Email API returned an error"
            )
            result["api_response"] = data

            return response_ok(result)

        result["mx"] = data.get(
            "is_mx_found"
        )

        result["smtp"] = data.get(
            "is_smtp_valid"
        )

        result["deliverability"] = data.get(
            "deliverability"
        )

        result["disposable"] = data.get(
            "is_disposable_email"
        )

        result["quality_score"] = data.get(
            "quality_score"
        )

        result["format"] = data.get(
            "is_valid_format",
            True
        )

        if (
            result["format"] is True
            and result["mx"] is True
        ):
            result["status"] = "FOUND"

        elif (
            result["format"] is False
            or result["mx"] is False
        ):
            result["status"] = "NOT_FOUND"

        else:
            result["status"] = "UNKNOWN"

        # Never claim a specific website account exists
        result["accounts"] = "UNKNOWN"

        return response_ok(result)

    # --------------------------------------------------------
    # NO API KEY
    # --------------------------------------------------------

    result["message"] = (
        "Email API key is not configured. "
        "Only syntax can be checked locally."
    )

    return response_ok(result)


# ============================================================
# ADDRESS / COORDINATES
# ============================================================

@app.get("/api/osint/address")
async def address_search(q: str = ""):

    q = q.strip()

    if not q:
        return response_error(
            "Enter an address, place name or coordinates"
        )

    # --------------------------------------------------------
    # COORDINATES
    # --------------------------------------------------------

    coordinate_match = re.match(
        r"^\s*(-?\d+(?:\.\d+)?)\s*[, ]\s*(-?\d+(?:\.\d+)?)\s*$",
        q
    )

    if coordinate_match:

        lat = float(coordinate_match.group(1))
        lon = float(coordinate_match.group(2))

        if not (-90 <= lat <= 90):
            return response_error(
                "Latitude must be between -90 and 90"
            )

        if not (-180 <= lon <= 180):
            return response_error(
                "Longitude must be between -180 and 180"
            )

        reverse_url = (
            "https://nominatim.openstreetmap.org/reverse"
        )

        params = {
            "lat": lat,
            "lon": lon,
            "format": "jsonv2",
            "zoom": 18,
            "addressdetails": 1
        }

        try:

            async with httpx.AsyncClient(
                timeout=15,
                headers={
                    "User-Agent": "NZX-OSINT-TOOL/3.0"
                }
            ) as client:

                r = await client.get(
                    reverse_url,
                    params=params
                )

                data = r.json()

        except Exception as e:

            return response_error(
                "Map service unavailable",
                502,
                {
                    "message": str(e)
                }
            )

        return response_ok({
            "type": "coordinates",
            "lat": lat,
            "lon": lon,
            "display_name": data.get(
                "display_name",
                "UNKNOWN"
            ),
            "address": data.get(
                "address",
                {}
            ),
            "osm_type": data.get("osm_type"),
            "osm_id": data.get("osm_id")
        })

    # --------------------------------------------------------
    # TEXT SEARCH
    # --------------------------------------------------------

    url = "https://nominatim.openstreetmap.org/search"

    params = {
        "q": q,
        "format": "jsonv2",
        "addressdetails": 1,
        "limit": 8
    }

    try:

        async with httpx.AsyncClient(
            timeout=15,
            headers={
                "User-Agent": "NZX-OSINT-TOOL/3.0"
            }
        ) as client:

            r = await client.get(
                url,
                params=params
            )

            data = r.json()

    except Exception as e:

        return response_error(
            "Map service unavailable",
            502,
            {
                "message": str(e)
            }
        )

    results = []

    for item in data:

        results.append({
            "lat": float(item["lat"]),
            "lon": float(item["lon"]),
            "display_name": item.get(
                "display_name",
                "UNKNOWN"
            ),
            "type": item.get(
                "type",
                "UNKNOWN"
            ),
            "category": item.get(
                "category",
                "UNKNOWN"
            ),
            "address": item.get(
                "address",
                {}
            ),
            "osm_type": item.get("osm_type"),
            "osm_id": item.get("osm_id")
        })

    return response_ok({
        "query": q,
        "results": results
    })


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
