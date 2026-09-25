import os
import re
import sqlite3
import hashlib
import secrets
from pathlib import Path
from typing import Optional

import httpx

from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# ============================================================
# CONFIG
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DB_PATH = os.getenv(
    "DB_PATH",
    str(BASE_DIR / "nzx.db")
)

PORT = int(
    os.getenv("PORT", "10000")
)

# ============================================================
# PHONE VALIDATION API
# ============================================================

PHONEVALIDATION_API_KEY = os.getenv(
    "PHONEVALIDATION_API_KEY",
    ""
).strip()

PHONEVALIDATION_URL = (
    "https://phonevalidationapi.com/api/v1/validate"
)


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="NZX OSINT TOOL",
    version="2.0"
)

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
    return hashlib.sha256(
        password.encode()
    ).hexdigest()


def valid_phone_format(phone: str):

    cleaned = re.sub(
        r"[()\s\-]",
        "",
        phone
    )

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


def safe_value(value, default="UNKNOWN"):

    if value is None:
        return default

    if isinstance(value, str):

        value = value.strip()

        if not value:
            return default

        return value

    return value


# ============================================================
# BASIC
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
async def home():

    html_file = BASE_DIR / "index.html"

    if not html_file.exists():

        return HTMLResponse(
            """
            <h1>NZX OSINT TOOL</h1>
            <p>index.html not found</p>
            """,
            status_code=500
        )

    return HTMLResponse(
        html_file.read_text(
            encoding="utf-8"
        )
    )


@app.get("/api/health")
async def health():

    return {
        "status": "ok",
        "service": "NZX OSINT TOOL",
        "phone_provider": (
            "configured"
            if PHONEVALIDATION_API_KEY
            else "not_configured"
        )
    }


# ============================================================
# PHONE OSINT
# ============================================================

@app.post("/api/osint/phone")
async def phone_osint(
    phone: str = Form(...)
):

    phone = phone.strip()

    # --------------------------------------------------------
    # BASIC LOCAL VALIDATION
    # --------------------------------------------------------

    valid_format, normalized = valid_phone_format(
        phone
    )

    if not valid_format:

        return {
            "success": True,
            "phone": phone,
            "valid": False,
            "possible": False,
            "confidence": "invalid",
            "score": 0,
            "country": "UNKNOWN",
            "country_code": "UNKNOWN",
            "region": "UNKNOWN",
            "city": "UNKNOWN",
            "carrier": "UNKNOWN",
            "line_type": "UNKNOWN",
            "disposable": "UNKNOWN",
            "national": "UNKNOWN",
            "international": "UNKNOWN",
            "e164": "UNKNOWN",
            "source": "local-format-check",
            "provider_status": "INVALID_FORMAT"
        }

    # --------------------------------------------------------
    # BASE RESULT
    # --------------------------------------------------------

    result = {

        "success": True,

        "phone": normalized,

        "valid": None,

        "possible": None,

        "confidence": "UNKNOWN",

        "score": None,

        "reason": "UNKNOWN",

        "country": "UNKNOWN",

        "country_code": "UNKNOWN",

        "region": "UNKNOWN",

        "city": "UNKNOWN",

        "carrier": "UNKNOWN",

        "line_type": "UNKNOWN",

        "disposable": "UNKNOWN",

        "national": "UNKNOWN",

        "international": "UNKNOWN",

        "e164": normalized,

        "source": "none",

        "provider_status": "NO_API_KEY",

        "credits_remaining": None,

        "diagnostics": {}
    }

    # --------------------------------------------------------
    # NO API KEY
    # --------------------------------------------------------

    if not PHONEVALIDATION_API_KEY:

        result["source"] = "local-format-check"

        result["provider_status"] = "NO_API_KEY"

        result["valid"] = None

        result["possible"] = True

        return result

    # --------------------------------------------------------
    # PHONE VALIDATION API
    # --------------------------------------------------------

    payload = {
        "phone": normalized,
        "level": "basic"
    }

    headers = {

        "Authorization":
            f"Bearer {PHONEVALIDATION_API_KEY}",

        "Content-Type":
            "application/json",

        "Accept":
            "application/json",

        "User-Agent":
            "NZX-OSINT-TOOL/2.0"
    }

    try:

        async with httpx.AsyncClient(
            timeout=20,
            follow_redirects=True
        ) as client:

            response = await client.post(
                PHONEVALIDATION_URL,
                headers=headers,
                json=payload
            )

        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        if response.status_code == 200:

            try:
                data = response.json()
            except Exception:

                result["provider_status"] = (
                    "INVALID_PROVIDER_RESPONSE"
                )

                return result

            result["source"] = (
                "phonevalidationapi"
            )

            result["provider_status"] = "OK"

            # ------------------------------------------------
            # MAIN
            # ------------------------------------------------

            if "valid" in data:
                result["valid"] = data.get(
                    "valid"
                )

            if "is_possible" in data:
                result["possible"] = data.get(
                    "is_possible"
                )

            result["confidence"] = safe_value(
                data.get("confidence")
            )

            result["score"] = data.get(
                "score"
            )

            result["reason"] = safe_value(
                data.get("reason")
            )

            # ------------------------------------------------
            # COUNTRY
            # ------------------------------------------------

            country = data.get(
                "country"
            )

            if isinstance(country, dict):

                result["country"] = safe_value(
                    country.get("iso2")
                )

                result["country_code"] = safe_value(
                    country.get("code")
                )

            elif country:

                result["country"] = str(
                    country
                )

            # ------------------------------------------------
            # REGION
            # ------------------------------------------------

            result["region"] = safe_value(
                data.get("region")
            )

            # ------------------------------------------------
            # CARRIER
            # ------------------------------------------------

            result["carrier"] = safe_value(
                data.get("carrier")
            )

            # ------------------------------------------------
            # LINE TYPE
            # ------------------------------------------------

            result["line_type"] = safe_value(
                data.get("line_type")
            )

            # ------------------------------------------------
            # DISPOSABLE
            # ------------------------------------------------

            if "is_disposable" in data:

                disposable = data.get(
                    "is_disposable"
                )

                if disposable is True:
                    result["disposable"] = "YES"

                elif disposable is False:
                    result["disposable"] = "NO"

                else:
                    result["disposable"] = (
                        "UNKNOWN"
                    )

            # ------------------------------------------------
            # FORMATS
            # ------------------------------------------------

            formatted = data.get(
                "formatted"
            )

            if isinstance(
                formatted,
                dict
            ):

                result["e164"] = safe_value(
                    formatted.get("e164"),
                    normalized
                )

                result["national"] = safe_value(
                    formatted.get("national")
                )

                result["international"] = safe_value(
                    formatted.get(
                        "international"
                    )
                )

            # ------------------------------------------------
            # DIAGNOSTICS
            # ------------------------------------------------

            diagnostics = data.get(
                "diagnostics"
            )

            if isinstance(
                diagnostics,
                dict
            ):

                result["diagnostics"] = (
                    diagnostics
                )

            # ------------------------------------------------
            # CREDITS
            # ------------------------------------------------

            if (
                "credits_remaining"
                in data
            ):

                result["credits_remaining"] = (
                    data.get(
                        "credits_remaining"
                    )
                )

            # ------------------------------------------------
            # CITY
            #
            # API does not promise exact city.
            # Do NOT invent it.
            # ------------------------------------------------

            result["city"] = "UNKNOWN"

            return result

        # ----------------------------------------------------
        # API KEY ERROR
        # ----------------------------------------------------

        if response.status_code == 401:

            result["provider_status"] = (
                "API_KEY_REJECTED"
            )

            result["source"] = (
                "phonevalidationapi"
            )

            return result

        # ----------------------------------------------------
        # QUOTA
        # ----------------------------------------------------

        if response.status_code == 402:

            result["provider_status"] = (
                "QUOTA_EXCEEDED"
            )

            result["source"] = (
                "phonevalidationapi"
            )

            try:

                error_data = response.json()

                result["provider_error"] = (
                    error_data
                )

            except Exception:
                pass

            return result

        # ----------------------------------------------------
        # BAD REQUEST
        # ----------------------------------------------------

        if response.status_code == 400:

            result["provider_status"] = (
                "BAD_REQUEST"
            )

            result["source"] = (
                "phonevalidationapi"
            )

            try:

                result["provider_error"] = (
                    response.json()
                )

            except Exception:
                pass

            return result

        # ----------------------------------------------------
        # VALIDATION ERROR
        # ----------------------------------------------------

        if response.status_code == 422:

            result["provider_status"] = (
                "VALIDATION_ERROR"
            )

            result["source"] = (
                "phonevalidationapi"
            )

            try:

                result["provider_error"] = (
                    response.json()
                )

            except Exception:
                pass

            return result

        # ----------------------------------------------------
        # RATE LIMIT
        # ----------------------------------------------------

        if response.status_code == 429:

            result["provider_status"] = (
                "RATE_LIMITED"
            )

            result["source"] = (
                "phonevalidationapi"
            )

            return result

        # ----------------------------------------------------
        # SERVER ERRORS
        # ----------------------------------------------------

        if response.status_code in (
            500,
            502,
            503,
            504
        ):

            result["provider_status"] = (
                f"PROVIDER_HTTP_{response.status_code}"
            )

            result["source"] = (
                "phonevalidationapi"
            )

            return result

        # ----------------------------------------------------
        # OTHER
        # ----------------------------------------------------

        result["provider_status"] = (
            f"PROVIDER_HTTP_{response.status_code}"
        )

        result["source"] = (
            "phonevalidationapi"
        )

        return result

    except httpx.TimeoutException:

        result["provider_status"] = (
            "PROVIDER_TIMEOUT"
        )

        result["source"] = (
            "phonevalidationapi"
        )

        return result

    except Exception as error:

        result["provider_status"] = (
            "PROVIDER_ERROR"
        )

        result["source"] = (
            "phonevalidationapi"
        )

        result["provider_error"] = str(
            error
        )

        return result


# ============================================================
# MAP SEARCH / ADDRESS
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

        "User-Agent":
            "NZX-OSINT-TOOL/2.0",

        "Accept":
            "application/json"
    }

    try:

        async with httpx.AsyncClient(
            timeout=15
        ) as client:

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

            address = item.get(
                "address",
                {}
            )

            results.append({

                "display_name":
                    item.get(
                        "display_name",
                        "UNKNOWN"
                    ),

                "lat":
                    item.get("lat"),

                "lon":
                    item.get("lon"),

                "type":
                    item.get("type"),

                "city":
                    (
                        address.get("city")
                        or address.get("town")
                        or address.get("village")
                        or address.get("municipality")
                        or "UNKNOWN"
                    ),

                "country":
                    address.get(
                        "country",
                        "UNKNOWN"
                    ),

                "country_code":
                    address.get(
                        "country_code",
                        "UNKNOWN"
                    ),

                "postcode":
                    address.get(
                        "postcode",
                        "UNKNOWN"
                    ),

                "state":
                    address.get(
                        "state",
                        "UNKNOWN"
                    ),

                "road":
                    address.get(
                        "road",
                        "UNKNOWN"
                    ),

                "house_number":
                    address.get(
                        "house_number",
                        "UNKNOWN"
                    )
            })

        return {
            "success": True,
            "results": results
        }

    except Exception as error:

        return {
            "success": False,
            "results": [],
            "error": str(error)
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

    email = clean_email(
        email
    )

    if len(username) < 3:

        raise HTTPException(
            status_code=400,
            detail="Username is too short"
        )

    if len(password) < 6:

        raise HTTPException(
            status_code=400,
            detail=(
                "Password must contain "
                "at least 6 characters"
            )
        )

    conn = db()

    try:

        cur = conn.execute(
            """
            INSERT INTO users
            (
                username,
                email,
                password_hash
            )
            VALUES (?,?,?)
            """,
            (
                username,
                email or None,
                hash_password(
                    password
                )
            )
        )

        conn.commit()

        return {
            "success": True,
            "user_id":
                cur.lastrowid
        }

    except sqlite3.IntegrityError:

        raise HTTPException(
            status_code=409,
            detail=(
                "Username or email "
                "already exists"
            )
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
        (
            username.strip(),
        )
    ).fetchone()

    conn.close()

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    if (
        user["password_hash"]
        != hash_password(password)
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    token = secrets.token_urlsafe(
        32
    )

    return {

        "success": True,

        "token": token,

        "user": {

            "id":
                user["id"],

            "username":
                user["username"],

            "email":
                user["email"],

            "avatar":
                user["avatar"]
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
        SELECT
            id,
            username,
            avatar
        FROM users
        WHERE username LIKE ?
        ORDER BY username
        LIMIT 30
        """,
        (
            f"%{q}%",
        )
    ).fetchall()

    conn.close()

    return [

        {
            "id":
                user["id"],

            "username":
                user["username"],

            "avatar":
                user["avatar"]
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

            "username":
                data.username,

            "email":
                data.email,

            "avatar":
                data.avatar
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
