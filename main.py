import os
import json
import base64
import re
from typing import Optional

import httpx
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_FILE = os.path.join(BASE_DIR, "index.html")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3-flash-preview").strip()
MAX_IMAGE_SIZE = 10 * 1024 * 1024

app = FastAPI(title="NZX OSINT TOOL", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def index():
    if not os.path.exists(INDEX_FILE):
        raise HTTPException(500, "index.html not found")
    return FileResponse(INDEX_FILE, media_type="text/html")


@app.get("/health")
async def health():
    return {
        "ok": True,
        "service": "NZX OSINT TOOL",
        "gemini_configured": bool(GEMINI_API_KEY),
        "model": GEMINI_MODEL,
    }


# -----------------------------
# PHONE CHECK
# -----------------------------

COUNTRY_PREFIXES = {
    "+374": "Armenia",
    "+7": "Russia / Kazakhstan",
    "+1": "United States / Canada",
    "+44": "United Kingdom",
    "+49": "Germany",
    "+33": "France",
    "+39": "Italy",
    "+34": "Spain",
    "+380": "Ukraine",
    "+995": "Georgia",
    "+90": "Turkey",
    "+971": "United Arab Emirates",
    "+972": "Israel",
    "+81": "Japan",
    "+82": "South Korea",
    "+86": "China",
    "+91": "India",
    "+61": "Australia",
    "+55": "Brazil",
    "+52": "Mexico",
    "+31": "Netherlands",
    "+32": "Belgium",
    "+41": "Switzerland",
    "+43": "Austria",
    "+46": "Sweden",
    "+47": "Norway",
    "+45": "Denmark",
    "+358": "Finland",
    "+48": "Poland",
    "+420": "Czech Republic",
    "+421": "Slovakia",
    "+359": "Bulgaria",
    "+30": "Greece",
}


def normalize_phone(value: str) -> str:
    value = value.strip()
    if value.startswith("00"):
        value = "+" + value[2:]
    if not value.startswith("+"):
        value = "+" + value
    return "+" + re.sub(r"\D", "", value[1:])


def phone_country(phone: str) -> str:
    for prefix in sorted(COUNTRY_PREFIXES, key=len, reverse=True):
        if phone.startswith(prefix):
            return COUNTRY_PREFIXES[prefix]
    return "UNKNOWN"


@app.post("/api/osint/phone")
async def phone_check(phone: str = Form(...)):
    normalized = normalize_phone(phone)
    digits = normalized[1:]

    if len(digits) < 7 or len(digits) > 15:
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid phone number format"},
        )

    country = phone_country(normalized)

    # This endpoint deliberately does not invent subscriber identity/data.
    return {
        "success": True,
        "phone": normalized,
        "e164": normalized,
        "number": normalized,
        "country": country,
        "region": "UNKNOWN",
        "city": "UNKNOWN",
        "timezone": "UNKNOWN",
        "time_code": "UNKNOWN",
        "note": "Only format/prefix information is available without a carrier/subscriber data provider.",
    }


# -----------------------------
# ADDRESS SEARCH — OpenStreetMap Nominatim
# -----------------------------

@app.get("/api/map/search")
async def map_search(q: str):
    query = q.strip()
    if not query:
        raise HTTPException(400, "Missing q")

    headers = {
        "User-Agent": "NZX-OSINT-TOOL/2.0 (address search)"
    }

    try:
        async with httpx.AsyncClient(timeout=15, headers=headers) as client:
            response = await client.get(
                "https://nominatim.openstreetmap.org/search",
                params={
                    "q": query,
                    "format": "jsonv2",
                    "addressdetails": 1,
                    "limit": 5,
                },
            )
    except httpx.TimeoutException:
        raise HTTPException(504, "Address search timed out")
    except Exception as exc:
        raise HTTPException(502, str(exc))

    if response.status_code >= 400:
        raise HTTPException(response.status_code, "Address provider error")

    try:
        raw = response.json()
    except Exception:
        raise HTTPException(502, "Invalid address provider response")

    results = []
    for item in raw:
        address = item.get("address") or {}
        city = (
            address.get("city")
            or address.get("town")
            or address.get("village")
            or address.get("municipality")
            or "UNKNOWN"
        )
        country = address.get("country") or "UNKNOWN"
        postcode = address.get("postcode") or "UNKNOWN"

        results.append({
            "display_name": item.get("display_name") or "UNKNOWN",
            "lat": item.get("lat"),
            "lon": item.get("lon"),
            "city": city,
            "country": country,
            "postcode": postcode,
        })

    return {"success": True, "results": results}


# -----------------------------
# GEOSINT — Gemini Vision
# -----------------------------

GEOSINT_PROMPT = """
You are the GeoSINT visual analysis module of NZX OSINT TOOL.

Analyze ONLY geographic information that is visibly supported by the image.

Return ONLY valid JSON using exactly this structure:
{
  "country": "",
  "city_estimate": "",
  "region_estimate": "",
  "latitude": null,
  "longitude": null,
  "environment": "",
  "visible_clues": [],
  "confidence": "low|medium|high",
  "reasoning": ""
}

Rules:
- Estimate a broad geographic area from visible evidence.
- Never identify a private person.
- Never infer someone's identity.
- Never claim an exact private residential address.
- Coordinates are optional estimates only; use null when unsupported.
- If there is not enough evidence, use UNKNOWN and null.
- Never invent signs, landmarks, languages, road markings or other clues.
- Use visible clues such as public signs, public landmarks, architecture,
  terrain, vegetation, road markings, visible language, public transport,
  utility infrastructure and climate.
- Keep reasoning concise and evidence-based.
""".strip()


def extract_gemini_text(data: dict) -> str:
    candidates = data.get("candidates") or []
    if not candidates:
        return ""

    content = candidates[0].get("content") or {}
    parts = content.get("parts") or []

    texts = []
    for part in parts:
        if isinstance(part, dict) and isinstance(part.get("text"), str):
            texts.append(part["text"])
    return "\n".join(texts).strip()


def parse_json_text(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.I)
        text = re.sub(r"\s*```$", "", text)

    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {"raw": value}
    except Exception:
        # Try to recover the first JSON object from a verbose response.
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                value = json.loads(text[start:end + 1])
                return value if isinstance(value, dict) else {"raw": value}
            except Exception:
                pass

    return {"raw": text}


@app.post("/api/geosint")
async def geosint(
    photo: UploadFile = File(...),
    prompt: str = Form(""),
):
    if not GEMINI_API_KEY:
        raise HTTPException(
            503,
            "GEMINI_API_KEY is not configured in Render Environment Variables",
        )

    image = await photo.read()

    if not image:
        raise HTTPException(400, "Empty image")

    if len(image) > MAX_IMAGE_SIZE:
        raise HTTPException(413, "Image is larger than 10 MB")

    content_type = photo.content_type or "image/jpeg"
    if not content_type.startswith("image/"):
        raise HTTPException(400, "Only image files are supported")

    image_b64 = base64.b64encode(image).decode("ascii")

    user_prompt = GEOSINT_PROMPT
    if prompt.strip():
        user_prompt += "\n\nAdditional task context:\n" + prompt.strip()

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {"text": user_prompt},
                    {
                        "inline_data": {
                            "mime_type": content_type,
                            "data": image_b64,
                        }
                    },
                ],
            }
        ],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{GEMINI_MODEL}:generateContent"
    )

    try:
        async with httpx.AsyncClient(timeout=120) as client:
            response = await client.post(
                url,
                headers={
                    "x-goog-api-key": GEMINI_API_KEY,
                    "Content-Type": "application/json",
                },
                json=payload,
            )
    except httpx.TimeoutException:
        raise HTTPException(504, "Gemini request timed out")
    except Exception as exc:
        raise HTTPException(502, f"Gemini connection error: {exc}")

    try:
        data = response.json()
    except Exception:
        data = {"raw": response.text}

    if response.status_code >= 400:
        error = data.get("error") if isinstance(data, dict) else None
        message = error.get("message") if isinstance(error, dict) else None
        raise HTTPException(
            response.status_code,
            message or "Gemini API error",
        )

    text = extract_gemini_text(data)
    result = parse_json_text(text)

    if not result:
        result = {"raw": text or "Gemini returned an empty response"}

    return {
        "success": True,
        "provider": "Google Gemini",
        "model": GEMINI_MODEL,
        "result": result,
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "10000"))
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info",
    )
