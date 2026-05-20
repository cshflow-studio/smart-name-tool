"""
Smart Name Tool — Backend сървър
Проксира заявките към Anthropic, пази API ключа скрит,
налага лимит от 100 AI анализа на ден на потребител.
"""

import os
import re
from datetime import date
from collections import defaultdict

import anthropic
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Приложение ────────────────────────────────────────────────────────────
app = FastAPI(title="Smart Name Tool API", version="1.0")

# CORS — разрешава заявки от всеки сайт (systeme.io, локален файл и др.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── Anthropic клиент ──────────────────────────────────────────────────────
API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
if not API_KEY:
    print("ВНИМАНИЕ: Липсва ANTHROPIC_API_KEY в environment variables!")

claude = anthropic.Anthropic(api_key=API_KEY)

# ── Дневен лимит (100 анализа / IP / ден) ────────────────────────────────
DAILY_LIMIT = 100
# { "192.168.1.1": {"date": "2026-05-20", "count": 45} }
_counts: dict = defaultdict(lambda: {"date": "", "count": 0})


def get_ip(request: Request) -> str:
    """Взима реалния IP на потребителя (включително зад прокси/CDN)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def remaining_for(ip: str) -> int:
    """Връща броя оставащи анализи за днес за този IP."""
    today = str(date.today())
    data  = _counts[ip]
    if data["date"] != today:
        data["date"]  = today
        data["count"] = 0
    return max(0, DAILY_LIMIT - data["count"])


def increment(ip: str) -> int:
    """Добавя 1 към брояча и връща оставащите."""
    today = str(date.today())
    data  = _counts[ip]
    if data["date"] != today:
        data["date"]  = today
        data["count"] = 0
    data["count"] += 1
    return max(0, DAILY_LIMIT - data["count"])


def slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    text = re.sub(r"-+", "-", text)
    return text[:120].strip("-")


# ── Модели ────────────────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    image_b64:  str
    media_type: str   # "image/png", "image/jpeg" и др.
    prefix:     str = ""


# ── Endpoints ─────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "ok", "app": "Smart Name Tool API", "version": "1.0"}


@app.get("/limit")
def get_limit(request: Request):
    """Връща колко AI анализа са останали за днес за този потребител."""
    ip  = get_ip(request)
    rem = remaining_for(ip)
    return {"remaining": rem, "limit": DAILY_LIMIT}


@app.post("/analyze")
async def analyze_image(req: AnalyzeRequest, request: Request):
    """
    Приема base64 изображение, праща го към Claude,
    връща SEO-оптимизирано файлово ime.
    """
    ip  = get_ip(request)
    rem = remaining_for(ip)

    if rem <= 0:
        raise HTTPException(
            status_code=429,
            detail=f"Дневният лимит от {DAILY_LIMIT} AI анализа е достигнат. Опитай утре."
        )

    prefix_note = f'Start with prefix "{slugify(req.prefix)}-".' if req.prefix else ""

    try:
        message = claude.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=64,
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type":       "base64",
                            "media_type": req.media_type,
                            "data":       req.image_b64,
                        },
                    },
                    {
                        "type": "text",
                        "text": (
                            "SEO filename for this image. "
                            "Rules: 3-7 words, hyphens, lowercase, no extension. "
                            f"Include subject + style + color. {prefix_note} "
                            "Reply ONLY with the filename. "
                            "Example: watercolor-red-roses-bouquet-floral"
                        ),
                    },
                ],
            }],
        )
    except anthropic.APIError as e:
        raise HTTPException(status_code=502, detail=f"Claude API грешка: {str(e)}")

    name      = slugify(message.content[0].text.strip())
    remaining = increment(ip)

    return {"name": name, "remaining": remaining}
