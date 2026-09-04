"""
AI Работилница — Backend сървър
Проксира заявките към Anthropic (Smart Name Tool) и Replicate (AI Upscaler),
пази API ключовете скрити и налага дневни лимити на потребител.

Environment variables:
  ANTHROPIC_API_KEY   — за Smart Name Tool (/analyze)
  REPLICATE_API_TOKEN — за AI Upscaler (/upscale)
  ACCESS_CODE         — по избор; ако е зададен, всяка заявка изисква
                        header "X-Access-Code" със същата стойност
"""

import asyncio
import base64
import io
import os
import re
from datetime import date, datetime, timezone, timedelta
from collections import defaultdict

import anthropic
import psycopg2
import psycopg2.extras
import replicate
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import hmac
import hashlib
import random
import time
import requests

# ── Приложение ────────────────────────────────────────────────────────────
app = FastAPI(title="AI Rabotilnica API", version="2.0")

# CORS — разрешава заявки от всеки сайт (systeme.io, локален файл и др.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── API клиенти ───────────────────────────────────────────────────────────
API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
if not API_KEY:
    print("ВНИМАНИЕ: Липсва ANTHROPIC_API_KEY в environment variables!")

REPLICATE_TOKEN = os.environ.get("REPLICATE_API_TOKEN", "")
if not REPLICATE_TOKEN:
    print("ВНИМАНИЕ: Липсва REPLICATE_API_TOKEN — /upscale няма да работи!")

ACCESS_CODE = os.environ.get("ACCESS_CODE", "")

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
if not RESEND_API_KEY:
    print("ВНИМАНИЕ: Липсва RESEND_API_KEY — изпращането на кодове за вход няма да работи!")

SECRET_KEY = os.environ.get("SECRET_KEY", "")
if not SECRET_KEY:
    print("ВНИМАНИЕ: Липсва SECRET_KEY — влизането с код няма да работи безопасно!")

LOGIN_FROM_EMAIL = "PODBG Tools <access@podbg.com>"

claude = anthropic.Anthropic(api_key=API_KEY)

# ── База данни (Neon Postgres) ────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "")
if not DATABASE_URL:
    print("ВНИМАНИЕ: Липсва DATABASE_URL — базата с членовете няма да работи!")


def get_db_connection():
    """Отваря нова връзка към базата. Затваряй я винаги след употреба (with)."""
    return psycopg2.connect(DATABASE_URL, sslmode="require")


def init_db():
    """Създава таблицата members и я обновява, ако още не съществува. Извиква се веднъж при старт."""
    if not DATABASE_URL:
        return
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS members (
                    email        TEXT PRIMARY KEY,
                    name         TEXT,
                    source       TEXT,
                    access_code  TEXT,
                    status       TEXT DEFAULT 'active',
                    created_at   TIMESTAMPTZ DEFAULT now()
                )
                """
            )
            cur.execute(
                "ALTER TABLE members ADD COLUMN IF NOT EXISTS access_code_expires TIMESTAMPTZ"
            )
        conn.commit()


def upsert_member(email: str, name: str, source: str) -> None:
    """Добавя нов член или обновява името/източника, ако имейлът вече съществува."""
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("Липсва имейл.")
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO members (email, name, source)
                VALUES (%s, %s, %s)
                ON CONFLICT (email) DO UPDATE
                    SET name = EXCLUDED.name,
                        source = EXCLUDED.source
                """,
                (email, name, source),
            )
        conn.commit()


def get_member(email: str):
    """Връща реда от members за този имейл (или None), като dict."""
    email = (email or "").strip().lower()
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM members WHERE email = %s", (email,))
            return cur.fetchone()


def set_login_code(email: str, code: str, expires_minutes: int = 15) -> None:
    """Записва нов код за вход и времето му на изтичане за този член."""
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE members SET access_code = %s, access_code_expires = %s WHERE email = %s",
                (code, expires_at, email),
            )
        conn.commit()


def generate_login_code() -> str:
    """Генерира 6-цифрен код за еднократен вход."""
    return f"{random.randint(0, 999999):06d}"


def make_access_token(email: str, days: int = 30) -> str:
    """Прави подписан токен за достъп (без нужда от отделна таблица за сесии)."""
    expires = int(time.time()) + days * 86400
    payload = f"{email}|{expires}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    raw = f"{payload}|{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def verify_access_token(token: str):
    """Проверява токен за достъп; връща имейла, ако е валиден, иначе None."""
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        email, expires, sig = raw.split("|")
        expected_sig = hmac.new(SECRET_KEY.encode(), f"{email}|{expires}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        if int(expires) < int(time.time()):
            return None
        return email
    except Exception:
        return None


def send_login_code_email(to_email: str, code: str) -> None:
    """Изпраща имейл с кода за вход през Resend."""
    if not RESEND_API_KEY:
        raise RuntimeError("RESEND_API_KEY не е зададен.")
    resp = requests.post(
        "https://api.resend.com/emails",
        headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
        json={
            "from": LOGIN_FROM_EMAIL,
            "to": [to_email],
            "subject": f"Твоят код за вход: {code}",
            "html": (
                f"<p>Здравей!</p>"
                f"<p>Твоят код за вход в PODBG Tools Hub е:</p>"
                f"<h2 style=\"letter-spacing:4px;\">{code}</h2>"
                f"<p>Кодът е валиден 15 минути. Ако не си го поискала ти, просто игнорирай това писмо.</p>"
            ),
        },
        timeout=15,
    )
    if resp.status_code >= 300:
        raise RuntimeError(f"Resend грешка ({resp.status_code}): {resp.text}")


@app.on_event("startup")
def _on_startup():
    try:
        init_db()
        print("База данни: таблицата members е готова.")
    except Exception as e:
        print(f"ВНИМАНИЕ: свързването с базата данни се провали при старт: {e}")


# ── Дневни лимити (на IP / ден) ───────────────────────────────────────────
DAILY_LIMIT_ANALYZE = 100  # AI преименувания, дневен лимит
DAILY_LIMIT_UPSCALE = 30   # AI upscale, дневен лимит, стига за един пакет

# { "analyze": { "192.168.1.1": {"date": "2026-07-15", "count": 45} } }
_counts: dict = {
    "analyze": defaultdict(lambda: {"date": "", "count": 0}),
    "upscale": defaultdict(lambda: {"date": "", "count": 0}),
}
_limits = {"analyze": DAILY_LIMIT_ANALYZE, "upscale": DAILY_LIMIT_UPSCALE}


def get_ip(request: Request) -> str:
    """Взима реалния IP на потребителя (включително зад прокси/CDN)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_access(request: Request) -> None:
    """Ако ACCESS_CODE е зададен, изисква валиден X-Access-Code header."""
    if ACCESS_CODE and request.headers.get("X-Access-Code", "") != ACCESS_CODE:
        raise HTTPException(
            status_code=401,
            detail="Невалиден код за достъп. Вземи го от членската зона."
        )


# И двата инструмента се броят на дневна база, за да могат хората да
# минат цял пакет изображения наведнъж, без да чакат месец.
_PERIOD_KIND = {"analyze": "daily", "upscale": "daily"}


def _period_key(kind: str) -> str:
    if _PERIOD_KIND.get(kind) == "monthly":
        today = date.today()
        return f"{today.year}-{today.month:02d}"
    return str(date.today())


def remaining_for(kind: str, ip: str) -> int:
    """Връща броя оставащи заявки за текущия период (ден или месец) за този IP."""
    period = _period_key(kind)
    data   = _counts[kind][ip]
    if data["date"] != period:
        data["date"]  = period
        data["count"] = 0
    return max(0, _limits[kind] - data["count"])


def increment(kind: str, ip: str) -> int:
    """Добавя 1 към брояча и връща оставащите за текущия период."""
    period = _period_key(kind)
    data   = _counts[kind][ip]
    if data["date"] != period:
        data["date"]  = period
        data["count"] = 0
    data["count"] += 1
    return max(0, _limits[kind] - data["count"])


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


class UpscaleRequest(BaseModel):
    image_b64:    str
    media_type:   str          # "image/png" или "image/jpeg"
    scale:        int  = 4     # 2 или 4
    face_enhance: bool = False # включи за портрети/карикатури


# ── Endpoints ─────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "ok", "app": "AI Rabotilnica API", "version": "2.0"}


@app.get("/limit")
def get_limit(request: Request):
    """Връща оставащите заявки за днес за този потребител (двата брояча)."""
    ip = get_ip(request)
    return {
        # запазени имена за съвместимост със Smart Name Tool
        "remaining": remaining_for("analyze", ip),
        "limit":     DAILY_LIMIT_ANALYZE,
        # нови полета за AI Upscaler
        "upscale_remaining": remaining_for("upscale", ip),
        "upscale_limit":     DAILY_LIMIT_UPSCALE,
    }


@app.post("/analyze")
async def analyze_image(req: AnalyzeRequest, request: Request):
    """
    Приема base64 изображение, праща го към Claude,
    връща SEO-оптимизирано файлово име.
    """
    check_access(request)
    ip  = get_ip(request)
    rem = remaining_for("analyze", ip)

    if rem <= 0:
        raise HTTPException(
            status_code=429,
            detail=f"Дневният лимит от {DAILY_LIMIT_ANALYZE} AI анализа е достигнат. Опитай утре."
        )

    prefix_note = f'Start with prefix "{slugify(req.prefix)}-".' if req.prefix else ""

    # Пазим сървъра от прекалено големи изображения (клиентът вече ги смалява
    # преди изпращане, това е допълнителна защита при стар кеширан клиент).
    if len(req.image_b64) > 8 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="Изображението е твърде голямо за анализ. Презареди страницата и опитай пак."
        )

    def _call_claude():
        return claude.messages.create(
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

    try:
        # Изпълнява се в отделна нишка, за да не блокира сървъра, докато
        # чака Claude, точно както при AI Upscaler-а. Иначе при няколко
        # едновременни потребителки заявките се редят една зад друга и
        # изтичат по време, преди Claude изобщо да е отговорил.
        message = await asyncio.to_thread(_call_claude)
    except anthropic.APIError as e:
        raise HTTPException(status_code=502, detail=f"Claude API грешка: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Неочаквана грешка: {str(e)}")

    name      = slugify(message.content[0].text.strip())
    remaining = increment("analyze", ip)

    return {"name": name, "remaining": remaining}


# ── AI Upscaler ───────────────────────────────────────────────────────────
UPSCALE_MODEL   = "nightmareai/real-esrgan"
MAX_INPUT_BYTES = 25 * 1024 * 1024   # 25 MB вход


def _run_upscale(image_bytes: bytes, scale: int, face_enhance: bool) -> str:
    """Блокиращо извикване към Replicate — върти се в отделна нишка.

    При натоварен трафик Replicate връща 429 (throttled) и предлага
    да опитаме пак след няколко секунди. Правим точно това — до 5 опита
    с нарастваща пауза, вместо да връщаме грешка на потребителя веднага.
    """
    max_attempts = 5
    delay = 3  # секунди, нараства с всеки неуспешен опит

    for attempt in range(1, max_attempts + 1):
        try:
            output = replicate.run(
                UPSCALE_MODEL,
                input={
                    "image":        io.BytesIO(image_bytes),
                    "scale":        scale,
                    "face_enhance": face_enhance,
                },
            )
            # Новият replicate клиент връща FileOutput, старият — string URL
            return getattr(output, "url", None) or str(output)
        except Exception as e:
            error_text = str(e).lower()
            is_throttled = "429" in error_text or "throttled" in error_text
            is_oom = "out of memory" in error_text or "cuda" in error_text
            is_retryable = is_throttled or is_oom
            if is_retryable and attempt < max_attempts:
                time.sleep(delay)
                delay += 2
                continue
            raise


@app.post("/upscale")
async def upscale_image(req: UpscaleRequest, request: Request):
    """
    Приема base64 изображение, праща го към Real-ESRGAN на Replicate,
    връща URL към увеличения резултат (валиден ~1 час — свали го веднага).
    """
    check_access(request)

    if not REPLICATE_TOKEN:
        raise HTTPException(status_code=503, detail="Upscale услугата не е конфигурирана.")

    if req.scale not in (2, 4):
        raise HTTPException(status_code=400, detail="scale трябва да е 2 или 4.")

    ip  = get_ip(request)
    rem = remaining_for("upscale", ip)
    if rem <= 0:
        raise HTTPException(
            status_code=429,
            detail=f"Дневният лимит от {DAILY_LIMIT_UPSCALE} AI увеличения е достигнат. Опитай утре, или си вземи добавка (top-up)."
        )

    try:
        image_bytes = base64.b64decode(req.image_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Невалиден base64 вход.")

    if len(image_bytes) > MAX_INPUT_BYTES:
        raise HTTPException(status_code=413, detail="Файлът надвишава 25 MB.")

    try:
        url = await asyncio.to_thread(_run_upscale, image_bytes, req.scale, req.face_enhance)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Replicate грешка: {str(e)}")

    remaining = increment("upscale", ip)
    return {"url": url, "remaining": remaining}

# ── Търсене на член по име (за проверка от Цвета) ─────────────────────────
@app.get("/find-member")
def find_member(q: str):
    """Търси членове по част от името или имейла (без значение главни/малки букви)."""
    if not DATABASE_URL:
        raise HTTPException(status_code=503, detail="DATABASE_URL не е зададен.")
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT email, name, status FROM members WHERE name ILIKE %s OR email ILIKE %s LIMIT 20",
                    (f"%{q}%", f"%{q}%"),
                )
                rows = cur.fetchall()
        return {"query": q, "matches": rows}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Грешка при търсене: {str(e)}")


# ── Проверка на базата данни ──────────────────────────────────────────────
@app.get("/db-check")
def db_check():
    """Прост тест: свързва се с базата и връща броя членове вътре."""
    if not DATABASE_URL:
        raise HTTPException(status_code=503, detail="DATABASE_URL не е зададен.")
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM members")
                count = cur.fetchone()[0]
        return {"database": "ok", "members_count": count}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Връзката с базата се провали: {str(e)}")


# ── Zapier webhook от Skool (New Paid Member) ─────────────────────────────
class SkoolWebhookRequest(BaseModel):
    email: str
    name:  str = ""


@app.post("/skool-webhook")
def skool_webhook(req: SkoolWebhookRequest, request: Request):
    """
    Адрес, който Zapier вика при всеки нов платен член в Skool.
    Пази/обновява записа в таблицата members.
    """
    check_access(request)
    try:
        upsert_member(req.email, req.name, "skool")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Грешка при запис в базата: {str(e)}")

    return {"status": "ok", "email": req.email.strip().lower()}


# ── Вход с код по имейл ────────────────────────────────────────────────────
class RequestCodeRequest(BaseModel):
    email: str


class VerifyCodeRequest(BaseModel):
    email: str
    code:  str


@app.post("/request-code")
async def request_code(req: RequestCodeRequest):
    """Проверява дали имейлът е в списъка с членове и изпраща 6-цифрен код."""
    email = (req.email or "").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Невалиден имейл.")

    member = await asyncio.to_thread(get_member, email)
    if not member or member.get("status") != "active":
        raise HTTPException(
            status_code=404,
            detail="Този имейл не е в списъка с членове на общността."
        )

    code = generate_login_code()
    await asyncio.to_thread(set_login_code, email, code)

    try:
        await asyncio.to_thread(send_login_code_email, email, code)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Грешка при изпращане на имейл: {str(e)}")

    return {"status": "sent"}


@app.post("/verify-code")
async def verify_code(req: VerifyCodeRequest):
    """Проверява кода и връща токен за достъп, ако е верен и все още валиден."""
    email = (req.email or "").strip().lower()
    code  = (req.code or "").strip()

    member = await asyncio.to_thread(get_member, email)
    if not member:
        raise HTTPException(status_code=404, detail="Не е намерен член с този имейл.")

    stored_code = member.get("access_code")
    expires_at  = member.get("access_code_expires")
    now         = datetime.now(timezone.utc)

    if not stored_code or stored_code != code:
        raise HTTPException(status_code=401, detail="Грешен код.")
    if not expires_at or expires_at < now:
        raise HTTPException(status_code=401, detail="Кодът е изтекъл. Поискай нов.")

    token = make_access_token(email)
    return {"status": "ok", "token": token, "name": member.get("name") or ""}


@app.post("/check-token")
async def check_token(request: Request):
    """Проверява дали токен за достъп все още е валиден (за защитените страници)."""
    body  = await request.json()
    token = (body or {}).get("token", "")
    email = verify_access_token(token)
    if not email:
        raise HTTPException(status_code=401, detail="Невалиден или изтекъл достъп.")
    return {"status": "ok", "email": email}

