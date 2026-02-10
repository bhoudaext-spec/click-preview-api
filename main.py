from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from user_agents import parse
import re

app = FastAPI(title="SMS Click vs Preview Detection API", version="2.2")

# ============================================
#  CONFIGURATION
# ============================================
API_KEY = "SUPER_SECRET_KEY_123"
AUTHORIZED_IPS = ("127.0.0.1", "::1")

# ============================================
#  REQUÊTE
# ============================================
class DetectRequest(BaseModel):
    url: str

# ============================================
#  SECURITÉ
# ============================================
@app.middleware("http")
async def restrict_access(request: Request, call_next):
    # Routes publiques
    public_paths = ["/", "/docs", "/openapi.json", "/favicon.ico"]

    if request.url.path in public_paths:
        return await call_next(request)

    client_ip = request.client.host
    api_key = request.headers.get("x-api-key")

    if client_ip not in AUTHORIZED_IPS:
        raise HTTPException(status_code=403, detail="Access denied")

    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")

    return await call_next(request)


# ============================================
#  DETECTION CLICK / PREVIEW / IGNORE
# ============================================
@app.post("/api/detect")
async def detect_event(request: Request, body: DetectRequest):
    user_agent = request.headers.get("user-agent", "").lower()
    headers = dict(request.headers)
    ip = request.client.host or "unknown"
    ua = parse(user_agent)

    reasons = []
    score = 0

    # --- 1️⃣ Détection bots / preview ---
    preview_signatures = [
        "whatsapp", "facebookexternalhit", "twitterbot", "slackbot",
        "discordbot", "linkedinbot", "bot", "crawl", "spider",
        "render", "headlesschrome", "googleapp", "prefetch",
        "stagefright", "wv", "webview", "preview"
    ]
    if any(sig in user_agent for sig in preview_signatures):
        return {
            "event": "preview",
            "confidence": 0.99,
            "reasons": ["ua:preview_or_bot_detected"],
            "ip": ip
        }

    # --- 2️⃣ Détection Desktop → ignoré complètement ---
    desktop_keywords = [
        "windows nt", "macintosh", "x11", "linux x86", "ubuntu", "intel mac"
    ]
    if ua.is_pc or any(k in user_agent for k in desktop_keywords):
        return {
            "event": "ignore",
            "confidence": 1.0,
            "reasons": ["ua:desktop_device"],
            "ip": ip,
            "user_agent": user_agent[:120]
        }

    # --- 3️⃣ Headers "prefetch" ---
    if headers.get("sec-purpose", "").lower() == "prefetch":
        return {
            "event": "preview",
            "confidence": 0.95,
            "reasons": ["header:prefetch"],
            "ip": ip
        }

    # --- 4️⃣ Détection mobile / tablette ---
    if ua.is_mobile:
        score += 3
        reasons.append("ua:mobile_device")
    elif ua.is_tablet:
        score += 2
        reasons.append("ua:tablet_device")

    # --- 5️⃣ Navigateurs humains ---
    if re.search(r"(chrome|safari|firefox|edge|opera)", user_agent):
        score += 2
        reasons.append("ua:known_browser")

    # --- 6️⃣ Chrome version check ---
    match = re.search(r"chrome/(\d+)", user_agent)
    if match:
        version = int(match.group(1))
        if version > 130:
            reasons.append("ua:fake_chrome_version")
        else:
            score += 1
            reasons.append("ua:valid_chrome_version")

    # --- 7️⃣ Headers humains ---
    if headers.get("sec-fetch-user") == "?1":
        score += 2
        reasons.append("header:sec-fetch-user")

    # --- 8️⃣ IP mobile ---
    if any(ip.startswith(prefix) for prefix in ["105.", "41.", "80.", "197."]):
        score += 1
        reasons.append("ip:mobile_network")

    # --- 9️⃣ Score final ---  
    if ua.is_mobile or ua.is_tablet:
        # Les mobiles réels méritent un bonus
        score += 1
        reasons.append("ua:mobile_bonus")

    if score >= 3:
        event = "click"
        confidence = min(0.85 + 0.05 * score, 0.99)
    else:
        event = "preview"
        confidence = min(0.7 + 0.05 * score, 0.95)


    return {
        "event": event,
        "confidence": round(confidence, 2),
        "score": score,
        "ip": ip,
        "reasons": reasons,
        "user_agent": user_agent[:120],
        "url": body.url
    }
