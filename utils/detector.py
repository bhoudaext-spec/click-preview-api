from user_agents import parse as ua_parse

def detect_event(user_agent: str, headers: dict, ip: str):
    ua = user_agent.lower()
    reasons = []
    score = 0

    # 1️⃣ Détection bots
    bot_signatures = ["whatsapp", "facebookexternalhit", "twitterbot", "discordbot", "telegrambot"]
    if any(bot in ua for bot in bot_signatures):
        return {"event": "preview", "confidence": 0.99, "reasons": ["ua:bot_signature"]}

    # 2️⃣ WebView / préchargement
    if "wv" in ua or "googleapp" in ua:
        return {"event": "preview", "confidence": 0.90, "reasons": ["ua:webview"]}
    if headers.get("sec-purpose") == "prefetch":
        return {"event": "preview", "confidence": 0.95, "reasons": ["header:prefetch"]}

    # 3️⃣ User-Agent humain
    parsed = ua_parse(user_agent)
    if parsed.is_mobile or parsed.is_pc or parsed.is_tablet:
        score += 2
        reasons.append("ua:human_browser")

    # 4️⃣ Headers humains
    if headers.get("sec-fetch-user") == "?1":
        score += 3
        reasons.append("header:sec-fetch-user")

    # 5️⃣ IP mobile (exemple FR/AF)
    if ip.startswith(("105.", "41.", "80.214.")):
        score += 1
        reasons.append("ip:mobile_network")

    # 6️⃣ Décision finale
    if score >= 4:
        event = "click"
        confidence = min(0.8 + score * 0.04, 0.99)
    else:
        event = "preview"
        confidence = 0.90 if score == 0 else 0.85 + (score * 0.02)

    return {
        "event": event,
        "confidence": round(confidence, 2),
        "reasons": reasons or ["no_strong_indicators"]
    }
