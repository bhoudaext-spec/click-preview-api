from fastapi import APIRouter, Request
from pydantic import BaseModel
from utils.detector import detect_event

router = APIRouter()

class URLRequest(BaseModel):
    url: str

@router.post("/api/detect")
async def detect(request: Request, payload: URLRequest):
    # 1 Récupération automatique des infos
    user_agent = request.headers.get("user-agent", "unknown")
    ip = request.client.host
    headers = dict(request.headers)

    # 2 Appel du moteur de détection
    result = detect_event(user_agent=user_agent, headers=headers, ip=ip)

    # 3 Ajout de l’URL dans la réponse (facultatif)
    result["url"] = payload.url
    result["client_ip"] = ip

    return result

