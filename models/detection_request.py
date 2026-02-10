from pydantic import BaseModel
from typing import Optional, Dict

class DetectionRequest(BaseModel):
    url: Optional[str] = None
    user_agent: str
    ip: str
    headers: Optional[Dict[str, str]] = None
