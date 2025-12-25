# Pydantic schemas

from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict
from datetime import datetime


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    is_premium: Optional[bool] = False


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AnalysisCreateOut(BaseModel):
    analysis_id: int
    total_lines: int
    threats_count: int
    top_threats: Dict[str, int]
    suspicious_ips: List[str]


class AnalysisOut(BaseModel):
    id: int
    user_id: int
    total_lines: int
    threats_count: int
    top_threats: Dict[str, int]
    suspicious_ips: List[str]
    created_at: datetime

    class Config:
        orm_mode = True