# Authentication helpers and endpoints

import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from passlib.context import CryptContext
from jose import JWTError, jwt

from . import models, schemas, database

# Secret
SECRET_KEY = os.getenv("SECRET_KEY", "change_me_for_prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
router = APIRouter(prefix="/auth", tags=["auth"])


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[models.User]:
    q = await db.execute(select(models.User).where(models.User.email == email))
    return q.scalars().first()


async def get_user(db: AsyncSession, user_id: int) -> Optional[models.User]:
    q = await db.execute(select(models.User).where(models.User.id == user_id))
    return q.scalars().first()


async def get_current_user(token: str = Depends(lambda: None), db: AsyncSession = Depends(database.get_db)):
    """
    Dependency that extracts and returns the current user from Authorization header.
    This function is re-wired in main depending on how the token is provided.
    """
    # This function should be replaced by FastAPI dependency injection through HTTPBearer,
    # but for flexibility we'll parse the token header in main via fastapi.security.
    raise RuntimeError("get_current_user should be overridden in main with proper dependency wiring")


# Endpoints
@router.post("/register", response_model=dict)
async def register(user: schemas.UserCreate, db: AsyncSession = Depends(database.get_db)):
    """
    Register a new user.
    """
    existing = await get_user_by_email(db, user.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(user.password)
    db_user = models.User(email=user.email, hashed_password=hashed, is_premium=bool(user.is_premium))
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return {"id": db_user.id, "email": db_user.email, "is_premium": db_user.is_premium}


@router.post("/login", response_model=schemas.Token)
async def login(form_data: dict, db: AsyncSession = Depends(database.get_db)):
    """
    Login with JSON body: { "email": "...", "password": "..." }
    Returns access token.
    """
    email = form_data.get("email")
    password = form_data.get("password")
    if not email or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email and password required")
    user = await get_user_by_email(db, email)
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect credentials")
    token = create_access_token({"sub": str(user.id), "email": user.email, "is_premium": user.is_premium})
    return {"access_token": token, "token_type": "bearer"}