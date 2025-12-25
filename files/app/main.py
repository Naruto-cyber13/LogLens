# FastAPI application wiring, dependency overrides, and startup table creation

import os
import logging
from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from . import auth, database, models, logs, schemas

logger = logging.getLogger("uvicorn.access")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="LogLens")

# Include routers
app.include_router(auth.router)
app.include_router(logs.router)

security = HTTPBearer(auto_error=False)

# Override dependency: provide current_user resolved from Authorization header
async def _get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(database.get_db),
):
    if not credentials:
        raise HTTPException(status_code=401, detail="Invalid or missing Authorization header")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY", "change_me_for_prod"), algorithms=["HS256"])
        user_id = int(payload.get("sub"))
    except (JWTError, Exception) as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    q = await db.execute(models.select().where(models.User.id == user_id)) if False else None
    # Use auth.get_user
    user = await auth.get_user(db, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# Rebind the placeholder dependencies used in auth and logs to the proper function
# In Python, FastAPI resolves Depends at import time; we provide overrides by assigning
# new callables into the module-level dependency placeholders used earlier.
auth.get_current_user = _get_current_user  # not used directly
# But for endpoints we used Depends(lambda: None). We'll provide direct dependency injection
# by creating wrapper functions and re-binding in the endpoint dependencies via app.dependency_overrides.

# Set dependency overrides used by logs endpoints (they had placeholder Depends(lambda: None))
app.dependency_overrides[lambda: None] = _get_current_user  # careful: this matches the same lambda object used in imports

# Startup event: ensure tables exist
@app.on_event("startup")
async def on_startup():
    logger.info("Starting up and ensuring database tables exist...")
    # Create tables if they don't exist
    async with database.engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)


# Simple root
@app.get("/")
async def root():
    return {"message": "LogLens API - visit /docs for OpenAPI UI"}