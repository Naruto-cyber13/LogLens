# Helper to initialize DB tables for scripts.init_db

import os
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from app import models, database

async def create_tables():
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./loglens.db")
    engine = create_async_engine(DATABASE_URL, echo=False, future=True)
    async with engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    await engine.dispose()
    print("Tables created.")