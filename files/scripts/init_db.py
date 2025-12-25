# Script to create database tables (async)
import asyncio
from . import init_helper

if __name__ == "__main__":
    asyncio.run(init_helper.create_tables())