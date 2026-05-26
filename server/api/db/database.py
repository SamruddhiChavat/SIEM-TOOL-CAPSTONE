import os
from urllib.parse import quote_plus
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

POSTGRES_URL = os.getenv(
    "POSTGRES_URL",
    "postgresql+asyncpg://siemuser:siempass123!@postgres:5432/siemdb"
)

# Convert sync URL to async URL if needed for SQLAlchemy
if POSTGRES_URL.startswith("postgresql://"):
    POSTGRES_URL = POSTGRES_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
elif POSTGRES_URL.startswith("postgres://"):
    POSTGRES_URL = POSTGRES_URL.replace("postgres://", "postgresql+asyncpg://", 1)

# Ensure no schema conflict or duplicate +asyncpg
if "++" in POSTGRES_URL:
    POSTGRES_URL = POSTGRES_URL.replace("++", "+")

# Fix special characters in password before the '@' sign
# The format is scheme://user:pass@host:port/dbname
try:
    if "@" in POSTGRES_URL:
        # Split at the last '@' to handle passwords containing '@'
        credentials_part, rest = POSTGRES_URL.rsplit("@", 1)
        scheme_and_user, password = credentials_part.rsplit(":", 1)
        # Ensure password is url encoded properly
        if "%" not in password:  # naive check to prevent double encoding
            safe_password = quote_plus(password)
            POSTGRES_URL = f"{scheme_and_user}:{safe_password}@{rest}"
except Exception:
    pass

engine = create_async_engine(
    POSTGRES_URL,
    echo=False,
    future=True,
    pool_size=10,
    max_overflow=20
)

async_session = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()

async def get_db():
    async with async_session() as session:
        yield session
