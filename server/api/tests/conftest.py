import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from db.database import Base, get_db
from main import app
from auth.jwt_handler import get_password_hash
from db.models import User
import os

# Test database
TEST_POSTGRES_URL = "sqlite+aiosqlite:///./test.db"

engine = create_async_engine(
    TEST_POSTGRES_URL, 
    echo=False,
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

async def override_get_db():
    async with TestingSessionLocal() as session:
        yield session

app.dependency_overrides[get_db] = override_get_db

@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_database():
    if os.path.exists("./test.db"):
        os.remove("./test.db")
        
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Create test admin user
    async with TestingSessionLocal() as db:
        hashed_pass = get_password_hash("testpass")
        user = User(id="test-admin-1", username="admin", hashed_password=hashed_pass, role="admin")
        db.add(user)
        await db.commit()
        
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    if os.path.exists("./test.db"):
        os.remove("./test.db")

@pytest_asyncio.fixture
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client

@pytest_asyncio.fixture
async def auth_token(async_client):
    response = await async_client.post(
        "/api/auth/login",
        data={"username": "admin", "password": "testpass"}
    )
    return response.json()["access_token"]
