import pytest
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.database import Base, get_db
from app.main import app

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

@pytest.fixture(scope="session")
def event_loop():
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(name="session")
async def session_fixture():
    engine = create_async_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    async with async_session() as session:
        yield session
        
    await engine.dispose()

@pytest.fixture()
async def client_session(session):
    async def _get_test_db():
        yield session
    app.dependency_overrides[get_db] = _get_test_db
    yield
    app.dependency_overrides.clear()
