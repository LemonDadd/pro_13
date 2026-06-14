import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.database import init_db, engine, Base
from app.models.audit import AuditLog
from app.models.batch import BatchJob


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    os.makedirs("data", exist_ok=True)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c
